#!/usr/bin/env bash
# leak-monitor.sh — Real-time traffic leak detector
#
# Monitors physical interface(s) for any traffic NOT going to the VPN endpoint.
# Any such traffic is a potential leak and triggers an alert.
#
# Usage:
#   sudo ./leak-monitor.sh [--endpoint IP] [--iface IFACE] [--duration SECS]
#
# Examples:
#   sudo ./leak-monitor.sh                           # Auto-detect from state file
#   sudo ./leak-monitor.sh --endpoint 1.2.3.4        # Manual endpoint
#   sudo ./leak-monitor.sh --iface eth0 --iface wlan0  # Multiple interfaces
#   sudo ./leak-monitor.sh --duration 60             # Run for 60 seconds
#
# Exit codes:
#   0 = No leaks detected (clean run or duration expired)
#   1 = Leak detected
#   2 = Setup error (missing deps, permissions, etc.)

set -euo pipefail

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
STATE_FILE="/run/airvpn-rs/state.json"
LOG_DIR="/tmp/leak-monitor"
DURATION=0  # 0 = indefinite

# ANSI colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# -----------------------------------------------------------------------------
# Parse args
# -----------------------------------------------------------------------------
ENDPOINT=""
IFACES=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --endpoint)
            ENDPOINT="$2"
            shift 2
            ;;
        --iface)
            IFACES+=("$2")
            shift 2
            ;;
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --help|-h)
            head -25 "$0" | tail -20
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 2
            ;;
    esac
done

# -----------------------------------------------------------------------------
# Preflight checks
# -----------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: Must run as root (need tcpdump privileges)${NC}" >&2
    exit 2
fi

for cmd in tcpdump jq ip; do
    if ! command -v "$cmd" &>/dev/null; then
        echo -e "${RED}Error: Missing required command: $cmd${NC}" >&2
        exit 2
    fi
done

# -----------------------------------------------------------------------------
# Auto-detect endpoint from state file if not provided
# -----------------------------------------------------------------------------
if [[ -z "$ENDPOINT" ]]; then
    if [[ -f "$STATE_FILE" ]]; then
        ENDPOINT=$(jq -r '.endpoint_ip // empty' "$STATE_FILE" 2>/dev/null || true)
    fi

    if [[ -z "$ENDPOINT" ]]; then
        # Try to get from WireGuard interface
        WG_ENDPOINT=$(wg show all endpoints 2>/dev/null | head -1 | awk '{print $2}' | cut -d: -f1 || true)
        if [[ -n "$WG_ENDPOINT" ]]; then
            ENDPOINT="$WG_ENDPOINT"
        fi
    fi

    if [[ -z "$ENDPOINT" ]]; then
        echo -e "${RED}Error: Could not auto-detect VPN endpoint.${NC}" >&2
        echo "Provide --endpoint IP or ensure airvpn-rs is connected." >&2
        exit 2
    fi
fi

echo -e "${GREEN}VPN endpoint: ${ENDPOINT}${NC}"

# -----------------------------------------------------------------------------
# Auto-detect physical interfaces if not provided
# -----------------------------------------------------------------------------
if [[ ${#IFACES[@]} -eq 0 ]]; then
    # Get all non-virtual, non-loopback interfaces
    # Exclude: lo, docker*, veth*, br-*, virbr*, tun*, tap*, wg*, avpn-*
    mapfile -t IFACES < <(
        ip -o link show | awk -F': ' '{print $2}' | \
        grep -v -E '^(lo|docker|veth|br-|virbr|tun|tap|wg|avpn-)' | \
        grep -v '@' || true
    )
fi

if [[ ${#IFACES[@]} -eq 0 ]]; then
    echo -e "${RED}Error: No physical interfaces found to monitor${NC}" >&2
    exit 2
fi

echo -e "${GREEN}Monitoring interfaces: ${IFACES[*]}${NC}"

# -----------------------------------------------------------------------------
# Build tcpdump filter
# Allow: traffic TO/FROM VPN endpoint, localhost, private ranges (if LAN enabled)
# Alert on: everything else
# -----------------------------------------------------------------------------
build_filter() {
    local endpoint="$1"

    # Everything NOT going to the endpoint and NOT local
    # Exclude Layer 2 protocols (ARP, LLC/SNAP, STP, LLDP) — can't be tunneled, not IP leaks
    # This catches any potential leak
    cat <<EOF
not arp and not llc and not stp and not (
    host $endpoint or
    host 127.0.0.1 or
    net 224.0.0.0/4 or
    net 255.255.255.255/32 or
    (net 192.168.0.0/16 and dst net 192.168.0.0/16) or
    (net 10.0.0.0/8 and dst net 10.0.0.0/8) or
    (net 172.16.0.0/12 and dst net 172.16.0.0/12)
)
and not (
    ip6 and (
        host ::1 or
        net fe80::/10 or
        net ff00::/8 or
        net fc00::/7
    )
)
EOF
}

FILTER=$(build_filter "$ENDPOINT" | tr '\n' ' ')

# -----------------------------------------------------------------------------
# Setup log directory
# -----------------------------------------------------------------------------
mkdir -p "$LOG_DIR"
LEAK_LOG="$LOG_DIR/leaks-$(date +%Y%m%d-%H%M%S).pcap"
LEAK_TXT="$LOG_DIR/leaks-$(date +%Y%m%d-%H%M%S).txt"

echo -e "${YELLOW}Leak capture file: ${LEAK_LOG}${NC}"
echo -e "${YELLOW}Leak summary: ${LEAK_TXT}${NC}"
echo ""

# -----------------------------------------------------------------------------
# Monitor function
# -----------------------------------------------------------------------------
LEAK_DETECTED=0
TCPDUMP_PIDS=()

cleanup() {
    echo -e "\n${YELLOW}Stopping monitors...${NC}"
    for pid in "${TCPDUMP_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done

    if [[ $LEAK_DETECTED -eq 1 ]]; then
        echo -e "${RED}=== LEAKS DETECTED ===${NC}"
        echo "Review: $LEAK_LOG (pcap) and $LEAK_TXT (summary)"
        exit 1
    else
        echo -e "${GREEN}=== No leaks detected ===${NC}"
        exit 0
    fi
}

trap cleanup EXIT INT TERM

handle_leak() {
    local line="$1"
    LEAK_DETECTED=1

    echo -e "${RED}[LEAK] $line${NC}"
    echo "[$(date -Iseconds)] $line" >> "$LEAK_TXT"
}

# Start tcpdump on each interface
for iface in "${IFACES[@]}"; do
    echo -e "${GREEN}Starting monitor on $iface...${NC}"

    # Capture to pcap file (for detailed analysis)
    tcpdump -i "$iface" -w "${LEAK_LOG%.pcap}-${iface}.pcap" "$FILTER" 2>/dev/null &
    TCPDUMP_PIDS+=($!)

    # Also print to stdout for real-time alerts
    tcpdump -i "$iface" -l -n "$FILTER" 2>/dev/null | while read -r line; do
        handle_leak "[$iface] $line"
    done &
    TCPDUMP_PIDS+=($!)
done

echo ""
echo -e "${GREEN}Monitoring active. Press Ctrl+C to stop.${NC}"
echo -e "${YELLOW}Any traffic not going to $ENDPOINT will trigger an alert.${NC}"
echo ""

# Wait for duration or forever
if [[ $DURATION -gt 0 ]]; then
    echo "Running for $DURATION seconds..."
    sleep "$DURATION"
else
    # Wait indefinitely
    wait
fi
