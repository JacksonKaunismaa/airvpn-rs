#!/usr/bin/env bash
# leak-monitor.sh — Real-time traffic leak detector
#
# Monitors physical interface(s) for any non-local IP traffic that isn't
# going to a known AirVPN destination. Detects both IP leaks and DNS leaks
# (including DoH/DoQ bypass via public resolver detection on any port).
#
# Default mode:
# - Allowlists bootstrap IPs + all AirVPN server IPs (from server_ips.txt)
# - Flags DNS on 53/853 + traffic to public DNS resolvers on any port
# - Runs active leak probes (can be disabled with --no-active-probe)
#
# Strict mode (--strict):
# - Minimal allowlist: only current endpoint + bootstrap IPs (+ --allow extras)
# - Same DNS and probe behavior as default
# - Useful for verifying only the connected endpoint gets physical traffic
# - Requires endpoint IP (--endpoint or state.json)
#
# Works regardless of VPN state — no restart needed on connect/disconnect/switch.
#
# Usage:
#   sudo ./leak-monitor.sh [--strict] [--endpoint IP] [--allow IP] [--iface IFACE] [--duration SECS]
#
# Examples:
#   sudo ./leak-monitor.sh                             # Full detection (recommended)
#   sudo ./leak-monitor.sh --no-active-probe           # Passive monitoring only
#   sudo ./leak-monitor.sh --strict --endpoint 1.2.3.4 # Endpoint-only allowlist
#   sudo ./leak-monitor.sh --allow 1.2.3.4             # Extra allowlisted IP
#   sudo ./leak-monitor.sh --iface eth0                # Specific interface
#   sudo ./leak-monitor.sh --duration 60               # Run for 60 seconds
#
# Exit codes:
#   0 = No leaks detected (clean run or duration expired)
#   1 = Leak detected
#   2 = Setup error (missing deps, permissions, etc.)

set -euo pipefail

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROVIDER_JSON="$SCRIPT_DIR/../resources/provider.json"
SERVER_IPS_FILE="$SCRIPT_DIR/../resources/server_ips.txt"
STATE_FILE="/run/airvpn-rs/state.json"
LOG_DIR="/tmp/leak-monitor"
DURATION=0  # 0 = indefinite
STRICT_MODE=0
ACTIVE_PROBE=-1  # -1 = auto (on by default), 0 = off, 1 = on
PROBE_INTERVAL=1

# ANSI colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# -----------------------------------------------------------------------------
# Parse args
# -----------------------------------------------------------------------------
EXTRA_IPS=()
ENDPOINT_IPS=()
IFACES=()

print_help() {
    cat <<'EOF'
leak-monitor.sh - real-time traffic leak detector

Usage:
  sudo ./leak-monitor.sh [--strict] [--active-probe|--no-active-probe] [--probe-interval SECS] [--endpoint IP] [--allow IP] [--iface IFACE] [--duration SECS]

Options:
  --strict         Endpoint-only allowlist (requires --endpoint or state.json)
  --active-probe   Generate active leak-attempt traffic in background (default: on)
  --no-active-probe Disable active probes
  --probe-interval Probe loop interval in seconds (default: 1)
  --endpoint IP    Allowlist endpoint IP (repeatable). Required in strict mode
  --allow IP       Extra allowlisted destination IP/CIDR (repeatable)
  --iface IFACE    Interface to monitor (repeatable). Overrides auto interface discovery
  --duration SECS  Exit after N seconds (default: run indefinitely)
  --help, -h       Show this help

Examples:
  sudo ./leak-monitor.sh                                    # Full detection
  sudo ./leak-monitor.sh --no-active-probe                  # Passive only
  sudo ./leak-monitor.sh --strict --endpoint 203.0.113.10   # Endpoint-only
  sudo ./leak-monitor.sh --iface eth0 --iface wlan0
EOF
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --strict)
            STRICT_MODE=1
            shift
            ;;
        --active-probe)
            ACTIVE_PROBE=1
            shift
            ;;
        --no-active-probe)
            ACTIVE_PROBE=0
            shift
            ;;
        --probe-interval)
            PROBE_INTERVAL="$2"
            shift 2
            ;;
        --endpoint)
            ENDPOINT_IPS+=("$2")
            shift 2
            ;;
        --allow)
            EXTRA_IPS+=("$2")
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
            print_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 2
            ;;
    esac
done

if [[ $ACTIVE_PROBE -lt 0 ]]; then
    ACTIVE_PROBE=1
fi

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

if ! [[ "$PROBE_INTERVAL" =~ ^[0-9]+$ ]] || [[ "$PROBE_INTERVAL" -lt 1 ]]; then
    echo -e "${RED}Error: --probe-interval must be an integer >= 1${NC}" >&2
    exit 2
fi

dedupe_ips() {
    awk 'NF && !seen[$0]++'
}

load_endpoint_from_state() {
    if [[ -f "$STATE_FILE" ]]; then
        jq -r '.endpoint_ip // ""' "$STATE_FILE" 2>/dev/null | head -1
    fi
}

# -----------------------------------------------------------------------------
# Build INDEPENDENT allowlist (does NOT read nftables)
# -----------------------------------------------------------------------------
ALLOWED_IPS=("${EXTRA_IPS[@]+"${EXTRA_IPS[@]}"}")

# Source 1: Bootstrap IPs from provider.json
if [[ -f "$PROVIDER_JSON" ]]; then
    mapfile -t BOOTSTRAP_IPS < <(
        jq -r '.manifest.urls[].address' "$PROVIDER_JSON" 2>/dev/null | \
        grep -oP '//\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true
    )
    mapfile -t BOOTSTRAP_IPS6 < <(
        jq -r '.manifest.urls[].address' "$PROVIDER_JSON" 2>/dev/null | \
        grep -oP '//\[\K[0-9a-f:]+(?=\])' || true
    )
    ALLOWED_IPS+=("${BOOTSTRAP_IPS[@]}" "${BOOTSTRAP_IPS6[@]}")
    echo -e "${GREEN}Bootstrap IPs (provider.json): ${#BOOTSTRAP_IPS[@]} IPv4, ${#BOOTSTRAP_IPS6[@]} IPv6${NC}"
else
    echo -e "${RED}Warning: provider.json not found at ${PROVIDER_JSON}${NC}" >&2
fi

if [[ $STRICT_MODE -eq 1 ]]; then
    # Strict: only current endpoint + bootstrap (no broad server list)
    if [[ ${#ENDPOINT_IPS[@]} -eq 0 ]]; then
        STATE_ENDPOINT="$(load_endpoint_from_state || true)"
        if [[ -n "${STATE_ENDPOINT:-}" ]]; then
            ENDPOINT_IPS+=("$STATE_ENDPOINT")
            echo -e "${GREEN}Endpoint from state.json: $STATE_ENDPOINT${NC}"
        fi
    fi

    if [[ ${#ENDPOINT_IPS[@]} -eq 0 ]]; then
        echo -e "${RED}Error: Strict mode requires endpoint IP (--endpoint or $STATE_FILE with endpoint_ip)${NC}" >&2
        exit 2
    fi

    ALLOWED_IPS+=("${ENDPOINT_IPS[@]}")
    echo -e "${GREEN}Strict mode endpoint allowlist: ${#ENDPOINT_IPS[@]} IP(s)${NC}"
else
    # Default: all AirVPN server entry IPs (covers latency pings, server switching, etc.)
    if [[ -f "$SERVER_IPS_FILE" ]]; then
        mapfile -t SERVER_IPS < "$SERVER_IPS_FILE"
        ALLOWED_IPS+=("${SERVER_IPS[@]}")
        echo -e "${GREEN}Server IPs (server_ips.txt): ${#SERVER_IPS[@]}${NC}"
    else
        echo -e "${YELLOW}Warning: server_ips.txt not found — only bootstrap IPs will be allowlisted${NC}"
        echo -e "${YELLOW}Generate it: sudo airvpn-rs servers --debug | grep -oP 'ips_entry=\"[^\"]*\"' | sed 's/ips_entry=\"//;s/\"//' | tr ',' '\\n' | sort -u > resources/server_ips.txt${NC}"
    fi
fi

mapfile -t ALLOWED_IPS < <(printf '%s\n' "${ALLOWED_IPS[@]}" | dedupe_ips)

echo -e "${GREEN}Total allowlisted: ${#ALLOWED_IPS[@]} IPs${NC}"

# -----------------------------------------------------------------------------
# Auto-detect physical interfaces if not provided
# -----------------------------------------------------------------------------
if [[ ${#IFACES[@]} -eq 0 ]]; then
    mapfile -t IFACES < <(
        ip -o link show | awk -F': ' '{print $2}' | \
        grep -v -E '^(lo|docker|veth|br-|virbr|tun|tap|wg|avpn)' | \
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
# -----------------------------------------------------------------------------
build_filter() {
    local -a allowed_ips=("$@")

    local allowlist_clause=""
    for ip in "${allowed_ips[@]}"; do
        if [[ -n "$ip" ]]; then
            if [[ "$ip" == */* ]]; then
                allowlist_clause="${allowlist_clause}    dst net $ip or
"
            else
                allowlist_clause="${allowlist_clause}    dst host $ip or
"
            fi
        fi
    done

    cat <<EOF
(ip or ip6) and not (
${allowlist_clause}    host 127.0.0.1 or
    net 224.0.0.0/4 or
    net 255.255.255.255/32 or
    (net 192.168.0.0/16 and dst net 192.168.0.0/16) or
    (net 10.0.0.0/8 and dst net 10.0.0.0/8) or
    (net 172.16.0.0/12 and dst net 172.16.0.0/12) or
    host ::1 or
    net fe80::/10 or
    net ff00::/8 or
    net fc00::/7
)
EOF
}

FILTER=$(build_filter "${ALLOWED_IPS[@]}" | tr '\n' ' ')

# DNS leak filter: any DNS leaving a physical interface is suspicious when VPN is up.
# Separate from main filter because RFC1918 DNS (e.g. 192.168.1.1:53) is the most
# common VPN leak vector and the main filter excludes RFC1918 traffic.
DNS_FILTER="(dst port 53 or dst port 853) and not (dst host 127.0.0.1 or dst host ::1)"

# Public DNS resolver filter: catches DoH/DoQ bypass attempts on any port.
COMMON_DNS_IPS=(
    "8.8.8.8" "8.8.4.4"
    "1.1.1.1" "1.0.0.1"
    "9.9.9.9" "149.112.112.112"
    "208.67.222.222" "208.67.220.220"
    "2620:fe::fe" "2620:fe::9"
    "2606:4700:4700::1111" "2606:4700:4700::1001"
    "2001:4860:4860::8888" "2001:4860:4860::8844"
    "2620:119:35::35" "2620:119:53::53"
)
dns_clause=""
for ip in "${COMMON_DNS_IPS[@]}"; do
    dns_clause="${dns_clause}dst host $ip or "
done
dns_clause="${dns_clause% or }"
PUBLIC_DNS_FILTER="(${dns_clause}) and not (dst host 127.0.0.1 or dst host ::1)"

# -----------------------------------------------------------------------------
# Setup log directory
# -----------------------------------------------------------------------------
mkdir -p "$LOG_DIR"
RUN_TS="$(date +%Y%m%d-%H%M%S)"
LEAK_LOG="$LOG_DIR/leaks-${RUN_TS}.pcap"
LEAK_TXT="$LOG_DIR/leaks-${RUN_TS}.txt"

echo -e "${YELLOW}Leak capture: ${LEAK_LOG}${NC}"
echo -e "${YELLOW}Leak summary: ${LEAK_TXT}${NC}"
if [[ $STRICT_MODE -eq 1 ]]; then
    echo -e "${YELLOW}Mode: STRICT (endpoint-only allowlist)${NC}"
fi
echo ""

# -----------------------------------------------------------------------------
# Monitor
# -----------------------------------------------------------------------------
TCPDUMP_PIDS=()
ACTIVE_PROBE_PID=""

CLEANUP_DONE=0
cleanup() {
    [[ $CLEANUP_DONE -eq 1 ]] && return
    CLEANUP_DONE=1

    echo -e "\n${YELLOW}Stopping monitors...${NC}"

    # Kill active probes first so they stop generating traffic
    if [[ -n "$ACTIVE_PROBE_PID" ]]; then
        kill "$ACTIVE_PROBE_PID" 2>/dev/null || true
    fi

    # Kill tcpdump writers and line-readers
    for pid in "${TCPDUMP_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done

    # Brief pause for processes to flush stderr (packet counts) and exit
    sleep 0.3

    # Merge per-interface pcaps into the advertised filename
    local pcaps=()
    for f in "${LEAK_LOG%.pcap}"-*.pcap; do
        [[ -f "$f" ]] && pcaps+=("$f")
    done
    if [[ ${#pcaps[@]} -gt 0 ]]; then
        if command -v mergecap &>/dev/null; then
            mergecap -w "$LEAK_LOG" "${pcaps[@]}" 2>/dev/null || true
        else
            cp "${pcaps[0]}" "$LEAK_LOG" 2>/dev/null || true
        fi
    fi

    # Print per-interface packet counts from tcpdump stderr
    # (tcpdump prints "N packets captured" to stderr on exit)
    local total_pkts=0 iface_count=0
    for errlog in "$LOG_DIR"/tcpdump-*.err; do
        [[ -f "$errlog" ]] || continue
        local iface_name count
        iface_name="$(basename "$errlog" .err)"
        iface_name="${iface_name#tcpdump-}"
        count="$(grep -oP '\d+(?= packets? captured)' "$errlog" 2>/dev/null | head -1 || true)"
        count="${count:-0}"
        total_pkts=$((total_pkts + count))
        iface_count=$((iface_count + 1))
    done
    if [[ $iface_count -gt 0 ]]; then
        echo -e "${GREEN}Captured ${total_pkts} filtered packets across ${iface_count} monitors.${NC}"
    fi

    # The txt file IS the leak indicator — no separate sentinel needed
    if [[ -s "$LEAK_TXT" ]]; then
        echo -e "${RED}=== LEAKS DETECTED ===${NC}"
        echo "Review: $LEAK_LOG (pcap) and $LEAK_TXT (summary)"
        exit 1
    else
        echo -e "${GREEN}=== No leaks detected ===${NC}"
        # Clean up per-interface pcaps and temp files on clean runs
        rm -f "${LEAK_LOG%.pcap}"-*.pcap 2>/dev/null || true
        rm -f "$LOG_DIR"/tcpdump-*.err 2>/dev/null || true
        rm -f "$LEAK_TXT" 2>/dev/null || true
        exit 0
    fi
}

trap cleanup EXIT

handle_leak() {
    local line="$1"
    echo -e "${RED}[LEAK] $line${NC}"
    # Write to txt FIRST — this file is the leak indicator checked in cleanup
    echo "[$(date -Iseconds)] $line" >> "$LEAK_TXT"
}

run_timed_probe() {
    local timeout_s="$1"
    shift
    if command -v timeout &>/dev/null; then
        timeout "$timeout_s" "$@" >/dev/null 2>&1 || true
    else
        "$@" >/dev/null 2>&1 || true
    fi
}

probe_iface() {
    local iface="$1"
    local src4
    src4="$(ip -4 -o addr show dev "$iface" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)"

    # DNS leak attempts
    if command -v dig &>/dev/null; then
        run_timed_probe 3 dig +time=1 +tries=1 @8.8.8.8 example.com A
        run_timed_probe 3 dig +time=1 +tries=1 @1.1.1.1 example.com A
    fi

    # TCP + UDP egress attempts
    if command -v nc &>/dev/null; then
        if [[ -n "$src4" ]]; then
            run_timed_probe 3 nc -z -w1 -s "$src4" 1.1.1.1 443
            printf "x" | run_timed_probe 3 nc -u -w1 -s "$src4" 8.8.8.8 53
        else
            run_timed_probe 3 nc -z -w1 1.1.1.1 443
            printf "x" | run_timed_probe 3 nc -u -w1 8.8.8.8 53
        fi
    else
        run_timed_probe 3 bash -c 'echo > /dev/tcp/1.1.1.1/443'
        run_timed_probe 3 bash -c 'echo x > /dev/udp/8.8.8.8/53'
    fi

    # HTTP egress attempts pinned to physical interface
    if command -v curl &>/dev/null; then
        run_timed_probe 4 curl -4 --interface "$iface" --connect-timeout 2 --max-time 3 -fsS "http://1.1.1.1"
        run_timed_probe 4 curl -4 --interface "$iface" --connect-timeout 2 --max-time 3 -fsS "http://8.8.8.8"
    fi
}

active_probe_loop() {
    while true; do
        for iface in "${IFACES[@]}"; do
            probe_iface "$iface"
        done
        sleep "$PROBE_INTERVAL"
    done
}

for iface in "${IFACES[@]}"; do
    echo -e "${GREEN}Starting monitor on $iface...${NC}"

    IFACE_ERR_LOG="$LOG_DIR/tcpdump-${iface}.err"

    # shellcheck disable=SC2086
    tcpdump -i "$iface" -w "${LEAK_LOG%.pcap}-${iface}.pcap" $FILTER 2>"$IFACE_ERR_LOG" &
    TCPDUMP_PIDS+=($!)

    # shellcheck disable=SC2086
    tcpdump -i "$iface" -l -n $FILTER 2>/dev/null | (
        while read -r line; do
            [[ -z "$line" ]] && continue
            handle_leak "[$iface] $line"
        done
    ) &
    TCPDUMP_PIDS+=($!)

    # DNS leak monitor — catches DNS to RFC1918 gateways that the main filter misses
    # shellcheck disable=SC2086
    tcpdump -i "$iface" -w "${LEAK_LOG%.pcap}-${iface}-dns.pcap" $DNS_FILTER 2>"$LOG_DIR/tcpdump-${iface}-dns.err" &
    TCPDUMP_PIDS+=($!)

    # shellcheck disable=SC2086
    tcpdump -i "$iface" -l -n $DNS_FILTER 2>/dev/null | (
        trap '' INT
        while read -r line; do
            [[ -z "$line" ]] && continue
            handle_leak "[DNS $iface] $line"
        done
    ) &
    TCPDUMP_PIDS+=($!)

    # Public DNS bypass detector: catches DoH/DoQ-to-public-resolver attempts.
    # shellcheck disable=SC2086
    tcpdump -i "$iface" -w "${LEAK_LOG%.pcap}-${iface}-public-dns.pcap" $PUBLIC_DNS_FILTER 2>"$LOG_DIR/tcpdump-${iface}-public-dns.err" &
    TCPDUMP_PIDS+=($!)

    # shellcheck disable=SC2086
    tcpdump -i "$iface" -l -n $PUBLIC_DNS_FILTER 2>/dev/null | (
        while read -r line; do
            [[ -z "$line" ]] && continue
            handle_leak "[PUBLIC-DNS $iface] $line"
        done
    ) &
    TCPDUMP_PIDS+=($!)
done

# Verify at least one tcpdump is still running
sleep 0.5
ALIVE=0
for pid in "${TCPDUMP_PIDS[@]}"; do
    kill -0 "$pid" 2>/dev/null && ((ALIVE++)) || true
done
if [[ $ALIVE -eq 0 ]]; then
    echo -e "${RED}Error: All tcpdump processes exited immediately.${NC}" >&2
    echo -e "${RED}Check ${LOG_DIR}/tcpdump-*.err${NC}" >&2
    exit 2
fi

if [[ $ACTIVE_PROBE -eq 1 ]]; then
    active_probe_loop &
    ACTIVE_PROBE_PID=$!
    echo -e "${GREEN}Active probes enabled (interval=${PROBE_INTERVAL}s).${NC}"
fi

echo ""
echo -e "${GREEN}Monitoring active ($ALIVE capture processes). Press Ctrl+C to stop.${NC}"
echo -e "${YELLOW}Any traffic to non-AirVPN IPs will trigger an alert.${NC}"
echo -e "${YELLOW}DNS traffic (port 53/853) on physical interfaces is flagged separately.${NC}"
echo -e "${YELLOW}Traffic to public DNS resolvers (8.8.8.8, 1.1.1.1, etc.) on any port is also flagged.${NC}"
if [[ $ACTIVE_PROBE -eq 1 ]]; then
    echo -e "${YELLOW}Active probes: periodic DNS/TCP/UDP/HTTP leak-attempt traffic is being generated.${NC}"
fi
echo ""

# Wait for duration or forever
if [[ $DURATION -gt 0 ]]; then
    echo "Running for $DURATION seconds..."
    sleep "$DURATION"
else
    wait
fi
