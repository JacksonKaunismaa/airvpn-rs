#!/usr/bin/env bash
# chaos-test.sh — Edge case simulation for VPN leak testing
#
# Simulates various failure scenarios to verify netlock holds:
#   - SIGSTOP/SIGCONT (suspend/resume simulation)
#   - WireGuard interface deletion
#   - Network interface down/up
#   - Process kill (SIGKILL)
#   - DNS server unreachable
#
# IMPORTANT: Run leak-monitor.sh in parallel to detect any leaks during chaos.
#
# Usage:
#   sudo ./chaos-test.sh <test> [options]
#
# Tests:
#   suspend         SIGSTOP for N seconds, then SIGCONT
#   kill-interface  Delete the WireGuard interface
#   net-down        Bring physical interface down, wait, bring up
#   sigkill         SIGKILL the airvpn-rs process
#   dns-block       Block DNS (port 53) temporarily
#   all             Run all tests sequentially
#
# Options:
#   --duration N    Seconds to hold failure state (default: 5)
#   --pid PID       airvpn-rs PID (auto-detected from state file)
#   --iface IFACE   Network interface for net-down test
#   --dry-run       Show what would happen without executing
#
# Exit codes:
#   0 = Test completed (check leak-monitor for actual leak detection)
#   1 = Test setup failed
#   2 = Usage error

set -euo pipefail

STATE_FILE="/run/airvpn-rs/state.json"

# ANSI colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Defaults
TEST=""
DURATION=5
PID=""
IFACE=""
DRY_RUN=0

# -----------------------------------------------------------------------------
# Parse args
# -----------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case $1 in
        suspend|kill-interface|net-down|sigkill|dns-block|all)
            TEST="$1"
            shift
            ;;
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --pid)
            PID="$2"
            shift 2
            ;;
        --iface)
            IFACE="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --help|-h)
            head -40 "$0" | tail -35
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 2
            ;;
    esac
done

if [[ -z "$TEST" ]]; then
    echo "Usage: $0 <test> [options]" >&2
    echo "Run '$0 --help' for details" >&2
    exit 2
fi

# -----------------------------------------------------------------------------
# Preflight
# -----------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: Must run as root${NC}" >&2
    exit 1
fi

# Auto-detect PID from state file
if [[ -z "$PID" && -f "$STATE_FILE" ]]; then
    PID=$(jq -r '.pid // empty' "$STATE_FILE" 2>/dev/null || true)
fi

# Auto-detect WireGuard interface
WG_IFACE=""
if [[ -f "$STATE_FILE" ]]; then
    WG_IFACE=$(jq -r '.wg_interface // empty' "$STATE_FILE" 2>/dev/null || true)
fi
if [[ -z "$WG_IFACE" ]]; then
    WG_IFACE=$(ip link show type wireguard 2>/dev/null | head -1 | awk -F': ' '{print $2}' || true)
fi

# Auto-detect physical interface for net-down
if [[ -z "$IFACE" ]]; then
    # Get the interface with default route
    IFACE=$(ip route | grep '^default' | head -1 | awk '{print $5}' || true)
fi

run_cmd() {
    if [[ $DRY_RUN -eq 1 ]]; then
        echo -e "${CYAN}[DRY-RUN] $*${NC}"
    else
        echo -e "${YELLOW}[RUN] $*${NC}"
        "$@"
    fi
}

# -----------------------------------------------------------------------------
# Test: suspend (SIGSTOP/SIGCONT)
# Simulates system suspend by stopping the process
# -----------------------------------------------------------------------------
test_suspend() {
    echo -e "${GREEN}=== Test: suspend (SIGSTOP/SIGCONT) ===${NC}"
    echo "Simulates system suspend by stopping airvpn-rs process"
    echo ""

    if [[ -z "$PID" ]]; then
        echo -e "${RED}Error: Could not find airvpn-rs PID${NC}" >&2
        return 1
    fi

    if ! kill -0 "$PID" 2>/dev/null; then
        echo -e "${RED}Error: PID $PID is not running${NC}" >&2
        return 1
    fi

    echo "Target PID: $PID"
    echo "Duration: ${DURATION}s"
    echo ""

    # Verify netlock is active before
    echo "Checking netlock before suspend..."
    if nft list table inet airvpn_lock &>/dev/null; then
        echo -e "${GREEN}Netlock table present${NC}"
    else
        echo -e "${YELLOW}WARNING: Netlock table not found${NC}"
    fi
    echo ""

    echo -e "${YELLOW}Sending SIGSTOP to PID $PID...${NC}"
    run_cmd kill -STOP "$PID"

    echo "Process stopped. Waiting ${DURATION}s..."
    echo -e "${RED}>>> VERIFY: leak-monitor should show NO traffic <<<${NC}"
    sleep "$DURATION"

    echo ""
    echo -e "${YELLOW}Sending SIGCONT to PID $PID...${NC}"
    run_cmd kill -CONT "$PID"

    echo "Process resumed."

    # Verify netlock still active
    echo "Checking netlock after resume..."
    if nft list table inet airvpn_lock &>/dev/null; then
        echo -e "${GREEN}Netlock table still present${NC}"
    else
        echo -e "${RED}ERROR: Netlock table MISSING after resume!${NC}"
        return 1
    fi

    echo -e "${GREEN}Test complete.${NC}"
}

# -----------------------------------------------------------------------------
# Test: kill-interface
# Deletes the WireGuard interface while VPN is connected
# -----------------------------------------------------------------------------
test_kill_interface() {
    echo -e "${GREEN}=== Test: kill-interface ===${NC}"
    echo "Deletes WireGuard interface to simulate sudden disconnect"
    echo ""

    if [[ -z "$WG_IFACE" ]]; then
        echo -e "${RED}Error: Could not find WireGuard interface${NC}" >&2
        return 1
    fi

    if ! ip link show "$WG_IFACE" &>/dev/null; then
        echo -e "${RED}Error: Interface $WG_IFACE does not exist${NC}" >&2
        return 1
    fi

    echo "Target interface: $WG_IFACE"
    echo ""

    echo -e "${RED}WARNING: This will disconnect the VPN!${NC}"
    echo "Netlock should prevent all non-local traffic."
    echo ""

    echo -e "${YELLOW}Deleting interface $WG_IFACE...${NC}"
    run_cmd ip link delete "$WG_IFACE"

    echo ""
    echo -e "${RED}>>> VERIFY: leak-monitor should show NO traffic <<<${NC}"
    echo "Waiting ${DURATION}s to observe any leaks..."
    sleep "$DURATION"

    # Check netlock
    echo ""
    echo "Checking netlock..."
    if nft list table inet airvpn_lock &>/dev/null; then
        echo -e "${GREEN}Netlock table still present (traffic blocked)${NC}"
    else
        echo -e "${RED}ERROR: Netlock table MISSING!${NC}"
        return 1
    fi

    echo ""
    echo -e "${YELLOW}To recover: restart airvpn-rs or run 'airvpn recover'${NC}"
    echo -e "${GREEN}Test complete.${NC}"
}

# -----------------------------------------------------------------------------
# Test: net-down
# Brings physical interface down, then back up
# -----------------------------------------------------------------------------
test_net_down() {
    echo -e "${GREEN}=== Test: net-down ===${NC}"
    echo "Brings physical interface down/up to simulate network loss"
    echo ""

    if [[ -z "$IFACE" ]]; then
        echo -e "${RED}Error: Could not determine physical interface${NC}" >&2
        return 1
    fi

    if ! ip link show "$IFACE" &>/dev/null; then
        echo -e "${RED}Error: Interface $IFACE does not exist${NC}" >&2
        return 1
    fi

    echo "Target interface: $IFACE"
    echo "Duration: ${DURATION}s"
    echo ""

    echo -e "${YELLOW}Bringing $IFACE down...${NC}"
    run_cmd ip link set "$IFACE" down

    echo "Interface down. Waiting ${DURATION}s..."
    sleep "$DURATION"

    echo -e "${YELLOW}Bringing $IFACE up...${NC}"
    run_cmd ip link set "$IFACE" up

    echo "Interface up."

    # Give network time to reconnect
    echo "Waiting 3s for network to stabilize..."
    sleep 3

    echo ""
    echo "Checking netlock..."
    if nft list table inet airvpn_lock &>/dev/null; then
        echo -e "${GREEN}Netlock table still present${NC}"
    else
        echo -e "${RED}ERROR: Netlock table MISSING!${NC}"
        return 1
    fi

    echo -e "${GREEN}Test complete.${NC}"
}

# -----------------------------------------------------------------------------
# Test: sigkill
# Sends SIGKILL to airvpn-rs (unclean shutdown)
# -----------------------------------------------------------------------------
test_sigkill() {
    echo -e "${GREEN}=== Test: sigkill ===${NC}"
    echo "Kills airvpn-rs with SIGKILL (no cleanup opportunity)"
    echo ""

    if [[ -z "$PID" ]]; then
        echo -e "${RED}Error: Could not find airvpn-rs PID${NC}" >&2
        return 1
    fi

    if ! kill -0 "$PID" 2>/dev/null; then
        echo -e "${RED}Error: PID $PID is not running${NC}" >&2
        return 1
    fi

    echo "Target PID: $PID"
    echo ""

    echo -e "${RED}WARNING: This will kill airvpn-rs!${NC}"
    echo "Netlock should remain active (blocking all traffic)."
    echo "Recovery state file should allow cleanup via 'airvpn recover'."
    echo ""

    echo -e "${YELLOW}Sending SIGKILL to PID $PID...${NC}"
    run_cmd kill -9 "$PID"

    echo "Process killed."
    echo ""
    echo -e "${RED}>>> VERIFY: leak-monitor should show NO traffic <<<${NC}"
    echo "Waiting ${DURATION}s to observe any leaks..."
    sleep "$DURATION"

    echo ""
    echo "Checking netlock..."
    if nft list table inet airvpn_lock &>/dev/null; then
        echo -e "${GREEN}Netlock table still present (traffic blocked)${NC}"
    else
        echo -e "${RED}ERROR: Netlock table MISSING after SIGKILL!${NC}"
        return 1
    fi

    echo ""
    echo "Checking recovery state..."
    if [[ -f "$STATE_FILE" ]]; then
        echo -e "${GREEN}Recovery state file exists${NC}"
        echo "Run 'sudo airvpn recover' to cleanup"
    else
        echo -e "${YELLOW}WARNING: Recovery state file missing${NC}"
    fi

    echo -e "${GREEN}Test complete.${NC}"
}

# -----------------------------------------------------------------------------
# Test: dns-block
# Temporarily blocks DNS (port 53) to simulate DNS failure
# -----------------------------------------------------------------------------
test_dns_block() {
    echo -e "${GREEN}=== Test: dns-block ===${NC}"
    echo "Blocks DNS (port 53) to simulate DNS server failure"
    echo ""

    echo "Duration: ${DURATION}s"
    echo ""

    # Add temporary nft rule to block DNS
    DNS_RULE_HANDLE=""

    echo -e "${YELLOW}Adding DNS block rule...${NC}"
    if [[ $DRY_RUN -eq 0 ]]; then
        # Add rule and capture handle
        nft add rule inet airvpn_lock output udp dport 53 drop comment \"chaos_test_dns_block\"
        nft add rule inet airvpn_lock output tcp dport 53 drop comment \"chaos_test_dns_block\"
    else
        echo -e "${CYAN}[DRY-RUN] nft add rule inet airvpn_lock output udp dport 53 drop${NC}"
        echo -e "${CYAN}[DRY-RUN] nft add rule inet airvpn_lock output tcp dport 53 drop${NC}"
    fi

    echo "DNS blocked."
    echo ""
    echo "Try: dig google.com (should timeout)"
    echo "Waiting ${DURATION}s..."
    sleep "$DURATION"

    echo ""
    echo -e "${YELLOW}Removing DNS block rules...${NC}"
    if [[ $DRY_RUN -eq 0 ]]; then
        # Remove by comment
        for handle in $(nft -a list table inet airvpn_lock 2>/dev/null | grep chaos_test_dns_block | grep -oP 'handle \K\d+'); do
            nft delete rule inet airvpn_lock output handle "$handle" 2>/dev/null || true
        done
    else
        echo -e "${CYAN}[DRY-RUN] nft delete rules with comment chaos_test_dns_block${NC}"
    fi

    echo "DNS unblocked."
    echo -e "${GREEN}Test complete.${NC}"
}

# -----------------------------------------------------------------------------
# Run all tests
# -----------------------------------------------------------------------------
test_all() {
    echo -e "${GREEN}=== Running all chaos tests ===${NC}"
    echo ""

    local tests=(suspend net-down dns-block)
    # Note: kill-interface and sigkill are destructive, run last if at all

    for t in "${tests[@]}"; do
        echo ""
        echo "========================================"
        "test_${t//-/_}"
        echo ""
        echo "Pausing 5s before next test..."
        sleep 5
    done

    echo ""
    echo -e "${YELLOW}Skipped destructive tests: kill-interface, sigkill${NC}"
    echo "Run these individually if needed."
    echo ""
    echo -e "${GREEN}All non-destructive tests complete.${NC}"
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
case "$TEST" in
    suspend)
        test_suspend
        ;;
    kill-interface)
        test_kill_interface
        ;;
    net-down)
        test_net_down
        ;;
    sigkill)
        test_sigkill
        ;;
    dns-block)
        test_dns_block
        ;;
    all)
        test_all
        ;;
    *)
        echo "Unknown test: $TEST" >&2
        exit 2
        ;;
esac
