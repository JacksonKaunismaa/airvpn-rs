#!/usr/bin/env bash
# eddie-compare.sh — Behavioral comparison between airvpn-rs and Eddie
#
# Captures snapshots of system state from both implementations for diff:
#   - nftables/iptables rules
#   - Routing table entries
#   - DNS configuration
#   - WireGuard interface config
#   - IPv6 status
#
# Usage:
#   sudo ./eddie-compare.sh capture-airvpn   # Capture airvpn-rs state
#   sudo ./eddie-compare.sh capture-eddie    # Capture Eddie state
#   ./eddie-compare.sh diff                  # Compare captured states
#   ./eddie-compare.sh report                # Generate comparison report
#
# The idea: connect with airvpn-rs, capture state. Disconnect. Connect with
# Eddie (same server), capture state. Then diff. Any differences are potential
# spec drift.

set -euo pipefail

SNAPSHOT_DIR="/tmp/vpn-compare"
AIRVPN_SNAPSHOT="$SNAPSHOT_DIR/airvpn-rs"
EDDIE_SNAPSHOT="$SNAPSHOT_DIR/eddie"

# ANSI colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# -----------------------------------------------------------------------------
# Capture functions
# -----------------------------------------------------------------------------
capture_nftables() {
    local out="$1/nftables.txt"
    echo "Capturing nftables..."

    {
        echo "=== nft list ruleset ==="
        nft list ruleset 2>/dev/null || echo "(nft not available or no rules)"
    } > "$out"
}

capture_iptables() {
    local out="$1/iptables.txt"
    echo "Capturing iptables..."

    {
        echo "=== iptables-save ==="
        iptables-save 2>/dev/null || echo "(iptables-save failed)"

        echo ""
        echo "=== ip6tables-save ==="
        ip6tables-save 2>/dev/null || echo "(ip6tables-save failed)"
    } > "$out"
}

capture_routes() {
    local out="$1/routes.txt"
    echo "Capturing routes..."

    {
        echo "=== ip -4 route ==="
        ip -4 route 2>/dev/null || echo "(failed)"

        echo ""
        echo "=== ip -6 route ==="
        ip -6 route 2>/dev/null || echo "(failed)"

        echo ""
        echo "=== ip -4 rule ==="
        ip -4 rule 2>/dev/null || echo "(failed)"

        echo ""
        echo "=== ip -6 rule ==="
        ip -6 rule 2>/dev/null || echo "(failed)"

        echo ""
        echo "=== Routing tables ==="
        for table in main 51820 52; do
            echo "--- Table $table (IPv4) ---"
            ip -4 route show table "$table" 2>/dev/null || echo "(empty or not found)"
            echo "--- Table $table (IPv6) ---"
            ip -6 route show table "$table" 2>/dev/null || echo "(empty or not found)"
        done
    } > "$out"
}

capture_dns() {
    local out="$1/dns.txt"
    echo "Capturing DNS..."

    {
        echo "=== /etc/resolv.conf ==="
        cat /etc/resolv.conf 2>/dev/null || echo "(not readable)"

        echo ""
        echo "=== resolvectl status (if systemd-resolved) ==="
        resolvectl status 2>/dev/null || echo "(not using systemd-resolved)"

        echo ""
        echo "=== /etc/resolv.conf attributes ==="
        lsattr /etc/resolv.conf 2>/dev/null || echo "(lsattr failed)"
    } > "$out"
}

capture_wireguard() {
    local out="$1/wireguard.txt"
    echo "Capturing WireGuard..."

    {
        echo "=== wg show ==="
        wg show 2>/dev/null || echo "(no wireguard interfaces)"

        echo ""
        echo "=== ip link show type wireguard ==="
        ip link show type wireguard 2>/dev/null || echo "(none)"

        echo ""
        echo "=== WireGuard interface addresses ==="
        for iface in $(ip link show type wireguard 2>/dev/null | grep -oP '^\d+: \K[^:@]+'); do
            echo "--- $iface ---"
            ip addr show "$iface" 2>/dev/null || echo "(failed)"
        done
    } > "$out"
}

capture_ipv6() {
    local out="$1/ipv6.txt"
    echo "Capturing IPv6 status..."

    {
        echo "=== sysctl net.ipv6.conf ==="
        sysctl -a 2>/dev/null | grep 'net.ipv6.conf' | grep -E '(disable_ipv6|accept_ra|forwarding)' | sort

        echo ""
        echo "=== IPv6 addresses ==="
        ip -6 addr show scope global 2>/dev/null || echo "(none)"
    } > "$out"
}

capture_interfaces() {
    local out="$1/interfaces.txt"
    echo "Capturing network interfaces..."

    {
        echo "=== ip link ==="
        ip link show

        echo ""
        echo "=== ip addr ==="
        ip addr show
    } > "$out"
}

capture_state_file() {
    local out="$1/state.txt"
    echo "Capturing VPN state file..."

    {
        echo "=== airvpn-rs state (/run/airvpn-rs/state.json) ==="
        if [[ -f /run/airvpn-rs/state.json ]]; then
            cat /run/airvpn-rs/state.json
        else
            echo "(not found)"
        fi

        # Eddie uses ~/.eddie (or system location)
        echo ""
        echo "=== Eddie state (if found) ==="
        for eddie_path in ~/.config/eddie ~/.eddie /etc/eddie; do
            if [[ -d "$eddie_path" ]]; then
                echo "--- $eddie_path ---"
                ls -la "$eddie_path" 2>/dev/null || true
                [[ -f "$eddie_path/Recovery.xml" ]] && cat "$eddie_path/Recovery.xml"
            fi
        done
    } > "$out"
}

do_capture() {
    local dest="$1"
    local label="$2"

    mkdir -p "$dest"

    echo -e "${GREEN}=== Capturing $label state ===${NC}"
    echo "Output: $dest"
    echo ""

    capture_nftables "$dest"
    capture_iptables "$dest"
    capture_routes "$dest"
    capture_dns "$dest"
    capture_wireguard "$dest"
    capture_ipv6 "$dest"
    capture_interfaces "$dest"
    capture_state_file "$dest"

    # Timestamp
    date -Iseconds > "$dest/timestamp.txt"

    echo ""
    echo -e "${GREEN}Capture complete: $dest${NC}"
    ls -la "$dest"
}

# -----------------------------------------------------------------------------
# Diff functions
# -----------------------------------------------------------------------------
do_diff() {
    if [[ ! -d "$AIRVPN_SNAPSHOT" ]]; then
        echo -e "${RED}Error: No airvpn-rs snapshot found${NC}" >&2
        echo "Run: sudo $0 capture-airvpn" >&2
        exit 1
    fi

    if [[ ! -d "$EDDIE_SNAPSHOT" ]]; then
        echo -e "${RED}Error: No Eddie snapshot found${NC}" >&2
        echo "Run: sudo $0 capture-eddie" >&2
        exit 1
    fi

    echo -e "${GREEN}=== Comparing snapshots ===${NC}"
    echo ""
    echo "airvpn-rs: $(cat "$AIRVPN_SNAPSHOT/timestamp.txt" 2>/dev/null || echo 'unknown')"
    echo "Eddie:     $(cat "$EDDIE_SNAPSHOT/timestamp.txt" 2>/dev/null || echo 'unknown')"
    echo ""

    local has_diff=0

    for file in nftables.txt iptables.txt routes.txt dns.txt wireguard.txt ipv6.txt; do
        echo -e "${CYAN}--- $file ---${NC}"

        if [[ ! -f "$AIRVPN_SNAPSHOT/$file" ]]; then
            echo -e "${YELLOW}(airvpn-rs file missing)${NC}"
            continue
        fi

        if [[ ! -f "$EDDIE_SNAPSHOT/$file" ]]; then
            echo -e "${YELLOW}(Eddie file missing)${NC}"
            continue
        fi

        if diff -q "$AIRVPN_SNAPSHOT/$file" "$EDDIE_SNAPSHOT/$file" &>/dev/null; then
            echo -e "${GREEN}IDENTICAL${NC}"
        else
            echo -e "${YELLOW}DIFFERS:${NC}"
            diff --color=always -u "$AIRVPN_SNAPSHOT/$file" "$EDDIE_SNAPSHOT/$file" | head -50 || true
            echo ""
            has_diff=1
        fi
        echo ""
    done

    if [[ $has_diff -eq 0 ]]; then
        echo -e "${GREEN}=== No significant differences found ===${NC}"
    else
        echo -e "${YELLOW}=== Differences detected (review above) ===${NC}"
    fi
}

# -----------------------------------------------------------------------------
# Report function
# -----------------------------------------------------------------------------
do_report() {
    local report="$SNAPSHOT_DIR/comparison-report.md"

    echo -e "${GREEN}=== Generating comparison report ===${NC}"

    {
        echo "# VPN Implementation Comparison Report"
        echo ""
        echo "Generated: $(date -Iseconds)"
        echo ""

        echo "## Snapshots"
        echo ""
        echo "- **airvpn-rs**: $(cat "$AIRVPN_SNAPSHOT/timestamp.txt" 2>/dev/null || echo 'not captured')"
        echo "- **Eddie**: $(cat "$EDDIE_SNAPSHOT/timestamp.txt" 2>/dev/null || echo 'not captured')"
        echo ""

        echo "## Summary"
        echo ""
        echo "| Component | Status |"
        echo "|-----------|--------|"

        for file in nftables.txt iptables.txt routes.txt dns.txt wireguard.txt ipv6.txt; do
            if [[ -f "$AIRVPN_SNAPSHOT/$file" && -f "$EDDIE_SNAPSHOT/$file" ]]; then
                if diff -q "$AIRVPN_SNAPSHOT/$file" "$EDDIE_SNAPSHOT/$file" &>/dev/null; then
                    echo "| ${file%.txt} | MATCH |"
                else
                    echo "| ${file%.txt} | **DIFFERS** |"
                fi
            else
                echo "| ${file%.txt} | (incomplete) |"
            fi
        done

        echo ""
        echo "## Detailed Diffs"
        echo ""

        for file in nftables.txt iptables.txt routes.txt dns.txt wireguard.txt ipv6.txt; do
            echo "### ${file%.txt}"
            echo ""

            if [[ -f "$AIRVPN_SNAPSHOT/$file" && -f "$EDDIE_SNAPSHOT/$file" ]]; then
                if diff -q "$AIRVPN_SNAPSHOT/$file" "$EDDIE_SNAPSHOT/$file" &>/dev/null; then
                    echo "No differences."
                else
                    echo '```diff'
                    diff -u "$AIRVPN_SNAPSHOT/$file" "$EDDIE_SNAPSHOT/$file" | head -100 || true
                    echo '```'
                fi
            else
                echo "(Files missing for comparison)"
            fi
            echo ""
        done

    } > "$report"

    echo "Report saved to: $report"
    echo ""
    cat "$report"
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
case "${1:-}" in
    capture-airvpn)
        if [[ $EUID -ne 0 ]]; then
            echo -e "${RED}Error: Must run as root${NC}" >&2
            exit 1
        fi
        do_capture "$AIRVPN_SNAPSHOT" "airvpn-rs"
        ;;
    capture-eddie)
        if [[ $EUID -ne 0 ]]; then
            echo -e "${RED}Error: Must run as root${NC}" >&2
            exit 1
        fi
        do_capture "$EDDIE_SNAPSHOT" "Eddie"
        ;;
    diff)
        do_diff
        ;;
    report)
        do_report
        ;;
    --help|-h|"")
        head -25 "$0" | tail -20
        exit 0
        ;;
    *)
        echo "Unknown command: $1" >&2
        exit 2
        ;;
esac
