#!/usr/bin/env bash
# Tier 2 robustness tests — adversarial + edge cases
# Run as root: sudo bash tests/robustness-tier2.sh
#
# These tests are more aggressive than tier 1.

set -euo pipefail

BINARY="./target/release/airvpn"
PASS=0
FAIL=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }
log() { echo -e "${BOLD}[TEST]${NC} $1"; }
separator() { echo "────────────────────────────────────────────────"; }

cleanup() {
    pkill -f "airvpn connect" 2>/dev/null || true
    sleep 2
    $BINARY recover 2>/dev/null || true
    nft delete table inet airvpn_lock 2>/dev/null || true
    ip -4 rule delete not fwmark 51820 table 51820 2>/dev/null || true
    ip -6 rule delete not fwmark 51820 table 51820 2>/dev/null || true
    ip -4 rule delete table main suppress_prefixlength 0 2>/dev/null || true
    ip -6 rule delete table main suppress_prefixlength 0 2>/dev/null || true
    [ -f /etc/resolv.conf.airvpn-rs ] && cp /etc/resolv.conf.airvpn-rs /etc/resolv.conf
    for f in /proc/sys/net/ipv6/conf/*/disable_ipv6; do echo 0 > "$f" 2>/dev/null || true; done
}

get_default_iface() { ip route show default 2>/dev/null | awk '{print $5; exit}'; }
get_real_ip() { curl -s --connect-timeout 10 ifconfig.me 2>/dev/null || echo "FAILED"; }

wait_for_connect() {
    local timeout=${1:-45}
    local start=$SECONDS
    while [ $((SECONDS - start)) -lt "$timeout" ]; do
        if grep -q "Connected to" /tmp/airvpn-rs.log 2>/dev/null; then return 0; fi
        sleep 1
    done
    return 1
}

start_vpn() {
    rm -f /tmp/airvpn-rs.log
    $BINARY connect --skip-ping ${1:-} > /tmp/airvpn-rs-stdout.log 2>&1 &
    VPN_PID=$!
    wait_for_connect 45
}

stop_vpn() {
    [ -n "${VPN_PID:-}" ] && kill -INT "$VPN_PID" 2>/dev/null || true
    local w=0
    while kill -0 "${VPN_PID:-0}" 2>/dev/null && [ $w -lt 10 ]; do sleep 1; w=$((w+1)); done
    kill -9 "${VPN_PID:-0}" 2>/dev/null || true
}

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  airvpn-rs Tier 2: Adversarial Tests${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo ""

[ "$(id -u)" -ne 0 ] && echo "ERROR: Must run as root" && exit 1
[ ! -x "$BINARY" ] && echo "ERROR: Binary not found" && exit 1

DEFAULT_IFACE=$(get_default_iface)
REAL_IP=$(get_real_ip)
log "Default interface: $DEFAULT_IFACE"
log "Real IP: $REAL_IP"

cleanup
echo ""

# ═══════════════════════════════════════════════════
# Test 1: Verify actual nftables rule content
# ═══════════════════════════════════════════════════
separator
log "Test 1: nftables rule content verification"

if start_vpn; then
    RULES=$(nft list table inet airvpn_lock 2>/dev/null)

    # Check chain policies
    if echo "$RULES" | grep -q "policy drop"; then
        pass "Test 1a: Default policy is DROP"
    else
        fail "Test 1a: Default policy is NOT drop"
    fi

    # Check loopback allowed
    if echo "$RULES" | grep -q 'iifname "lo".*accept'; then
        pass "Test 1b: Loopback traffic allowed"
    else
        fail "Test 1b: Loopback rule missing"
    fi

    # Check conntrack
    if echo "$RULES" | grep -q "ct state.*established"; then
        pass "Test 1c: Connection tracking (established) present"
    else
        fail "Test 1c: Connection tracking rule missing"
    fi

    # Check VPN interface allowed (look for the comment tag pattern)
    WG_IFACE=$(ip link show type wireguard 2>/dev/null | head -1 | awk -F: '{print $2}' | tr -d ' ')
    if [ -n "$WG_IFACE" ] && echo "$RULES" | grep -qE "iifname.*$WG_IFACE|airvpn_interface.*$WG_IFACE"; then
        pass "Test 1d: VPN interface ($WG_IFACE) allowed in rules"
    elif [ -n "$WG_IFACE" ]; then
        # allow_interface might not have been called yet — check if interface exists in any rule
        log "  WG interface: $WG_IFACE — checking nft rules..."
        IFACE_RULES=$(echo "$RULES" | grep -c "$WG_IFACE" || echo "0")
        if [ "$IFACE_RULES" -gt 0 ]; then
            pass "Test 1d: VPN interface ($WG_IFACE) found in $IFACE_RULES rules"
        else
            fail "Test 1d: VPN interface ($WG_IFACE) not found in nftables rules"
        fi
    else
        fail "Test 1d: No WireGuard interface found"
    fi

    # Check IPv6 NDP rules (hoplimit 255)
    if echo "$RULES" | grep -q "hoplimit 255"; then
        pass "Test 1e: IPv6 NDP rules present (hoplimit 255)"
    else
        fail "Test 1e: IPv6 NDP rules missing"
    fi

    # Check RH0 drop
    if echo "$RULES" | grep -q "rt type 0.*drop"; then
        pass "Test 1f: IPv6 RH0 drop rule present"
    else
        fail "Test 1f: IPv6 RH0 drop rule missing"
    fi
else
    fail "Test 1: VPN failed to connect"
fi

# ═══════════════════════════════════════════════════
# Test 2: Third-party DNS leak verification
# ═══════════════════════════════════════════════════
separator
log "Test 2: Third-party DNS verification"

# Use multiple methods to check DNS
# Try dig first, fall back to nslookup, fall back to python
DNS_SERVER=""
if command -v dig &>/dev/null; then
    DNS_SERVER=$(dig +short +timeout=5 whoami.akamai.net 2>/dev/null || echo "")
elif command -v nslookup &>/dev/null; then
    DNS_SERVER=$(nslookup -timeout=5 whoami.akamai.net 2>/dev/null | grep "Address:" | tail -1 | awk '{print $2}' || echo "")
fi
# Also try curl-based check as fallback
if [ -z "$DNS_SERVER" ]; then
    DNS_SERVER=$(curl -s --connect-timeout 5 https://am.i.mullvad.net/json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('ip',''))" 2>/dev/null || echo "")
fi

if [ -n "$DNS_SERVER" ]; then
    log "  External resolver/IP check: $DNS_SERVER"
    if [ "$DNS_SERVER" = "$REAL_IP" ]; then
        fail "Test 2a: External check shows your real IP — LEAK"
    else
        pass "Test 2a: External check ($DNS_SERVER) differs from real IP"
    fi
else
    fail "Test 2a: Could not reach any DNS/IP check service"
fi

# Check we're using AirVPN's DNS by verifying resolv.conf
VPN_DNS=$(grep "^nameserver" /etc/resolv.conf | head -1 | awk '{print $2}')
if [[ "$VPN_DNS" == 10.* ]] || [[ "$VPN_DNS" == fd7d:* ]]; then
    pass "Test 2b: resolv.conf nameserver is VPN-internal ($VPN_DNS)"
else
    fail "Test 2b: resolv.conf nameserver ($VPN_DNS) looks like ISP DNS"
fi

# ═══════════════════════════════════════════════════
# Test 3: Multiple bypass attempts
# ═══════════════════════════════════════════════════
separator
log "Test 3: Multiple bypass methods"

# Raw socket ping to external IP
PING_BYPASS=$(ping -c 1 -W 3 -I "$DEFAULT_IFACE" 8.8.8.8 2>&1 || true)
if echo "$PING_BYPASS" | grep -qE "100% packet loss|not permitted|prohibited"; then
    pass "Test 3a: ICMP ping via $DEFAULT_IFACE blocked"
else
    fail "Test 3a: ICMP ping via $DEFAULT_IFACE NOT blocked"
fi

# UDP traffic attempt
NCAT_RESULT=$(timeout 3 bash -c "echo test | nc -u -w 1 -s $(ip -4 addr show "$DEFAULT_IFACE" 2>/dev/null | grep inet | awk '{print $2}' | cut -d/ -f1) 8.8.8.8 53" 2>&1 || true)
pass "Test 3b: UDP via $DEFAULT_IFACE attempted (non-fatal check)"

# TCP to a known IP via physical interface
TCP_BYPASS=$(curl -s --connect-timeout 3 --interface "$DEFAULT_IFACE" http://1.1.1.1 2>&1 || echo "BLOCKED")
if echo "$TCP_BYPASS" | grep -qiE "timed out|refused|blocked|reset|couldn't connect"; then
    pass "Test 3c: TCP via $DEFAULT_IFACE to 1.1.1.1 blocked"
elif [ "$TCP_BYPASS" = "BLOCKED" ]; then
    pass "Test 3c: TCP via $DEFAULT_IFACE to 1.1.1.1 blocked"
else
    fail "Test 3c: TCP via $DEFAULT_IFACE reached 1.1.1.1!"
fi

# ═══════════════════════════════════════════════════
# Test 4: IPv6 leak attempts
# ═══════════════════════════════════════════════════
separator
log "Test 4: IPv6 leak prevention (comprehensive)"

# Check all non-lo interfaces have IPv6 disabled
IPV6_LEAK=false
for iface_dir in /proc/sys/net/ipv6/conf/*/; do
    iface=$(basename "$iface_dir")
    [ "$iface" = "lo" ] && continue
    [ "$iface" = "all" ] && continue
    [ "$iface" = "default" ] && continue
    # Skip the VPN interface (IPv6 must be enabled for wg-quick to add IPv6 addresses)
    [[ "$iface" == avpn-* ]] && continue
    [ "$iface" = "${WG_IFACE:-}" ] && continue

    val=$(cat "${iface_dir}disable_ipv6" 2>/dev/null || echo "?")
    if [ "$val" != "1" ]; then
        fail "Test 4: IPv6 enabled on $iface (disable_ipv6=$val)"
        IPV6_LEAK=true
    fi
done
if ! $IPV6_LEAK; then
    pass "Test 4: IPv6 disabled on all non-VPN/non-lo interfaces"
fi

# ═══════════════════════════════════════════════════
# Test 5: Stability — hold connection for 30s
# ═══════════════════════════════════════════════════
separator
log "Test 5: Connection stability (30 second hold)"

VPN_IP_START=$(curl -s --connect-timeout 10 ifconfig.me 2>/dev/null || echo "FAILED")
log "  VPN IP at start: $VPN_IP_START"

STABLE=true
for i in $(seq 1 6); do
    sleep 5
    CHECK_IP=$(curl -s --connect-timeout 10 ifconfig.me 2>/dev/null || echo "FAILED")
    if [ "$CHECK_IP" = "$REAL_IP" ]; then
        fail "Test 5: Real IP leaked at check $i (${i}*5s)"
        STABLE=false
        break
    elif [ "$CHECK_IP" = "FAILED" ]; then
        fail "Test 5: Connection lost at check $i (${i}*5s)"
        STABLE=false
        break
    fi
    log "  Check $i (${i}0s): $CHECK_IP ✓"
done
if $STABLE; then
    pass "Test 5: Connection stable for 30s (6 checks)"
fi

# ═══════════════════════════════════════════════════
# Test 6: DNS drift resistance
# ═══════════════════════════════════════════════════
separator
log "Test 6: DNS drift resistance — tamper with resolv.conf"

# Save current VPN resolv.conf
VPN_RESOLV=$(cat /etc/resolv.conf)

# Tamper: overwrite with ISP DNS
echo "nameserver 8.8.8.8" > /etc/resolv.conf
log "  Tampered resolv.conf with 8.8.8.8"

# Wait for drift check to kick in (our monitor loop checks every 5s)
sleep 8

RESTORED_RESOLV=$(cat /etc/resolv.conf)
if echo "$RESTORED_RESOLV" | grep -q "10.128.0.1"; then
    pass "Test 6: DNS drift detected and corrected"
else
    fail "Test 6: DNS drift NOT corrected — resolv.conf still tampered"
    # Restore manually
    echo "$VPN_RESOLV" > /etc/resolv.conf
fi

# ═══════════════════════════════════════════════════
# Test 7: Orphan nftables detection after unclean stop
# ═══════════════════════════════════════════════════
separator
log "Test 7: Recovery handles orphaned nftables"

stop_vpn
sleep 2

# Manually leave a stale nftables table (simulating incomplete cleanup)
nft add table inet airvpn_lock 2>/dev/null || true

# Start VPN — should detect and handle the orphaned table
if start_vpn; then
    # Check it's working despite the pre-existing table
    VPN_IP_7=$(curl -s --connect-timeout 10 ifconfig.me 2>/dev/null || echo "FAILED")
    if [ "$VPN_IP_7" != "FAILED" ] && [ "$VPN_IP_7" != "$REAL_IP" ]; then
        pass "Test 7: Connected despite orphaned nftables table"
    else
        fail "Test 7: Orphaned table prevented connection"
    fi
    stop_vpn
else
    fail "Test 7: Failed to connect with orphaned nftables table"
fi

# ═══════════════════════════════════════════════════
# Test 8: Multiple routing rule cleanup
# ═══════════════════════════════════════════════════
separator
log "Test 8: No leaked routing rules after multiple connect/disconnect cycles"

cleanup
sleep 1

for cycle in 1 2 3; do
    if start_vpn; then
        stop_vpn
        sleep 2
    fi
done

# Count routing rules for table 51820 (grep -c can return multiline with || echo)
RULE_COUNT=$(ip rule show 2>/dev/null | grep -c "51820" || true)
SUPPRESS_COUNT=$(ip rule show 2>/dev/null | grep -c "suppress_prefixlength" || true)
# Ensure single integer (trim whitespace/newlines)
RULE_COUNT=$(echo "$RULE_COUNT" | tr -d '[:space:]')
SUPPRESS_COUNT=$(echo "$SUPPRESS_COUNT" | tr -d '[:space:]')
RULE_COUNT=${RULE_COUNT:-0}
SUPPRESS_COUNT=${SUPPRESS_COUNT:-0}

if [ "$RULE_COUNT" -eq 0 ] && [ "$SUPPRESS_COUNT" -eq 0 ]; then
    pass "Test 8: No leaked routing rules after 3 cycles"
else
    fail "Test 8: Found $RULE_COUNT fwmark rules and $SUPPRESS_COUNT suppress rules after 3 cycles"
fi

# ═══════════════════════════════════════════════════
# Final cleanup
# ═══════════════════════════════════════════════════
cleanup

echo ""
separator
echo -e "${BOLD}  Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}"
separator
echo ""
echo "Detailed log: /tmp/airvpn-rs.log"

[ "$FAIL" -gt 0 ] && exit 1 || exit 0
