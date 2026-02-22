#!/usr/bin/env bash
# Tier 3 adversarial tests — active attack simulation
# Run as root: sudo bash tests/adversarial-tier3.sh
#
# Section A: Isolated tests (no VPN connection needed)
# Section B: Connected tests (requires AIRVPN_USER + AIRVPN_PASS or saved profile)

set -euo pipefail

BINARY="./target/release/airvpn"
PASS=0
FAIL=0
SKIP=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }
skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; SKIP=$((SKIP+1)); }
log() { echo -e "${BOLD}[TEST]${NC} $1"; }
separator() { echo "────────────────────────────────────────────────"; }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

get_default_iface() { ip route show default 2>/dev/null | awk '{print $5; exit}'; }
get_default_gw() { ip route show default 2>/dev/null | awk '{print $3; exit}'; }

# Minimal nftables ruleset that mirrors the production table inet airvpn_lock
# at priority -300 with policy drop.  Only loopback, DHCP, and conntrack are
# allowed — no VPN interface rules, so ALL external traffic should be dropped.
install_killswitch_ruleset() {
    local ruleset
    ruleset=$(cat <<'NFTEOF'
table inet airvpn_lock {
  chain input {
    type filter hook input priority -300; policy drop;
    iifname "lo" counter accept
    iifname != "lo" ip6 saddr ::1 counter drop
    ip saddr 255.255.255.255 counter accept
    ip6 saddr ff02::1:2 counter accept
    ip6 saddr ff05::1:3 counter accept
    ct state related,established counter accept
    counter drop comment "airvpn_filter_input_latest_rule"
  }
  chain forward {
    type filter hook forward priority -300; policy drop;
    counter drop comment "airvpn_filter_forward_latest_rule"
  }
  chain output {
    type filter hook output priority -300; policy drop;
    oifname "lo" counter accept
    ip daddr 255.255.255.255 counter accept
    ip6 daddr ff02::1:2 counter accept
    ip6 daddr ff05::1:3 counter accept
    counter drop comment "airvpn_filter_output_latest_rule"
  }
}
NFTEOF
    )
    echo "$ruleset" | nft -f -
}

remove_killswitch() {
    nft delete table inet airvpn_lock 2>/dev/null || true
}

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

cleanup_all() {
    pkill -f "airvpn connect" 2>/dev/null || true
    sleep 2
    $BINARY recover 2>/dev/null || true
    remove_killswitch
    # Remove injected routes
    local gw iface
    gw=$(get_default_gw)
    iface=$(get_default_iface)
    ip route del 8.8.8.8/32 via "$gw" dev "$iface" 2>/dev/null || true
    # Remove dummy interface
    ip link del test-avpn-t3 2>/dev/null || true
    # Restore default IPv6 template
    echo 0 > /proc/sys/net/ipv6/conf/default/disable_ipv6 2>/dev/null || true
    # Routing rules
    ip -4 rule delete not fwmark 51820 table 51820 2>/dev/null || true
    ip -6 rule delete not fwmark 51820 table 51820 2>/dev/null || true
    ip -4 rule delete table main suppress_prefixlength 0 2>/dev/null || true
    ip -6 rule delete table main suppress_prefixlength 0 2>/dev/null || true
    [ -f /etc/resolv.conf.airvpn-rs ] && cp /etc/resolv.conf.airvpn-rs /etc/resolv.conf
}

trap cleanup_all EXIT

# ---------------------------------------------------------------------------
# Preamble
# ---------------------------------------------------------------------------

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  airvpn-rs Tier 3: Adversarial Attack Simulation${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo ""

[ "$(id -u)" -ne 0 ] && echo "ERROR: Must run as root" && exit 1
[ ! -x "$BINARY" ] && echo "ERROR: Binary not found at $BINARY" && exit 1

DEFAULT_IFACE=$(get_default_iface)
DEFAULT_GW=$(get_default_gw)
log "Default interface: $DEFAULT_IFACE"
log "Default gateway:   $DEFAULT_GW"

cleanup_all 2>/dev/null || true
echo ""

# ═══════════════════════════════════════════════════
# SECTION A: Isolated Tests (no VPN connection)
# ═══════════════════════════════════════════════════

echo -e "${BOLD}--- Section A: Isolated Tests (no VPN needed) ---${NC}"
echo ""

# ═══════════════════════════════════════════════════
# A1: Kill switch blocks traffic when WireGuard is down
# ═══════════════════════════════════════════════════
separator
log "A1: Kill switch blocks all external traffic when WireGuard is down"

install_killswitch_ruleset

# Capture non-LAN traffic on the default interface
PCAP_A1=$(mktemp /tmp/t3-a1-XXXXXX.pcap)
timeout 10 tcpdump -i "$DEFAULT_IFACE" -w "$PCAP_A1" \
    'not (dst net 10.0.0.0/8 or dst net 172.16.0.0/12 or dst net 192.168.0.0/16)' \
    >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1

# Attempt external traffic (all should fail)
curl --connect-timeout 3 -s ifconfig.me >/dev/null 2>&1 || true
ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 || true
dig +short +timeout=2 @8.8.8.8 example.com >/dev/null 2>&1 || true

# Wait for tcpdump to finish
wait "$TCPDUMP_PID" 2>/dev/null || true

PKT_COUNT=$(tcpdump -r "$PCAP_A1" 2>/dev/null | wc -l)
rm -f "$PCAP_A1"
remove_killswitch

if [ "$PKT_COUNT" -eq 0 ]; then
    pass "A1: Zero leaked packets with kill switch active (curl, ping, dig all blocked)"
else
    fail "A1: $PKT_COUNT packets leaked through kill switch"
fi

# ═══════════════════════════════════════════════════
# A2: DHCP route injection blocked by nftables
# ═══════════════════════════════════════════════════
separator
log "A2: DHCP route injection — nftables blocks despite rogue routes"

install_killswitch_ruleset

# Inject a host route that bypasses the VPN (simulating DHCP option 121 attack)
ip route add 8.8.8.8/32 via "$DEFAULT_GW" dev "$DEFAULT_IFACE" 2>/dev/null || true

PCAP_A2=$(mktemp /tmp/t3-a2-XXXXXX.pcap)
timeout 10 tcpdump -i "$DEFAULT_IFACE" -w "$PCAP_A2" 'host 8.8.8.8' >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1

# Attempt traffic to the injected route target
ping -c 2 -W 2 8.8.8.8 >/dev/null 2>&1 || true
curl --connect-timeout 3 -s http://8.8.8.8 >/dev/null 2>&1 || true

wait "$TCPDUMP_PID" 2>/dev/null || true

PKT_COUNT=$(tcpdump -r "$PCAP_A2" 2>/dev/null | wc -l)
rm -f "$PCAP_A2"

# Clean up injected route and nftables
ip route del 8.8.8.8/32 via "$DEFAULT_GW" dev "$DEFAULT_IFACE" 2>/dev/null || true
remove_killswitch

if [ "$PKT_COUNT" -eq 0 ]; then
    pass "A2: Zero packets leaked despite injected host route to 8.8.8.8"
else
    fail "A2: $PKT_COUNT packets leaked through injected route"
fi

# ═══════════════════════════════════════════════════
# A3: IPv6 disabled on newly created interface
# ═══════════════════════════════════════════════════
separator
log "A3: IPv6 disabled on dynamically created interfaces"

# Save original default template
ORIG_DEFAULT_IPV6=$(cat /proc/sys/net/ipv6/conf/default/disable_ipv6)

# Set the default template so new interfaces inherit disable_ipv6=1
echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6

# Create a dummy interface
ip link add test-avpn-t3 type dummy
ip link set test-avpn-t3 up

# Check the new interface inherited disable_ipv6=1
NEW_IFACE_IPV6=$(cat /proc/sys/net/ipv6/conf/test-avpn-t3/disable_ipv6 2>/dev/null || echo "?")
IPV6_ADDRS=$(ip -6 addr show dev test-avpn-t3 2>/dev/null | grep -c "inet6" || true)

# Clean up
ip link del test-avpn-t3 2>/dev/null || true
echo "$ORIG_DEFAULT_IPV6" > /proc/sys/net/ipv6/conf/default/disable_ipv6

if [ "$NEW_IFACE_IPV6" = "1" ] && [ "$IPV6_ADDRS" -eq 0 ]; then
    pass "A3: New interface inherits disable_ipv6=1, zero IPv6 addresses"
elif [ "$NEW_IFACE_IPV6" = "1" ]; then
    fail "A3: disable_ipv6=1 but found $IPV6_ADDRS IPv6 addresses"
else
    fail "A3: New interface has disable_ipv6=$NEW_IFACE_IPV6 (expected 1)"
fi

# ═══════════════════════════════════════════════════
# SECTION B: Connected Tests (requires VPN)
# ═══════════════════════════════════════════════════

echo ""
echo -e "${BOLD}--- Section B: Connected Tests (VPN required) ---${NC}"
echo ""

if [ -z "${AIRVPN_USER:-}" ]; then
    log "AIRVPN_USER not set — checking for saved profile..."
    if $BINARY status >/dev/null 2>&1; then
        log "Found saved profile, proceeding with connected tests"
    else
        skip "B1: DNS leak during resolv.conf tampering (no credentials)"
        skip "B2: Traffic leak during interface down/up (no credentials)"
        skip "B3: Concurrent DNS manipulation race (no credentials)"
        skip "B4: nftables table deletion detection (no credentials)"
        echo ""
        separator
        echo -e "${BOLD}  Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}, ${YELLOW}$SKIP skipped${NC}"
        separator
        echo ""
        [ "$FAIL" -gt 0 ] && exit 1 || exit 0
    fi
fi

# ═══════════════════════════════════════════════════
# B1: DNS leak during resolv.conf tampering
# ═══════════════════════════════════════════════════
separator
log "B1: DNS leak during resolv.conf tampering"

if start_vpn; then
    # Save current VPN resolv.conf
    VPN_RESOLV=$(cat /etc/resolv.conf)

    PCAP_B1=$(mktemp /tmp/t3-b1-XXXXXX.pcap)
    timeout 15 tcpdump -i "$DEFAULT_IFACE" -w "$PCAP_B1" 'udp port 53 and host 8.8.8.8' \
        >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 1

    # Tamper with resolv.conf
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    log "  Tampered resolv.conf with 8.8.8.8"

    # Wait for the daemon's drift monitor to restore it
    sleep 8

    # Check if resolv.conf was restored
    RESTORED_NS=$(grep "^nameserver" /etc/resolv.conf | head -1 | awk '{print $2}')
    B1_RESTORED=false
    if [[ "$RESTORED_NS" == 10.* ]] || [[ "$RESTORED_NS" == fd7d:* ]]; then
        B1_RESTORED=true
    fi

    wait "$TCPDUMP_PID" 2>/dev/null || true

    PKT_COUNT=$(tcpdump -r "$PCAP_B1" 2>/dev/null | wc -l)
    rm -f "$PCAP_B1"

    if $B1_RESTORED && [ "$PKT_COUNT" -eq 0 ]; then
        pass "B1: resolv.conf restored ($RESTORED_NS) AND zero DNS leak packets"
    elif $B1_RESTORED; then
        fail "B1: resolv.conf restored but $PKT_COUNT DNS packets leaked to 8.8.8.8"
    elif [ "$PKT_COUNT" -eq 0 ]; then
        fail "B1: Zero DNS leak packets but resolv.conf NOT restored (nameserver=$RESTORED_NS)"
    else
        fail "B1: resolv.conf NOT restored AND $PKT_COUNT DNS packets leaked"
    fi

    # Restore manually if needed
    if ! $B1_RESTORED; then
        echo "$VPN_RESOLV" > /etc/resolv.conf
    fi

    stop_vpn
    sleep 2
else
    fail "B1: VPN failed to connect"
fi

# ═══════════════════════════════════════════════════
# B2: Traffic leak during interface down/up
# ═══════════════════════════════════════════════════
separator
log "B2: Traffic leak during WireGuard interface down/up cycle"

if start_vpn; then
    WG_IFACE=$(ip link show type wireguard 2>/dev/null | grep -o 'avpn-[^ :]*' | head -1)
    if [ -z "$WG_IFACE" ]; then
        fail "B2: No WireGuard interface found"
    else
        PCAP_B2=$(mktemp /tmp/t3-b2-XXXXXX.pcap)
        timeout 15 tcpdump -i "$DEFAULT_IFACE" -w "$PCAP_B2" \
            'not (dst net 10.0.0.0/8 or dst net 172.16.0.0/12 or dst net 192.168.0.0/16)' \
            >/dev/null 2>&1 &
        TCPDUMP_PID=$!
        sleep 1

        # Bring WireGuard interface down
        ip link set "$WG_IFACE" down
        log "  Brought $WG_IFACE down"

        sleep 2

        # Attempt traffic while interface is down
        curl --connect-timeout 3 -s ifconfig.me >/dev/null 2>&1 || true
        ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 || true

        # Bring it back up
        ip link set "$WG_IFACE" up
        log "  Brought $WG_IFACE back up"

        sleep 2

        wait "$TCPDUMP_PID" 2>/dev/null || true

        # Verify nftables table survived the down/up cycle
        NFT_ALIVE=false
        if nft list table inet airvpn_lock >/dev/null 2>&1; then
            NFT_ALIVE=true
        fi

        PKT_COUNT=$(tcpdump -r "$PCAP_B2" 2>/dev/null | wc -l)
        rm -f "$PCAP_B2"

        if $NFT_ALIVE && [ "$PKT_COUNT" -eq 0 ]; then
            pass "B2: nftables survived down/up, zero leaked packets"
        elif $NFT_ALIVE; then
            fail "B2: nftables survived but $PKT_COUNT packets leaked"
        elif [ "$PKT_COUNT" -eq 0 ]; then
            fail "B2: Zero leaked packets but nftables table was lost"
        else
            fail "B2: nftables table lost AND $PKT_COUNT packets leaked"
        fi
    fi

    stop_vpn
    sleep 2
else
    fail "B2: VPN failed to connect"
fi

# ═══════════════════════════════════════════════════
# B3: Concurrent DNS manipulation race
# ═══════════════════════════════════════════════════
separator
log "B3: Concurrent DNS manipulation race (10s attack)"

if start_vpn; then
    PCAP_B3=$(mktemp /tmp/t3-b3-XXXXXX.pcap)
    timeout 20 tcpdump -i "$DEFAULT_IFACE" -w "$PCAP_B3" 'udp port 53 and host 8.8.8.8' \
        >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 1

    # Background attacker: overwrite resolv.conf every 200ms for 10s
    (
        end=$((SECONDS + 10))
        while [ $SECONDS -lt $end ]; do
            echo "nameserver 8.8.8.8" > /etc/resolv.conf 2>/dev/null || true
            sleep 0.2
        done
    ) &
    ATTACKER_PID=$!

    # Foreground: send DNS queries every 500ms for 10s
    QUERY_COUNT=0
    end=$((SECONDS + 10))
    while [ $SECONDS -lt $end ]; do
        dig +short +timeout=1 example.com >/dev/null 2>&1 || true
        QUERY_COUNT=$((QUERY_COUNT + 1))
        sleep 0.5
    done
    log "  Sent $QUERY_COUNT DNS queries during 10s attack window"

    # Wait for attacker to finish
    wait "$ATTACKER_PID" 2>/dev/null || true

    # Give the drift monitor time to restore
    sleep 4

    # Check resolv.conf restored
    RESTORED_NS=$(grep "^nameserver" /etc/resolv.conf | head -1 | awk '{print $2}')
    B3_RESTORED=false
    if [[ "$RESTORED_NS" == 10.* ]] || [[ "$RESTORED_NS" == fd7d:* ]]; then
        B3_RESTORED=true
    fi

    wait "$TCPDUMP_PID" 2>/dev/null || true

    PKT_COUNT=$(tcpdump -r "$PCAP_B3" 2>/dev/null | wc -l)
    rm -f "$PCAP_B3"

    if $B3_RESTORED && [ "$PKT_COUNT" -eq 0 ]; then
        pass "B3: Zero DNS leak packets during 10s race, resolv.conf restored ($RESTORED_NS)"
    elif [ "$PKT_COUNT" -eq 0 ]; then
        fail "B3: Zero DNS leak packets but resolv.conf NOT restored (nameserver=$RESTORED_NS)"
    else
        fail "B3: $PKT_COUNT DNS packets leaked to 8.8.8.8 during race"
    fi

    stop_vpn
    sleep 2
else
    fail "B3: VPN failed to connect"
fi

# ═══════════════════════════════════════════════════
# B4: nftables table deletion detection
# ═══════════════════════════════════════════════════
separator
log "B4: nftables table deletion detection"

if start_vpn; then
    # Delete the kill switch table out from under the VPN
    nft delete table inet airvpn_lock 2>/dev/null || true
    log "  Deleted table inet airvpn_lock while VPN running"

    # Wait for the daemon to notice
    sleep 5

    # Check the VPN log for an error/warning about the kill switch
    B4_DETECTED=false
    if grep -qiE "kill.?switch|netlock|nftables.*(missing|deleted|lost|gone|error|fail)|table.*not found|reconnect" \
        /tmp/airvpn-rs.log /tmp/airvpn-rs-stdout.log 2>/dev/null; then
        B4_DETECTED=true
    fi

    if $B4_DETECTED; then
        pass "B4: VPN detected nftables table deletion"
    else
        fail "B4: VPN did NOT detect nftables table deletion (check monitoring)"
    fi

    stop_vpn
    sleep 2
else
    fail "B4: VPN failed to connect"
fi

# ═══════════════════════════════════════════════════
# Final cleanup + results
# ═══════════════════════════════════════════════════
cleanup_all 2>/dev/null || true

echo ""
separator
echo -e "${BOLD}  Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}, ${YELLOW}$SKIP skipped${NC}"
separator
echo ""
echo "Detailed log: /tmp/airvpn-rs.log"

[ "$FAIL" -gt 0 ] && exit 1 || exit 0
