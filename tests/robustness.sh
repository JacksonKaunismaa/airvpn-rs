#!/usr/bin/env bash
# Robustness test suite for airvpn-rs
# Run as root: sudo bash tests/robustness.sh
#
# Prerequisites: airvpn-rs built (cargo build --release), credentials saved
# This script will connect/disconnect the VPN multiple times.

set -euo pipefail

BINARY="./target/release/airvpn"
LOG="/tmp/airvpn-rs-robustness.log"
PASS=0
FAIL=0
SKIP=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

log() { echo -e "${BOLD}[TEST]${NC} $1"; }
pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }
skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; SKIP=$((SKIP+1)); }
separator() { echo "────────────────────────────────────────────────"; }

cleanup() {
    log "Cleaning up..."
    # Kill any running airvpn
    pkill -f "airvpn connect" 2>/dev/null || true
    sleep 2
    # Force recover
    $BINARY recover 2>/dev/null || true
    # Manual cleanup in case recover missed something
    nft delete table inet airvpn_lock 2>/dev/null || true
    ip -4 rule delete not fwmark 51820 table 51820 2>/dev/null || true
    ip -6 rule delete not fwmark 51820 table 51820 2>/dev/null || true
    ip -4 rule delete table main suppress_prefixlength 0 2>/dev/null || true
    ip -6 rule delete table main suppress_prefixlength 0 2>/dev/null || true
    # Restore DNS if backup exists
    if [ -f /etc/resolv.conf.airvpn-rs ]; then
        cp /etc/resolv.conf.airvpn-rs /etc/resolv.conf
    fi
    # Re-enable IPv6
    for f in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
        echo 0 > "$f" 2>/dev/null || true
    done
}

# Get real IP before any VPN stuff
get_real_ip() {
    curl -s --connect-timeout 10 ifconfig.me 2>/dev/null || echo "FAILED"
}

# Get current default interface
get_default_iface() {
    ip route show default 2>/dev/null | awk '{print $5; exit}'
}

# Wait for VPN to connect (poll log for "Connected to")
wait_for_connect() {
    local timeout=${1:-30}
    local start=$SECONDS
    while [ $((SECONDS - start)) -lt "$timeout" ]; do
        if grep -q "Connected to" /tmp/airvpn-rs.log 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# Start VPN in background, wait for connection
start_vpn() {
    local extra_args="${1:-}"
    rm -f /tmp/airvpn-rs.log
    $BINARY connect --skip-ping $extra_args > /tmp/airvpn-rs-stdout.log 2>&1 &
    VPN_PID=$!
    if wait_for_connect 45; then
        return 0
    else
        return 1
    fi
}

# Stop VPN gracefully
stop_vpn() {
    if [ -n "${VPN_PID:-}" ] && kill -0 "$VPN_PID" 2>/dev/null; then
        kill -INT "$VPN_PID" 2>/dev/null || true
        # Wait up to 10s for clean exit
        local waited=0
        while kill -0 "$VPN_PID" 2>/dev/null && [ $waited -lt 10 ]; do
            sleep 1
            waited=$((waited+1))
        done
        if kill -0 "$VPN_PID" 2>/dev/null; then
            kill -9 "$VPN_PID" 2>/dev/null || true
            return 1
        fi
    fi
    return 0
}

# ═══════════════════════════════════════════════════
# Pre-flight
# ═══════════════════════════════════════════════════

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  airvpn-rs Robustness Test Suite${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo ""

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root (sudo bash tests/robustness.sh)"
    exit 1
fi

if [ ! -x "$BINARY" ]; then
    echo "ERROR: Binary not found at $BINARY — run cargo build --release first"
    exit 1
fi

DEFAULT_IFACE=$(get_default_iface)
if [ -z "$DEFAULT_IFACE" ]; then
    echo "ERROR: No default network interface found"
    exit 1
fi

log "Default interface: $DEFAULT_IFACE"
REAL_IP=$(get_real_ip)
log "Real IP: $REAL_IP"

if [ "$REAL_IP" = "FAILED" ]; then
    echo "ERROR: Cannot reach ifconfig.me — check your internet connection"
    exit 1
fi

# Clean slate
cleanup
echo ""

# ═══════════════════════════════════════════════════
# Test 1: Basic connect + IP change
# ═══════════════════════════════════════════════════
separator
log "Test 1: Basic connect — VPN IP should differ from real IP"

if start_vpn; then
    VPN_IP=$(curl -s --connect-timeout 10 ifconfig.me 2>/dev/null || echo "FAILED")
    if [ "$VPN_IP" != "FAILED" ] && [ "$VPN_IP" != "$REAL_IP" ]; then
        pass "Test 1: VPN IP ($VPN_IP) differs from real IP ($REAL_IP)"
    else
        fail "Test 1: VPN IP ($VPN_IP) — expected different from $REAL_IP"
    fi
else
    fail "Test 1: VPN failed to connect within 45s"
fi

# ═══════════════════════════════════════════════════
# Test 2: Network lock blocks direct traffic
# ═══════════════════════════════════════════════════
separator
log "Test 2: Kill switch — direct traffic via $DEFAULT_IFACE should be blocked"

if nft list table inet airvpn_lock &>/dev/null; then
    BYPASS_RESULT=$(curl -s --connect-timeout 5 --interface "$DEFAULT_IFACE" ifconfig.me 2>/dev/null || echo "BLOCKED")
    if [ "$BYPASS_RESULT" = "BLOCKED" ] || [ -z "$BYPASS_RESULT" ]; then
        pass "Test 2: Direct traffic via $DEFAULT_IFACE blocked by kill switch"
    else
        fail "Test 2: Traffic bypassed kill switch! Got: $BYPASS_RESULT"
    fi
else
    fail "Test 2: airvpn_lock table not found — kill switch not active"
fi

# ═══════════════════════════════════════════════════
# Test 3: DNS not leaking
# ═══════════════════════════════════════════════════
separator
log "Test 3: DNS leak check — resolv.conf should point to VPN DNS"

RESOLV_CONTENT=$(cat /etc/resolv.conf 2>/dev/null)
if echo "$RESOLV_CONTENT" | grep -q "10.128.0.1"; then
    pass "Test 3a: resolv.conf points to VPN DNS (10.128.0.1)"
else
    fail "Test 3a: resolv.conf does NOT point to VPN DNS"
fi

# Try direct DNS bypass
DNS_BYPASS=$(dig +short +timeout=3 +tries=1 @8.8.8.8 whoami.akamai.net 2>/dev/null || echo "BLOCKED")
if [ "$DNS_BYPASS" = "BLOCKED" ] || [ -z "$DNS_BYPASS" ]; then
    pass "Test 3b: Direct DNS query to 8.8.8.8 blocked by kill switch"
else
    fail "Test 3b: DNS bypass succeeded (got: $DNS_BYPASS) — DNS leak!"
fi

# ═══════════════════════════════════════════════════
# Test 4: IPv6 disabled
# ═══════════════════════════════════════════════════
separator
log "Test 4: IPv6 leak prevention"

IPV6_DEFAULT=$(cat /proc/sys/net/ipv6/conf/"$DEFAULT_IFACE"/disable_ipv6 2>/dev/null || echo "?")
if [ "$IPV6_DEFAULT" = "1" ]; then
    pass "Test 4: IPv6 disabled on $DEFAULT_IFACE"
else
    fail "Test 4: IPv6 NOT disabled on $DEFAULT_IFACE (value=$IPV6_DEFAULT)"
fi

# ═══════════════════════════════════════════════════
# Test 5: Clean disconnect (Ctrl+C / SIGINT)
# ═══════════════════════════════════════════════════
separator
log "Test 5: Clean disconnect via SIGINT"

if stop_vpn; then
    sleep 2
    # Check cleanup
    LOCK_GONE=true
    DNS_RESTORED=true
    RULES_GONE=true
    IPV6_RESTORED=true

    if nft list table inet airvpn_lock &>/dev/null; then LOCK_GONE=false; fi
    if grep -q "10.128.0.1" /etc/resolv.conf 2>/dev/null; then DNS_RESTORED=false; fi
    if ip rule show 2>/dev/null | grep -q "51820"; then RULES_GONE=false; fi
    IPV6_VAL=$(cat /proc/sys/net/ipv6/conf/"$DEFAULT_IFACE"/disable_ipv6 2>/dev/null || echo "?")
    if [ "$IPV6_VAL" = "1" ]; then IPV6_RESTORED=false; fi

    if $LOCK_GONE; then pass "Test 5a: nftables table removed"; else fail "Test 5a: nftables table STILL EXISTS"; fi
    if $DNS_RESTORED; then pass "Test 5b: DNS restored"; else fail "Test 5b: DNS still points to VPN"; fi
    if $RULES_GONE; then pass "Test 5c: Routing rules cleaned up"; else fail "Test 5c: Routing rules STILL EXIST"; fi
    if $IPV6_RESTORED; then pass "Test 5d: IPv6 re-enabled"; else fail "Test 5d: IPv6 still disabled"; fi

    POST_IP=$(get_real_ip)
    if [ "$POST_IP" = "$REAL_IP" ]; then
        pass "Test 5e: Real IP restored ($POST_IP)"
    else
        fail "Test 5e: IP after disconnect ($POST_IP) != real IP ($REAL_IP)"
    fi
else
    fail "Test 5: VPN didn't stop gracefully within 10s"
fi

# ═══════════════════════════════════════════════════
# Test 6: Crash recovery (kill -9)
# ═══════════════════════════════════════════════════
separator
log "Test 6: Crash recovery (SIGKILL + airvpn recover)"

cleanup
sleep 1

if start_vpn; then
    VPN_PID_BEFORE=$VPN_PID

    # Verify connected
    VPN_IP_6=$(curl -s --connect-timeout 10 ifconfig.me 2>/dev/null || echo "FAILED")
    if [ "$VPN_IP_6" = "FAILED" ] || [ "$VPN_IP_6" = "$REAL_IP" ]; then
        fail "Test 6: VPN not actually connected before kill"
    else
        # Kill hard
        kill -9 "$VPN_PID_BEFORE" 2>/dev/null || true
        sleep 2

        # Kill switch should persist (network broken = safe)
        CRASH_CURL=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || echo "BLOCKED")
        if [ "$CRASH_CURL" = "BLOCKED" ] || [ -z "$CRASH_CURL" ]; then
            pass "Test 6a: Kill switch persists after crash (network blocked)"
        else
            # If traffic works, it should still be VPN IP (tunnel might survive)
            if [ "$CRASH_CURL" = "$REAL_IP" ]; then
                fail "Test 6a: Real IP exposed after crash — kill switch failed!"
            else
                pass "Test 6a: Traffic still through VPN after crash (tunnel survived)"
            fi
        fi

        # Recover
        $BINARY recover 2>/dev/null || true
        sleep 2

        POST_RECOVER_IP=$(get_real_ip)
        if [ "$POST_RECOVER_IP" = "$REAL_IP" ]; then
            pass "Test 6b: Recovery restored real IP ($POST_RECOVER_IP)"
        elif [ "$POST_RECOVER_IP" = "FAILED" ]; then
            fail "Test 6b: No internet after recovery"
        else
            fail "Test 6b: Unexpected IP after recovery ($POST_RECOVER_IP)"
        fi
    fi
else
    fail "Test 6: VPN failed to connect for crash test"
fi

# ═══════════════════════════════════════════════════
# Test 7: Rapid reconnect (no stale state)
# ═══════════════════════════════════════════════════
separator
log "Test 7: Rapid reconnect — connect, disconnect, connect again"

cleanup
sleep 1

if start_vpn; then
    stop_vpn
    sleep 2

    # Second connect immediately
    if start_vpn; then
        VPN_IP_7=$(curl -s --connect-timeout 10 ifconfig.me 2>/dev/null || echo "FAILED")
        if [ "$VPN_IP_7" != "FAILED" ] && [ "$VPN_IP_7" != "$REAL_IP" ]; then
            pass "Test 7: Rapid reconnect works (IP: $VPN_IP_7)"
        else
            fail "Test 7: Rapid reconnect — VPN IP is $VPN_IP_7, expected not $REAL_IP"
        fi
        stop_vpn
    else
        fail "Test 7: Second connect failed (stale state?)"
    fi
else
    fail "Test 7: First connect failed"
fi

# ═══════════════════════════════════════════════════
# Test 8: --server flag
# ═══════════════════════════════════════════════════
separator
log "Test 8: --server flag (connect to specific server)"

cleanup
sleep 1

if start_vpn "--server Achernar"; then
    # Check logs for server name
    if grep -q "Selected server: Achernar" /tmp/airvpn-rs.log 2>/dev/null; then
        pass "Test 8: Connected to requested server Achernar"
    else
        fail "Test 8: Server selection didn't honor --server flag"
    fi
    stop_vpn
else
    fail "Test 8: Connect with --server failed"
fi

# ═══════════════════════════════════════════════════
# Test 9: State file exists during connection
# ═══════════════════════════════════════════════════
separator
log "Test 9: State file management"

cleanup
sleep 1

if start_vpn; then
    if [ -f /run/airvpn-rs/state.json ]; then
        pass "Test 9a: State file exists during connection"
        # Verify it has expected fields
        if python3 -c "import json; d=json.load(open('/run/airvpn-rs/state.json')); assert d['lock_active']; assert d['wg_interface']" 2>/dev/null; then
            pass "Test 9b: State file has correct structure"
        else
            fail "Test 9b: State file structure invalid"
        fi
    else
        # Check /tmp fallback
        if [ -f /tmp/airvpn-rs-state.json ]; then
            pass "Test 9a: State file exists (fallback location)"
        else
            fail "Test 9a: No state file found"
        fi
    fi
    stop_vpn
    sleep 2

    if [ ! -f /run/airvpn-rs/state.json ] && [ ! -f /tmp/airvpn-rs-state.json ]; then
        pass "Test 9c: State file removed after disconnect"
    else
        fail "Test 9c: State file still exists after disconnect"
    fi
else
    fail "Test 9: VPN failed to connect for state file test"
fi

# ═══════════════════════════════════════════════════
# Final cleanup
# ═══════════════════════════════════════════════════
cleanup

# ═══════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════
echo ""
separator
echo -e "${BOLD}  Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}, ${YELLOW}$SKIP skipped${NC}"
separator
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "Log file: /tmp/airvpn-rs.log"
    echo "Stdout log: /tmp/airvpn-rs-stdout.log"
    exit 1
fi
