#!/usr/bin/env bash
# shellcheck shell=bash
#
# test-ping-routing.sh — Exhaustive test of ping routing + firewall behavior
#
# Tests every combination of:
#   - Connected vs disconnected
#   - Session lock vs persistent lock vs both vs neither
#   - With/without host routes
#   - With/without ICMP holes
#   - With/without allowlist entries
#
# Run WHILE CONNECTED: sudo ./scripts/test-ping-routing.sh [server-entry-ip]
# Run WHILE DISCONNECTED: sudo ./scripts/test-ping-routing.sh --disconnected [server-entry-ip]
#
# Non-destructive — cleans up everything it touches.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()   { echo -e "${CYAN}[INFO]${NC}  $*"; }
pass()   { echo -e "${GREEN}[PASS]${NC}  $*"; }
fail()   { echo -e "${RED}[FAIL]${NC}  $*"; }
warn()   { echo -e "${YELLOW}[WARN]${NC}  $*"; }
header() { echo -e "\n${BOLD}${CYAN}=== $* ===${NC}"; }
subhdr() { echo -e "\n${CYAN}--- $* ---${NC}"; }

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo $0 $*"
    exit 1
fi

# Parse args
DISCONNECTED_MODE=false
TEST_IP=""
for arg in "$@"; do
    if [[ "$arg" == "--disconnected" ]]; then
        DISCONNECTED_MODE=true
    elif [[ "$arg" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        TEST_IP="$arg"
    fi
done

# ---------------------------------------------------------------------------
# State tracking for cleanup
# ---------------------------------------------------------------------------
CLEANUP_ROUTE=""
CLEANUP_NFT_HANDLES=()   # "table:chain:handle" entries
CLEANUP_ALLOWLIST=()      # "table:chain:handle" entries (same format)

cleanup_all() {
    echo
    info "Cleaning up..."
    # Remove host route
    if [[ -n "$CLEANUP_ROUTE" ]]; then
        ip -4 route delete "$CLEANUP_ROUTE" 2>/dev/null || true
        info "  Removed route: $CLEANUP_ROUTE"
    fi
    # Remove nft rules by handle
    for entry in "${CLEANUP_NFT_HANDLES[@]}" "${CLEANUP_ALLOWLIST[@]}"; do
        IFS=':' read -r table chain handle <<< "$entry"
        if [[ -n "$handle" ]]; then
            nft delete rule inet "$table" "$chain" handle "$handle" 2>/dev/null || true
            info "  Removed nft rule: $table/$chain handle $handle"
        fi
    done
    info "Cleanup done."
}
trap cleanup_all EXIT

# ---------------------------------------------------------------------------
# Helper: add a /32 host route, track for cleanup
# ---------------------------------------------------------------------------
add_host_route() {
    local ip="$1" gw="$2" dev="$3"
    ip -4 route add "$ip/32" via "$gw" dev "$dev" 2>/dev/null && {
        CLEANUP_ROUTE="$ip/32 via $gw dev $dev"
        return 0
    }
    return 1
}

remove_host_route() {
    if [[ -n "$CLEANUP_ROUTE" ]]; then
        ip -4 route delete $CLEANUP_ROUTE 2>/dev/null || true
        CLEANUP_ROUTE=""
    fi
}

# ---------------------------------------------------------------------------
# Helper: add ICMP hole to a table, track for cleanup
# ---------------------------------------------------------------------------
add_icmp_hole() {
    local table="$1" ip="$2"
    local chain="output"
    # persistent lock has ping_allow subchain
    if [[ "$table" == "airvpn_persist" ]]; then
        chain="ping_allow"
        nft add rule inet "$table" "$chain" ip daddr "$ip" icmp type echo-request counter accept 2>/dev/null || return 1
    else
        nft insert rule inet "$table" "$chain" ip daddr "$ip" icmp type echo-request counter accept 2>/dev/null || return 1
    fi
    local handle
    handle=$(nft -a list chain inet "$table" "$chain" 2>/dev/null | grep "$ip" | grep -oP 'handle \K\d+' | head -1)
    if [[ -n "$handle" ]]; then
        CLEANUP_NFT_HANDLES+=("$table:$chain:$handle")
    fi
    return 0
}

remove_icmp_holes() {
    for entry in "${CLEANUP_NFT_HANDLES[@]}"; do
        IFS=':' read -r table chain handle <<< "$entry"
        if [[ -n "$handle" ]]; then
            nft delete rule inet "$table" "$chain" handle "$handle" 2>/dev/null || true
        fi
    done
    CLEANUP_NFT_HANDLES=()
}

# ---------------------------------------------------------------------------
# Helper: add allowlist entry (ip daddr X accept) to session lock output
# ---------------------------------------------------------------------------
add_allowlist_entry() {
    local table="$1" ip="$2"
    nft insert rule inet "$table" output ip daddr "$ip" counter accept 2>/dev/null || return 1
    local handle
    handle=$(nft -a list chain inet "$table" output 2>/dev/null | grep "ip daddr $ip" | grep -v "icmp" | grep -oP 'handle \K\d+' | head -1)
    if [[ -n "$handle" ]]; then
        CLEANUP_ALLOWLIST+=("$table:output:$handle")
    fi
    return 0
}

remove_allowlist_entries() {
    for entry in "${CLEANUP_ALLOWLIST[@]}"; do
        IFS=':' read -r table chain handle <<< "$entry"
        if [[ -n "$handle" ]]; then
            nft delete rule inet "$table" "$chain" handle "$handle" 2>/dev/null || true
        fi
    done
    CLEANUP_ALLOWLIST=()
}

# ---------------------------------------------------------------------------
# Helper: single ping test, returns 0=success 1=fail
# ---------------------------------------------------------------------------
do_ping() {
    ping -c 1 -W 3 -q "$1" &>/dev/null
}

# ---------------------------------------------------------------------------
# Helper: check routing path
# ---------------------------------------------------------------------------
check_route() {
    ip route get "$1" 2>&1
}

# ---------------------------------------------------------------------------
# Results table
# ---------------------------------------------------------------------------
declare -A RESULTS
record() {
    local test_name="$1" result="$2"
    RESULTS["$test_name"]="$result"
    if [[ "$result" == "PASS" ]]; then
        pass "$test_name"
    elif [[ "$result" == "FAIL" ]]; then
        fail "$test_name"
    else
        warn "$test_name — $result"
    fi
}

# ---------------------------------------------------------------------------
# Gather state
# ---------------------------------------------------------------------------
header "Environment"

VPN_IFACE="avpn0"
VPN_UP=false
if ip link show "$VPN_IFACE" &>/dev/null; then
    VPN_UP=true
    info "VPN interface $VPN_IFACE: UP"
else
    info "VPN interface $VPN_IFACE: DOWN"
fi

if $DISCONNECTED_MODE && $VPN_UP; then
    fail "You passed --disconnected but $VPN_IFACE is up. Disconnect first."
    exit 1
fi

# Get physical gateway
PHYS_GW=$(ip -4 route show default | head -1 | awk '/via/ {print $3}')
PHYS_DEV=$(ip -4 route show default | head -1 | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
if [[ -z "$PHYS_GW" ]]; then
    PHYS_GW=$(ip -4 route show | grep -v "${VPN_IFACE}" | grep "via" | head -1 | awk '{print $3}')
    PHYS_DEV=$(ip -4 route show | grep -v "${VPN_IFACE}" | grep "via" | head -1 | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
fi
if [[ -z "$PHYS_GW" || -z "$PHYS_DEV" ]]; then
    fail "Cannot determine physical gateway"
    exit 1
fi
info "Physical gateway: $PHYS_GW via $PHYS_DEV"

# Get test IP
if [[ -z "$TEST_IP" ]]; then
    info "Fetching a server IP from AirVPN API..."
    API_JSON=$(curl -s --max-time 10 "https://airvpn.org/api/status/" || true)
    if [[ -z "$API_JSON" ]]; then
        fail "Could not reach AirVPN API. Pass a server IP manually."
        exit 1
    fi
    CONNECTED_ENDPOINT=""
    if $VPN_UP; then
        CONNECTED_ENDPOINT=$(ip -4 route show | grep "/32.*via.*$PHYS_GW" | awk '{print $1}' | sed 's|/32||' | head -1)
    fi
    TEST_IP=$(echo "$API_JSON" | python3 -c "
import sys, json, random
data = json.load(sys.stdin)
servers = data.get('servers', [])
endpoint = '$CONNECTED_ENDPOINT'
candidates = [s['ip_v4_in1'] for s in servers if s.get('ip_v4_in1') and s['ip_v4_in1'] != endpoint]
if candidates:
    print(random.choice(candidates))
" 2>/dev/null || true)
    if [[ -z "$TEST_IP" ]]; then
        fail "Could not extract a test IP. Pass one manually."
        exit 1
    fi
fi
info "Test IP: $TEST_IP"

# Detect locks
SESSION_ACTIVE=false
PERSIST_ACTIVE=false
nft list table inet airvpn_lock &>/dev/null 2>&1 && SESSION_ACTIVE=true
nft list table inet airvpn_persist &>/dev/null 2>&1 && PERSIST_ACTIVE=true
info "Session lock:    $($SESSION_ACTIVE && echo ACTIVE || echo inactive)"
info "Persistent lock: $($PERSIST_ACTIVE && echo ACTIVE || echo inactive)"

# Check if test IP is in session lock allowlist already
IP_IN_SESSION_ALLOWLIST=false
if $SESSION_ACTIVE; then
    if nft list chain inet airvpn_lock output 2>/dev/null | grep -q "ip daddr $TEST_IP.*accept"; then
        # Make sure it's not just an ICMP rule
        if nft list chain inet airvpn_lock output 2>/dev/null | grep "ip daddr $TEST_IP" | grep -qv "icmp"; then
            IP_IN_SESSION_ALLOWLIST=true
        fi
    fi
fi
info "Test IP in session allowlist: $IP_IN_SESSION_ALLOWLIST"

# Dump firewall state for reference
header "Firewall State (ICMP + allowlist rules in OUTPUT)"
for table in airvpn_lock airvpn_persist; do
    if nft list table inet "$table" &>/dev/null 2>&1; then
        subhdr "$table OUTPUT"
        nft list chain inet "$table" output 2>/dev/null | grep -iE "icmp|echo|ping|avpn|daddr" | head -20 || echo "  (none)"
        if nft list chain inet "$table" ping_allow &>/dev/null 2>&1; then
            subhdr "$table ping_allow"
            nft list chain inet "$table" ping_allow 2>/dev/null | grep -v "^table\|^}" || echo "  (empty)"
        fi
    fi
done

header "Routing State"
echo "  ip rule list:"
ip rule list | sed 's/^/    /'
echo
echo "  Table 51820:"
ip -4 route show table 51820 2>/dev/null | sed 's/^/    /' || echo "    (not found)"
echo
echo "  Relevant main table routes:"
ip -4 route show table main | grep -v "^default" | head -10 | sed 's/^/    /'

# =========================================================================
# TESTS
# =========================================================================

header "Running Tests"
echo
echo "  Legend: each test cleans up after itself before the next one runs."
echo "  All nft rules and routes are removed between tests."
echo

# -------------------------------------------------------------------------
# Test 1: Plain ping (no modifications)
# -------------------------------------------------------------------------
subhdr "Test 1: Plain ping to $TEST_IP (no modifications)"
ROUTE_INFO=$(check_route "$TEST_IP")
echo "  Route: $ROUTE_INFO"
if do_ping "$TEST_IP"; then
    record "T1: Plain ping" "PASS"
else
    record "T1: Plain ping" "FAIL"
fi

# -------------------------------------------------------------------------
# Test 2: Host route only (no firewall changes)
# -------------------------------------------------------------------------
if $VPN_UP; then
    subhdr "Test 2: Host route only (routing bypass, no firewall changes)"
    if add_host_route "$TEST_IP" "$PHYS_GW" "$PHYS_DEV"; then
        ROUTE_INFO=$(check_route "$TEST_IP")
        echo "  Route: $ROUTE_INFO"
        if do_ping "$TEST_IP"; then
            record "T2: Host route only" "PASS"
        else
            record "T2: Host route only" "FAIL"
        fi
        remove_host_route
    else
        record "T2: Host route only" "SKIP (route add failed)"
    fi
else
    info "Skipping T2 (not connected — no tunnel to bypass)"
    record "T2: Host route only" "SKIP (disconnected)"
fi

# -------------------------------------------------------------------------
# Test 3: Host route + ICMP holes in all active locks
# -------------------------------------------------------------------------
if $VPN_UP; then
    subhdr "Test 3: Host route + ICMP holes in all active locks"
    add_host_route "$TEST_IP" "$PHYS_GW" "$PHYS_DEV" || true
    if $SESSION_ACTIVE; then
        add_icmp_hole "airvpn_lock" "$TEST_IP" && info "  ICMP hole in session lock" || warn "  Failed to add session hole"
    fi
    if $PERSIST_ACTIVE; then
        add_icmp_hole "airvpn_persist" "$TEST_IP" && info "  ICMP hole in persistent lock" || warn "  Failed to add persistent hole"
    fi
    if do_ping "$TEST_IP"; then
        record "T3: Host route + ICMP holes (both locks)" "PASS"
    else
        record "T3: Host route + ICMP holes (both locks)" "FAIL"
    fi
    remove_icmp_holes
    remove_host_route
fi

# -------------------------------------------------------------------------
# Test 4: Host route + ICMP hole in session lock ONLY
# -------------------------------------------------------------------------
if $VPN_UP && $SESSION_ACTIVE && $PERSIST_ACTIVE; then
    subhdr "Test 4: Host route + ICMP hole in session lock ONLY (not persistent)"
    add_host_route "$TEST_IP" "$PHYS_GW" "$PHYS_DEV" || true
    add_icmp_hole "airvpn_lock" "$TEST_IP" && info "  ICMP hole in session lock only" || true
    if do_ping "$TEST_IP"; then
        record "T4: Host route + session hole only" "PASS"
    else
        record "T4: Host route + session hole only" "FAIL"
    fi
    remove_icmp_holes
    remove_host_route
fi

# -------------------------------------------------------------------------
# Test 5: Host route + ICMP hole in persistent lock ONLY
# -------------------------------------------------------------------------
if $VPN_UP && $SESSION_ACTIVE && $PERSIST_ACTIVE; then
    subhdr "Test 5: Host route + ICMP hole in persistent lock ONLY (not session)"
    add_host_route "$TEST_IP" "$PHYS_GW" "$PHYS_DEV" || true
    add_icmp_hole "airvpn_persist" "$TEST_IP" && info "  ICMP hole in persistent lock only" || true
    if do_ping "$TEST_IP"; then
        record "T5: Host route + persistent hole only" "PASS"
    else
        record "T5: Host route + persistent hole only" "FAIL"
    fi
    remove_icmp_holes
    remove_host_route
fi

# -------------------------------------------------------------------------
# Test 6: Host route + allowlist entry in session lock (Eddie approach)
#   This adds "ip daddr <ip> accept" (all protocols) instead of ICMP-only
# -------------------------------------------------------------------------
if $VPN_UP && $SESSION_ACTIVE; then
    subhdr "Test 6: Host route + allowlist entry in session lock (Eddie approach)"
    add_host_route "$TEST_IP" "$PHYS_GW" "$PHYS_DEV" || true
    add_allowlist_entry "airvpn_lock" "$TEST_IP" && info "  Allowlist entry in session lock" || warn "  Failed to add allowlist"
    if $PERSIST_ACTIVE; then
        add_icmp_hole "airvpn_persist" "$TEST_IP" && info "  ICMP hole in persistent lock" || true
    fi
    if do_ping "$TEST_IP"; then
        record "T6: Host route + session allowlist + persist hole" "PASS"
    else
        record "T6: Host route + session allowlist + persist hole" "FAIL"
    fi
    remove_allowlist_entries
    remove_icmp_holes
    remove_host_route
fi

# -------------------------------------------------------------------------
# Test 7: Host route + allowlist in session + allowlist in persistent
#   (Full Eddie-style: all-protocol allow in both locks)
# -------------------------------------------------------------------------
if $VPN_UP && $SESSION_ACTIVE && $PERSIST_ACTIVE; then
    subhdr "Test 7: Host route + allowlist in BOTH locks (full Eddie-style)"
    add_host_route "$TEST_IP" "$PHYS_GW" "$PHYS_DEV" || true
    add_allowlist_entry "airvpn_lock" "$TEST_IP" && info "  Allowlist in session lock" || true
    add_allowlist_entry "airvpn_persist" "$TEST_IP" && info "  Allowlist in persistent lock" || true
    if do_ping "$TEST_IP"; then
        record "T7: Host route + allowlist both locks" "PASS"
    else
        record "T7: Host route + allowlist both locks" "FAIL"
    fi
    remove_allowlist_entries
    remove_host_route
fi

# -------------------------------------------------------------------------
# Test 8: No host route, but IP is allowlisted (ping goes through tunnel)
#   Verifies allowlist alone doesn't affect routing
# -------------------------------------------------------------------------
if $VPN_UP && $SESSION_ACTIVE; then
    subhdr "Test 8: Allowlist in session lock, NO host route (through tunnel)"
    add_allowlist_entry "airvpn_lock" "$TEST_IP" || true
    ROUTE_INFO=$(check_route "$TEST_IP")
    echo "  Route: $ROUTE_INFO"
    if do_ping "$TEST_IP"; then
        record "T8: Allowlist only, no route (through tunnel)" "PASS"
    else
        record "T8: Allowlist only, no route (through tunnel)" "FAIL"
    fi
    remove_allowlist_entries
fi

# -------------------------------------------------------------------------
# Tests 9-12: Disconnected scenarios (persistent lock only)
# -------------------------------------------------------------------------
if ! $VPN_UP; then
    # Test 9: Plain ping, no locks
    if ! $SESSION_ACTIVE && ! $PERSIST_ACTIVE; then
        subhdr "Test 9: Disconnected, no locks, plain ping"
        if do_ping "$TEST_IP"; then
            record "T9: Disconnected, no locks" "PASS"
        else
            record "T9: Disconnected, no locks" "FAIL"
        fi
    fi

    # Test 10: Plain ping, persistent lock active (no holes)
    if $PERSIST_ACTIVE && ! $SESSION_ACTIVE; then
        subhdr "Test 10: Disconnected, persistent lock active, plain ping (no holes)"
        ROUTE_INFO=$(check_route "$TEST_IP")
        echo "  Route: $ROUTE_INFO"
        if do_ping "$TEST_IP"; then
            record "T10: Disconnected + persist lock, plain ping" "PASS"
        else
            record "T10: Disconnected + persist lock, plain ping" "FAIL"
        fi
    fi

    # Test 11: Persistent lock + ICMP hole
    if $PERSIST_ACTIVE && ! $SESSION_ACTIVE; then
        subhdr "Test 11: Disconnected, persistent lock + ICMP hole"
        add_icmp_hole "airvpn_persist" "$TEST_IP" && info "  ICMP hole in persistent lock" || true
        if do_ping "$TEST_IP"; then
            record "T11: Disconnected + persist lock + ICMP hole" "PASS"
        else
            record "T11: Disconnected + persist lock + ICMP hole" "FAIL"
        fi
        remove_icmp_holes
    fi

    # Test 12: Persistent lock + allowlist entry (all-protocol)
    if $PERSIST_ACTIVE && ! $SESSION_ACTIVE; then
        subhdr "Test 12: Disconnected, persistent lock + allowlist entry"
        add_allowlist_entry "airvpn_persist" "$TEST_IP" && info "  Allowlist in persistent lock" || true
        if do_ping "$TEST_IP"; then
            record "T12: Disconnected + persist lock + allowlist" "PASS"
        else
            record "T12: Disconnected + persist lock + allowlist" "FAIL"
        fi
        remove_allowlist_entries
    fi

    # Test 13: Persistent lock + session lock both active while disconnected
    # (unusual but possible if disconnect didn't clean up session lock)
    if $PERSIST_ACTIVE && $SESSION_ACTIVE; then
        subhdr "Test 13: Disconnected, BOTH locks active, plain ping"
        if do_ping "$TEST_IP"; then
            record "T13: Disconnected + both locks, plain ping" "PASS"
        else
            record "T13: Disconnected + both locks, plain ping" "FAIL"
        fi

        subhdr "Test 14: Disconnected, BOTH locks + holes in both"
        add_icmp_hole "airvpn_lock" "$TEST_IP" || true
        add_icmp_hole "airvpn_persist" "$TEST_IP" || true
        if do_ping "$TEST_IP"; then
            record "T14: Disconnected + both locks + holes" "PASS"
        else
            record "T14: Disconnected + both locks + holes" "FAIL"
        fi
        remove_icmp_holes
    fi
fi

# -------------------------------------------------------------------------
# Test 15: Connected, check if connected server's endpoint IP is pingable
#   (should work — endpoint has host route + is in session allowlist)
# -------------------------------------------------------------------------
if $VPN_UP; then
    # Find endpoint: a host route (no /) via our physical gateway, not a subnet
    CONNECTED_ENDPOINT=$(ip -4 route show table main | awk -v gw="$PHYS_GW" \
        '$0 ~ "via "gw && $1 !~ /\// && $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $1; exit}')
    if [[ -n "$CONNECTED_ENDPOINT" ]]; then
        subhdr "Test 15: Ping connected server endpoint $CONNECTED_ENDPOINT (already has host route)"
        ROUTE_INFO=$(check_route "$CONNECTED_ENDPOINT")
        echo "  Route: $ROUTE_INFO"
        IN_ALLOWLIST=false
        if nft list chain inet airvpn_lock output 2>/dev/null | grep "ip daddr $CONNECTED_ENDPOINT" | grep -qv "icmp"; then
            IN_ALLOWLIST=true
        fi
        IN_PERSIST_ALLOWLIST=false
        if $PERSIST_ACTIVE; then
            if nft list chain inet airvpn_persist output 2>/dev/null | grep "ip daddr $CONNECTED_ENDPOINT" | grep -qv "icmp"; then
                IN_PERSIST_ALLOWLIST=true
            fi
        fi
        echo "  In session allowlist: $IN_ALLOWLIST"
        echo "  In persistent allowlist: $IN_PERSIST_ALLOWLIST"
        if do_ping "$CONNECTED_ENDPOINT"; then
            record "T15: Ping connected endpoint (has route+allowlist)" "PASS"
        else
            record "T15: Ping connected endpoint (has route+allowlist)" "FAIL"
        fi
    else
        warn "Could not find connected server endpoint route"
    fi
fi

# -------------------------------------------------------------------------
# Test 16: Connected, session lock ONLY scenario simulation
#   We can't disable persistent lock safely, but we CAN add an allowlist
#   entry in persistent lock and test if that's sufficient (simulating
#   what would happen if persistent lock allowed the IP)
# -------------------------------------------------------------------------
if $VPN_UP && $SESSION_ACTIVE && $PERSIST_ACTIVE; then
    subhdr "Test 16: Host route + session allowlist only (+ persist allowlist to simulate no-persist)"
    info "  Simulates: session lock active, persistent lock either absent or has allowlist"
    add_host_route "$TEST_IP" "$PHYS_GW" "$PHYS_DEV" || true
    add_allowlist_entry "airvpn_lock" "$TEST_IP" && info "  Allowlist in session lock" || true
    add_allowlist_entry "airvpn_persist" "$TEST_IP" && info "  Allowlist in persistent lock" || true
    if do_ping "$TEST_IP"; then
        record "T16: Host route + allowlist in both (full solution)" "PASS"
    else
        record "T16: Host route + allowlist in both (full solution)" "FAIL"
    fi
    remove_allowlist_entries
    remove_host_route
fi

# -------------------------------------------------------------------------
# Test 17: Scale test — add many allowlist entries to check performance
# -------------------------------------------------------------------------
if $VPN_UP || $PERSIST_ACTIVE; then
    subhdr "Test 17: Scale test — add 200 allowlist entries"
    SCALE_TABLE=""
    if $SESSION_ACTIVE; then
        SCALE_TABLE="airvpn_lock"
    elif $PERSIST_ACTIVE; then
        SCALE_TABLE="airvpn_persist"
    fi
    if [[ -n "$SCALE_TABLE" ]]; then
        SCALE_HANDLES=()
        START_TIME=$(date +%s%N)
        for i in $(seq 1 200); do
            # Use 198.51.100.0/24 (TEST-NET-2, RFC 5737) — won't route anywhere real
            FAKE_IP="198.51.100.$((i % 256))"
            if [[ $i -gt 255 ]]; then
                FAKE_IP="198.51.101.$((i - 256))"
            fi
            nft insert rule inet "$SCALE_TABLE" output ip daddr "$FAKE_IP" counter accept 2>/dev/null || true
            handle=$(nft -a list chain inet "$SCALE_TABLE" output 2>/dev/null | grep "ip daddr $FAKE_IP" | grep -oP 'handle \K\d+' | head -1)
            if [[ -n "$handle" ]]; then
                SCALE_HANDLES+=("$SCALE_TABLE:output:$handle")
            fi
        done
        END_TIME=$(date +%s%N)
        ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
        info "  Added 200 rules to $SCALE_TABLE in ${ELAPSED_MS}ms"

        # Test a ping to see if nft performance is affected
        if $VPN_UP; then
            # Ping through tunnel (should still work quickly)
            PING_START=$(date +%s%N)
            do_ping "$TEST_IP"
            PING_END=$(date +%s%N)
            PING_MS=$(( (PING_END - PING_START) / 1000000 ))
            info "  Ping through tunnel with 200 extra rules: ${PING_MS}ms total"
        fi

        # Count total rules in the table
        RULE_COUNT=$(nft list chain inet "$SCALE_TABLE" output 2>/dev/null | wc -l)
        info "  Total lines in $SCALE_TABLE output chain: $RULE_COUNT"

        # Cleanup scale test rules
        for entry in "${SCALE_HANDLES[@]}"; do
            IFS=':' read -r t c h <<< "$entry"
            nft delete rule inet "$t" "$c" handle "$h" 2>/dev/null || true
        done
        info "  Cleaned up 200 test rules"
        record "T17: Scale test (200 rules)" "PASS (${ELAPSED_MS}ms add, ${RULE_COUNT} total lines)"
    fi
fi

# -------------------------------------------------------------------------
# Test 18: Manifest server count (how many IPs would we allowlist?)
# -------------------------------------------------------------------------
subhdr "Test 18: Manifest server count"
API_JSON=$(curl -s --max-time 10 "https://airvpn.org/api/status/" 2>/dev/null || true)
if [[ -n "$API_JSON" ]]; then
    SERVER_COUNT=$(echo "$API_JSON" | python3 -c "
import sys, json
data = json.load(sys.stdin)
servers = data.get('servers', [])
ips = set()
for s in servers:
    for i in range(1, 5):
        ip = s.get(f'ip_v4_in{i}', '')
        if ip:
            ips.add(ip)
print(f'{len(servers)} servers, {len(ips)} unique IPv4 entry IPs')
" 2>/dev/null || echo "parse error")
    info "  AirVPN: $SERVER_COUNT"
    record "T18: Server count" "$SERVER_COUNT"
else
    warn "  Could not reach API"
    record "T18: Server count" "SKIP (API unreachable)"
fi

# -------------------------------------------------------------------------
# Test 19: T15 fix — add endpoint to persistent lock, retry ping
# -------------------------------------------------------------------------
if $VPN_UP && $PERSIST_ACTIVE; then
    CONNECTED_ENDPOINT=$(ip -4 route show table main | awk -v gw="$PHYS_GW" \
        '$0 ~ "via "gw && $1 !~ /\// && $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $1; exit}')
    if [[ -n "$CONNECTED_ENDPOINT" ]]; then
        subhdr "Test 19: Ping endpoint $CONNECTED_ENDPOINT with persistent allowlist added"
        info "  T15 failed because endpoint not in persistent lock. Adding it now."
        add_allowlist_entry "airvpn_persist" "$CONNECTED_ENDPOINT" && info "  Added $CONNECTED_ENDPOINT to persistent allowlist" || true
        if do_ping "$CONNECTED_ENDPOINT"; then
            record "T19: Endpoint + persist allowlist" "PASS"
        else
            record "T19: Endpoint + persist allowlist" "FAIL"
        fi
        remove_allowlist_entries
    fi
fi

# -------------------------------------------------------------------------
# Test 20: Batch nft performance — add 1024 rules via nft -f (atomic)
# -------------------------------------------------------------------------
subhdr "Test 20: Batch nft -f performance (1024 rules)"
BATCH_TABLE=""
if $SESSION_ACTIVE; then
    BATCH_TABLE="airvpn_lock"
elif $PERSIST_ACTIVE; then
    BATCH_TABLE="airvpn_persist"
fi
if [[ -n "$BATCH_TABLE" ]]; then
    # Generate 1024 rules using TEST-NET ranges (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
    # Plus some from 100.64.0.0/10 (shared address space, won't route)
    BATCH_FILE=$(mktemp /tmp/nft-batch-XXXXXX.nft)
    for i in $(seq 0 1023); do
        OCTET3=$(( i / 256 ))
        OCTET4=$(( i % 256 ))
        echo "insert rule inet $BATCH_TABLE output ip daddr 100.64.${OCTET3}.${OCTET4} counter accept comment \"ping_test_batch\"" >> "$BATCH_FILE"
    done

    START_TIME=$(date +%s%N)
    if nft -f "$BATCH_FILE" 2>/dev/null; then
        END_TIME=$(date +%s%N)
        ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
        RULE_COUNT=$(nft list chain inet "$BATCH_TABLE" output 2>/dev/null | wc -l)
        info "  Added 1024 rules to $BATCH_TABLE via nft -f in ${ELAPSED_MS}ms"
        info "  Total lines in output chain: $RULE_COUNT"

        # Test ping performance with 1024 extra rules
        if $VPN_UP; then
            PING_START=$(date +%s%N)
            do_ping "$TEST_IP"
            PING_END=$(date +%s%N)
            PING_MS=$(( (PING_END - PING_START) / 1000000 ))
            info "  Ping with 1024 extra rules: ${PING_MS}ms"
        else
            # Disconnected: test with a hole for the test IP
            add_icmp_hole "airvpn_persist" "$TEST_IP" 2>/dev/null || true
            PING_START=$(date +%s%N)
            do_ping "$TEST_IP"
            PING_END=$(date +%s%N)
            PING_MS=$(( (PING_END - PING_START) / 1000000 ))
            info "  Ping with 1024 extra rules + hole: ${PING_MS}ms"
            remove_icmp_holes
        fi

        # Cleanup: flush all batch rules by comment
        # Can't easily track handles for 1024 rules, so use a flush+reload approach
        # Just remove by matching comment
        nft -a list chain inet "$BATCH_TABLE" output 2>/dev/null | grep "ping_test_batch" | grep -oP 'handle \K\d+' | while read -r h; do
            nft delete rule inet "$BATCH_TABLE" output handle "$h" 2>/dev/null || true
        done
        info "  Cleaned up 1024 batch rules"
        record "T20: Batch nft -f (1024 rules)" "PASS (${ELAPSED_MS}ms add, ping ${PING_MS}ms)"
    else
        END_TIME=$(date +%s%N)
        ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
        record "T20: Batch nft -f (1024 rules)" "FAIL (nft -f failed after ${ELAPSED_MS}ms)"
    fi
    rm -f "$BATCH_FILE"
fi

# -------------------------------------------------------------------------
# Test 21: Batch ip route performance — add 256 /32 routes via ip -batch
# -------------------------------------------------------------------------
if $VPN_UP; then
    subhdr "Test 21: Batch ip route performance (256 /32 routes)"
    ROUTE_BATCH_FILE=$(mktemp /tmp/ip-batch-XXXXXX)
    for i in $(seq 0 255); do
        echo "route add 100.64.0.${i}/32 via $PHYS_GW dev $PHYS_DEV" >> "$ROUTE_BATCH_FILE"
    done

    START_TIME=$(date +%s%N)
    ip -batch "$ROUTE_BATCH_FILE" 2>/dev/null
    END_TIME=$(date +%s%N)
    ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
    ROUTE_COUNT=$(ip -4 route show | grep -c "100.64.0." || true)
    info "  Added 256 routes via ip -batch in ${ELAPSED_MS}ms ($ROUTE_COUNT visible)"

    # Cleanup routes
    ROUTE_DEL_FILE=$(mktemp /tmp/ip-batch-del-XXXXXX)
    for i in $(seq 0 255); do
        echo "route del 100.64.0.${i}/32 via $PHYS_GW dev $PHYS_DEV" >> "$ROUTE_DEL_FILE"
    done
    ip -batch "$ROUTE_DEL_FILE" 2>/dev/null
    info "  Cleaned up 256 routes"
    rm -f "$ROUTE_BATCH_FILE" "$ROUTE_DEL_FILE"
    record "T21: Batch ip route (256 routes)" "PASS (${ELAPSED_MS}ms)"
else
    info "Skipping T21 (not connected — no need for host routes)"
    record "T21: Batch ip route (256 routes)" "SKIP (disconnected)"
fi

# -------------------------------------------------------------------------
# Test 22: Full 1024 route batch (realistic scale)
# -------------------------------------------------------------------------
if $VPN_UP; then
    subhdr "Test 22: Full batch ip route (1024 /32 routes)"
    ROUTE_BATCH_FILE=$(mktemp /tmp/ip-batch-XXXXXX)
    for i in $(seq 0 1023); do
        OCTET3=$(( i / 256 ))
        OCTET4=$(( i % 256 ))
        echo "route add 100.64.${OCTET3}.${OCTET4}/32 via $PHYS_GW dev $PHYS_DEV" >> "$ROUTE_BATCH_FILE"
    done

    START_TIME=$(date +%s%N)
    ip -batch "$ROUTE_BATCH_FILE" 2>/dev/null
    END_TIME=$(date +%s%N)
    ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
    ROUTE_COUNT=$(ip -4 route show | grep -c "100.64." || true)
    info "  Added 1024 routes via ip -batch in ${ELAPSED_MS}ms ($ROUTE_COUNT visible)"

    # Cleanup
    ROUTE_DEL_FILE=$(mktemp /tmp/ip-batch-del-XXXXXX)
    for i in $(seq 0 1023); do
        OCTET3=$(( i / 256 ))
        OCTET4=$(( i % 256 ))
        echo "route del 100.64.${OCTET3}.${OCTET4}/32 via $PHYS_GW dev $PHYS_DEV" >> "$ROUTE_DEL_FILE"
    done
    ip -batch "$ROUTE_DEL_FILE" 2>/dev/null
    info "  Cleaned up 1024 routes"
    rm -f "$ROUTE_BATCH_FILE" "$ROUTE_DEL_FILE"
    record "T22: Batch ip route (1024 routes)" "PASS (${ELAPSED_MS}ms)"
else
    info "Skipping T22 (not connected)"
    record "T22: Batch ip route (1024 routes)" "SKIP (disconnected)"
fi

# -------------------------------------------------------------------------
# Test 23: End-to-end — host route + allowlist in both locks for a
#   non-connected server, then actually measure ping RTT
# -------------------------------------------------------------------------
subhdr "Test 23: End-to-end ping with RTT measurement"
if $VPN_UP; then
    add_host_route "$TEST_IP" "$PHYS_GW" "$PHYS_DEV" || true
fi
if $SESSION_ACTIVE; then
    add_allowlist_entry "airvpn_lock" "$TEST_IP" || true
fi
if $PERSIST_ACTIVE; then
    add_allowlist_entry "airvpn_persist" "$TEST_IP" || true
fi
# Do 3 pings and show RTT
PING_OUTPUT=$(ping -c 3 -W 3 "$TEST_IP" 2>&1 || true)
RTT_LINE=$(echo "$PING_OUTPUT" | grep "rtt\|round-trip" || echo "no RTT data")
LOSS_LINE=$(echo "$PING_OUTPUT" | grep "packet loss" || echo "no loss data")
echo "  $LOSS_LINE"
echo "  $RTT_LINE"
if echo "$PING_OUTPUT" | grep -q "0% packet loss"; then
    record "T23: E2E ping with RTT" "PASS ($RTT_LINE)"
elif echo "$PING_OUTPUT" | grep -q "packet loss"; then
    record "T23: E2E ping with RTT" "PARTIAL ($LOSS_LINE)"
else
    record "T23: E2E ping with RTT" "FAIL"
fi
remove_allowlist_entries
remove_host_route

# =========================================================================
# Summary
# =========================================================================
header "Results Summary"
echo
printf "  %-55s %s\n" "TEST" "RESULT"
printf "  %-55s %s\n" "-------------------------------------------------------" "------"

# Collect keys and sort them
mapfile -t SORTED_KEYS < <(printf '%s\n' "${!RESULTS[@]}" | sort)

for key in "${SORTED_KEYS[@]}"; do
    result="${RESULTS[$key]:-???}"
    if [[ "$result" == "PASS" ]]; then
        printf "  %-55s ${GREEN}%s${NC}\n" "$key" "$result"
    elif [[ "$result" == "FAIL" ]]; then
        printf "  %-55s ${RED}%s${NC}\n" "$key" "$result"
    else
        printf "  %-55s ${YELLOW}%s${NC}\n" "$key" "$result"
    fi
done

echo
header "What This Means For The Background Pinger"
echo

# Helper to safely get result
r() { echo "${RESULTS[$1]:-NONE}"; }

if $VPN_UP; then
    echo "  WHILE CONNECTED (session=${SESSION_ACTIVE}, persist=${PERSIST_ACTIVE}):"
    echo
    [[ "$(r 'T1: Plain ping')" == "PASS" ]] && \
        echo "    [T1]  Plain ping through tunnel: works" || \
        echo "    [T1]  Plain ping through tunnel: BROKEN"
    [[ "$(r 'T2: Host route only')" == "PASS" ]] && \
        echo "    [T2]  Host route alone bypasses tunnel + firewall" || \
        echo "    [T2]  Host route alone: firewall blocks (need holes)"
    [[ "$(r 'T3: Host route + ICMP holes (both locks)')" == "PASS" ]] && \
        echo "    [T3]  Host route + ICMP holes in BOTH locks: works" || true
    [[ "$(r 'T4: Host route + session hole only')" != "NONE" ]] && {
        [[ "$(r 'T4: Host route + session hole only')" == "PASS" ]] && \
            echo "    [T4]  Session hole only: sufficient" || \
            echo "    [T4]  Session hole only: NOT sufficient (persistent also blocks)"
    }
    [[ "$(r 'T5: Host route + persistent hole only')" != "NONE" ]] && {
        [[ "$(r 'T5: Host route + persistent hole only')" == "PASS" ]] && \
            echo "    [T5]  Persistent hole only: sufficient" || \
            echo "    [T5]  Persistent hole only: NOT sufficient (session also blocks)"
    }
    [[ "$(r 'T6: Host route + session allowlist + persist hole')" == "PASS" ]] && \
        echo "    [T6]  Eddie approach (session allowlist + persist hole): works" || true
    [[ "$(r 'T7: Host route + allowlist both locks')" == "PASS" ]] && \
        echo "    [T7]  Allowlist in BOTH locks: works" || true
    [[ "$(r 'T8: Allowlist only, no route (through tunnel)')" == "PASS" ]] && \
        echo "    [T8]  Allowlist without host route: goes through tunnel (routing unaffected)" || true
    [[ "$(r 'T15: Ping connected endpoint (has route+allowlist)')" != "NONE" ]] && {
        [[ "$(r 'T15: Ping connected endpoint (has route+allowlist)')" == "PASS" ]] && \
            echo "    [T15] Connected server endpoint (already routed+allowed): works" || \
            echo "    [T15] Connected server endpoint: BROKEN"
    }
    [[ "$(r 'T16: Host route + allowlist in both (full solution)')" != "NONE" ]] && {
        [[ "$(r 'T16: Host route + allowlist in both (full solution)')" == "PASS" ]] && \
            echo "    [T16] Full solution (route + allowlist both locks): works" || \
            echo "    [T16] Full solution: BROKEN"
    }
    [[ "$(r 'T17: Scale test (200 rules)')" != "NONE" ]] && \
        echo "    [T17] Scale (200 individual inserts): $(r 'T17: Scale test (200 rules)')"
    [[ "$(r 'T18: Server count')" != "NONE" ]] && \
        echo "    [T18] Manifest: $(r 'T18: Server count')"
    [[ "$(r 'T19: Endpoint + persist allowlist')" != "NONE" ]] && {
        [[ "$(r 'T19: Endpoint + persist allowlist')" == "PASS" ]] && \
            echo "    [T19] T15 fix (endpoint + persist allowlist): works — confirms both locks needed" || \
            echo "    [T19] T15 fix: still broken"
    }
    [[ "$(r 'T20: Batch nft -f (1024 rules)')" != "NONE" ]] && \
        echo "    [T20] Batch nft -f (1024 rules): $(r 'T20: Batch nft -f (1024 rules)')"
    [[ "$(r 'T21: Batch ip route (256 routes)')" != "NONE" ]] && \
        echo "    [T21] Batch ip route (256): $(r 'T21: Batch ip route (256 routes)')"
    [[ "$(r 'T22: Batch ip route (1024 routes)')" != "NONE" ]] && \
        echo "    [T22] Batch ip route (1024): $(r 'T22: Batch ip route (1024 routes)')"
    [[ "$(r 'T23: E2E ping with RTT')" != "NONE" ]] && \
        echo "    [T23] E2E ping: $(r 'T23: E2E ping with RTT')"
    echo
    echo "  CONCLUSION (connected):"
    if [[ "$(r 'T2: Host route only')" == "PASS" ]]; then
        echo "    -> Host routes are all you need. No firewall changes required."
    elif [[ "$(r 'T7: Host route + allowlist both locks')" == "PASS" ]]; then
        echo "    -> Need: host routes + allowlist entries in ALL active locks."
        echo "       Allowlist = 'ip daddr <server-ip> accept' (all protocols)."
        echo "       This is what Eddie does for reconnection readiness."
    elif [[ "$(r 'T3: Host route + ICMP holes (both locks)')" == "PASS" ]]; then
        echo "    -> Need: host routes + ICMP holes in ALL active locks."
    else
        echo "    -> No tested approach worked. Investigate further."
    fi
fi

if ! $VPN_UP; then
    echo "  WHILE DISCONNECTED (session=${SESSION_ACTIVE}, persist=${PERSIST_ACTIVE}):"
    echo
    [[ "$(r 'T1: Plain ping')" != "NONE" ]] && {
        [[ "$(r 'T1: Plain ping')" == "PASS" ]] && \
            echo "    [T1]  Plain ping: works (no firewall blocking)" || \
            echo "    [T1]  Plain ping: BLOCKED by firewall"
    }
    [[ "$(r 'T9: Disconnected, no locks')" != "NONE" ]] && {
        [[ "$(r 'T9: Disconnected, no locks')" == "PASS" ]] && \
            echo "    [T9]  No locks: pings work freely" || \
            echo "    [T9]  No locks: pings FAIL (unexpected!)"
    }
    [[ "$(r 'T10: Disconnected + persist lock, plain ping')" != "NONE" ]] && {
        [[ "$(r 'T10: Disconnected + persist lock, plain ping')" == "PASS" ]] && \
            echo "    [T10] Persistent lock, plain ping: works (not blocked)" || \
            echo "    [T10] Persistent lock, plain ping: BLOCKED"
    }
    [[ "$(r 'T11: Disconnected + persist lock + ICMP hole')" != "NONE" ]] && {
        [[ "$(r 'T11: Disconnected + persist lock + ICMP hole')" == "PASS" ]] && \
            echo "    [T11] Persistent lock + ICMP hole: fixes it" || \
            echo "    [T11] Persistent lock + ICMP hole: still blocked"
    }
    [[ "$(r 'T12: Disconnected + persist lock + allowlist')" != "NONE" ]] && {
        [[ "$(r 'T12: Disconnected + persist lock + allowlist')" == "PASS" ]] && \
            echo "    [T12] Persistent lock + allowlist: fixes it" || \
            echo "    [T12] Persistent lock + allowlist: still blocked"
    }
    [[ "$(r 'T13: Disconnected + both locks, plain ping')" != "NONE" ]] && {
        [[ "$(r 'T13: Disconnected + both locks, plain ping')" == "PASS" ]] && \
            echo "    [T13] Both locks, plain ping: works" || \
            echo "    [T13] Both locks, plain ping: BLOCKED"
    }
    [[ "$(r 'T14: Disconnected + both locks + holes')" != "NONE" ]] && {
        [[ "$(r 'T14: Disconnected + both locks + holes')" == "PASS" ]] && \
            echo "    [T14] Both locks + holes: fixes it" || \
            echo "    [T14] Both locks + holes: still blocked"
    }
    echo
    echo "  CONCLUSION (disconnected):"
    if [[ "$(r 'T1: Plain ping')" == "PASS" ]]; then
        echo "    -> No firewall blocking pings. Background pinger works out of the box."
    elif [[ "$(r 'T11: Disconnected + persist lock + ICMP hole')" == "PASS" ]]; then
        echo "    -> Persistent lock blocks pings. Need ICMP holes (or allowlist) in persistent lock."
    elif [[ "$(r 'T12: Disconnected + persist lock + allowlist')" == "PASS" ]]; then
        echo "    -> Persistent lock blocks pings. Allowlist entries fix it."
    else
        echo "    -> Investigate further."
    fi
fi
echo
