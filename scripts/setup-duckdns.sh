#!/usr/bin/env bash
# One-shot DuckDNS setup for a WireGuard endpoint DNS record.
#
# Replaces the AirDNS dependence (see docs/known_divergences.md #17): after
# this, the helper writes <subdomain>.duckdns.org -> current AirVPN exit IP
# on every connect and every 5 min, through DuckDNS's acked API.
#
# Prerequisite (manual, one time): create the subdomain in your DuckDNS
# account at https://www.duckdns.org and have the account token ready.
#
# Usage:  sudo ./scripts/setup-duckdns.sh <subdomain>
# The token is prompted for silently (never lands in argv or shell history).
#
# Client side (after this script succeeds): edit the WireGuard profile's
# Endpoint to <subdomain>.duckdns.org:<port>, re-import into the client app.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $EUID -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

if [[ $# -ne 1 ]]; then
    echo "usage: sudo $0 <duckdns-subdomain>   (e.g. myhost)" >&2
    exit 1
fi

domain="${1%.duckdns.org}"

if [[ ! "$domain" =~ ^[A-Za-z0-9-]+$ ]]; then
    echo "error: '$domain' is not a DuckDNS subdomain (letters, digits, '-')" >&2
    exit 1
fi
# If the subdomain already resolves, it may be serving something else in
# this account (a pager, a web host) — repointing it at the VPN exit would
# break that service. Require explicit confirmation.
if existing=$(getent hosts "$domain.duckdns.org" 2>/dev/null | awk '{print $1; exit}') && [[ -n "$existing" ]]; then
    echo "WARNING: $domain.duckdns.org already resolves to $existing."
    echo "If that record serves something (alerting, web), this script will repoint it."
    read -rp "Repoint it to the VPN exit anyway? [y/N] " confirm
    [[ "$confirm" == y* || "$confirm" == Y* ]] || { echo "aborted"; exit 1; }
fi

# Shield the token from `bash -x` traces for the whole secret-handling span.
{ set +x; } 2>/dev/null
read -rs -p "DuckDNS account token (input hidden): " token
echo
if [[ -z "$token" ]]; then
    echo "error: empty token" >&2
    exit 1
fi

echo "==> building release binary (for the new config options)..."
# Build as the invoking user — root has no rustup toolchain (same pattern
# as install.sh line 31).
sudo -u "${SUDO_USER:-$(logname)}" bash -c "cd '$REPO_DIR' && cargo build --release --quiet"
airvpn_new="$REPO_DIR/target/release/airvpn"

echo "==> writing profile options..."
"$airvpn_new" config set ddns.duckdns_domain "$domain"
printf '%s' "$token" | "$airvpn_new" config set ddns.duckdns_token --stdin
unset token

echo "==> installing + restarting helper (reconnects; writer arms on this connect)..."
"$REPO_DIR/scripts/install.sh"

# test-duckdns with an empty ip= is source-detect: correct (= the exit IP)
# only while the tunnel is up. Disconnected, it would publish the raw home
# WAN IP into public DNS under a memorable name (2026-08-20 security
# review) — so require an active connection; the helper writes the proper
# record on every connect anyway.
if curl -s --unix-socket /run/airvpn-rs/helper.sock http://localhost/status 2>/dev/null \
        | grep -q '"Connected"'; then
    echo "==> live write through the real path..."
    airvpn ddns test-duckdns
else
    echo "==> VPN not connected — SKIPPING the live source-detect test write"
    echo "    (it would publish this machine's raw WAN IP). Connect the VPN;"
    echo "    the helper writes the record automatically on connect."
fi

echo "==> waiting for the helper's own first acked write (up to 60s)..."
for _ in $(seq 12); do
    if journalctl -u airvpn-helper --since -5min -q --no-pager 2>/dev/null \
            | grep -q 'duckdns: .*(acked)'; then
        journalctl -u airvpn-helper --since -5min -q --no-pager | grep 'duckdns:' | tail -2
        break
    fi
    sleep 5
done

echo "==> current record (via system resolver; TTL 60s, may lag a moment):"
getent hosts "$domain.duckdns.org" || echo "   (not resolvable yet — check again in a minute)"

cat <<EOF

Laptop side done. Remote-client side (manual):
  1. In the remote WireGuard profile, set:
       Endpoint = $domain.duckdns.org:<your-forwarded-port>
     (keep keys, MTU, DNS as they are)
  2. Re-import the profile into the client app, then toggle the tunnel.

IMPORTANT: never set an IPv6/AAAA on this DuckDNS subdomain — keep it
A-only so clients with IPv4-only reachability always resolve correctly.

Once the bridge works over the new name, optionally clean up the old airdns
options if any linger:  they are already ignored (removed from the registry).
EOF
