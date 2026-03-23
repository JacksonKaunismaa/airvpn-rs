#!/usr/bin/env bash
# dns-snitch.sh — Find which process is trying to reach public DNS resolvers
#
# Polls ss(8) rapidly to catch ephemeral sockets to known public DNS IPs.
# Must run as root to see process info for all users.
#
# Usage:
#   sudo ./dns-snitch.sh              # Monitor indefinitely
#   sudo ./dns-snitch.sh --duration 60  # Monitor for 60 seconds
#   sudo ./dns-snitch.sh --kill        # Also kill offending sockets

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

DURATION=0
KILL_MODE=0
POLL_MS=100  # poll interval in ms

while [[ $# -gt 0 ]]; do
    case $1 in
        --duration) DURATION="$2"; shift 2 ;;
        --kill) KILL_MODE=1; shift ;;
        --poll-ms) POLL_MS="$2"; shift 2 ;;
        --help|-h)
            cat <<'EOF'
dns-snitch.sh — Find processes reaching out to public DNS resolvers

Usage:
  sudo ./dns-snitch.sh [--duration SECS] [--kill] [--poll-ms MS]

Options:
  --duration SECS  Run for N seconds (default: indefinite)
  --kill           Destroy offending sockets via ss --kill
  --poll-ms MS     Poll interval in milliseconds (default: 100)
EOF
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: Must run as root to see all process info${NC}" >&2
    exit 2
fi

# Known public DNS resolver IPs
DNS_IPS=(
    "8.8.8.8" "8.8.4.4"           # Google
    "1.1.1.1" "1.0.0.1"           # Cloudflare
    "9.9.9.9" "149.112.112.112"   # Quad9
    "208.67.222.222" "208.67.220.220"  # OpenDNS
)

# Build ss filter: ( dst 8.8.8.8 or dst 8.8.4.4 or ... )
SS_FILTER="( $(printf 'dst %s or ' "${DNS_IPS[@]}" | sed 's/ or $//' ) )"

# Track already-seen sockets to avoid spam
declare -A SEEN

echo -e "${GREEN}dns-snitch: watching for connections to public DNS resolvers${NC}"
echo -e "${YELLOW}IPs: ${DNS_IPS[*]}${NC}"
echo -e "${YELLOW}Poll interval: ${POLL_MS}ms${NC}"
[[ $KILL_MODE -eq 1 ]] && echo -e "${RED}Kill mode: ON — offending sockets will be destroyed${NC}"
echo ""

POLL_SEC=$(awk "BEGIN {printf \"%.3f\", $POLL_MS / 1000}")
START=$(date +%s)

while true; do
    # Check duration
    if [[ $DURATION -gt 0 ]]; then
        NOW=$(date +%s)
        (( NOW - START >= DURATION )) && break
    fi

    # Poll all TCP/UDP sockets to public DNS IPs, with process info
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        # Skip header
        [[ "$line" == Netid* ]] && continue

        # Dedup by local+remote+process
        KEY=$(echo "$line" | awk '{print $5, $6, $NF}')
        [[ -n "${SEEN[$KEY]:-}" ]] && continue
        SEEN[$KEY]=1

        TS=$(date '+%H:%M:%S.%3N')
        echo -e "${RED}[${TS}] SNITCH: ${line}${NC}"

        if [[ $KILL_MODE -eq 1 ]]; then
            # Extract protocol and addresses for ss --kill
            PROTO=$(echo "$line" | awk '{print $1}')
            SRC=$(echo "$line" | awk '{print $5}')
            DST=$(echo "$line" | awk '{print $6}')
            if [[ "$PROTO" == "tcp" ]]; then
                ss --kill state all src "$SRC" dst "$DST" 2>/dev/null && \
                    echo -e "${YELLOW}  → Socket killed${NC}" || true
            fi
        fi
    done < <(ss -tunap state all "$SS_FILTER" 2>/dev/null || true)

    sleep "$POLL_SEC"
done

echo -e "${GREEN}dns-snitch: done${NC}"
