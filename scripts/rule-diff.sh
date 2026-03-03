#!/usr/bin/env bash
# rule-diff.sh — Compare airvpn-rs nftables rules against Eddie reference
#
# Dumps current nftables rules and compares structure against Eddie's expected
# ruleset. Reports missing rules, extra rules, and policy mismatches.
#
# Usage:
#   sudo ./rule-diff.sh [--verbose] [--json]
#
# Exit codes:
#   0 = Rules match Eddie spec
#   1 = Differences found
#   2 = Setup error

set -eo pipefail

TABLE_NAME="airvpn_lock"
VERBOSE=0
JSON_OUTPUT=0

# ANSI colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# -----------------------------------------------------------------------------
# Parse args
# -----------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case $1 in
        --verbose|-v)
            VERBOSE=1
            shift
            ;;
        --json)
            JSON_OUTPUT=1
            shift
            ;;
        --help|-h)
            head -20 "$0" | tail -15
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 2
            ;;
    esac
done

# -----------------------------------------------------------------------------
# Preflight
# -----------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: Must run as root${NC}" >&2
    exit 2
fi

if ! command -v nft &>/dev/null; then
    echo -e "${RED}Error: nft not found${NC}" >&2
    exit 2
fi

# -----------------------------------------------------------------------------
# Check if table exists
# -----------------------------------------------------------------------------
if ! nft list table inet "$TABLE_NAME" &>/dev/null; then
    echo -e "${RED}Error: Table 'inet $TABLE_NAME' not found${NC}" >&2
    echo "Is airvpn-rs netlock active?" >&2
    exit 2
fi

# -----------------------------------------------------------------------------
# Eddie reference rules (from NetworkLockNftables.cs analysis)
# These are the REQUIRED structural elements
# -----------------------------------------------------------------------------
declare -A EDDIE_INPUT_REQUIRED=(
    ["loopback"]='iifname "lo".*accept'
    ["ipv6_antispoof"]='iifname != "lo" ip6 saddr ::1.*(drop|reject)'
    ["conntrack"]='ct state.*(related,established|established,related).*accept'
    ["rh0_drop"]='rt type 0.*drop'
    ["ndp_router_advert"]='icmpv6 type nd-router-advert.*hoplimit 255.*accept'
    ["ndp_neighbor_solicit"]='icmpv6 type nd-neighbor-solicit.*hoplimit 255.*accept'
    ["ndp_neighbor_advert"]='icmpv6 type nd-neighbor-advert.*hoplimit 255.*accept'
    ["ndp_redirect"]='icmpv6 type nd-redirect.*hoplimit 255.*accept'
    ["final_drop"]='drop.*comment.*latest_rule'
)

declare -A EDDIE_OUTPUT_REQUIRED=(
    ["loopback"]='oifname "lo".*accept'
    ["rh0_drop"]='rt type 0.*drop'
    ["final_drop"]='drop.*comment.*latest_rule'
)

declare -A EDDIE_FORWARD_REQUIRED=(
    ["rh0_drop"]='rt type 0.*drop'
    ["final_drop"]='drop.*comment.*latest_rule'
)

# Optional rules (depend on config)
declare -A EDDIE_OPTIONAL=(
    ["dhcp_v4_in"]='ip saddr 255\.255\.255\.255.*accept'
    ["dhcp_v4_out"]='ip daddr 255\.255\.255\.255.*accept'
    ["dhcp_v6"]='(ff02::1:2|ff05::1:3).*accept'
    ["lan_192"]='192\.168\.0\.0/16.*192\.168\.0\.0/16.*accept'
    ["lan_10"]='10\.0\.0\.0/8.*10\.0\.0\.0/8.*accept'
    ["lan_172"]='172\.16\.0\.0/12.*172\.16\.0\.0/12.*accept'
    ["ping_request"]='icmp type echo-request.*accept'
    ["ping_reply"]='icmp type echo-reply.*accept'
    ["nat64"]='64:ff9b::/96.*accept'
)

# -----------------------------------------------------------------------------
# Dump current rules
# -----------------------------------------------------------------------------
RULES=$(nft list table inet "$TABLE_NAME" 2>/dev/null)

# Extract chain contents
extract_chain() {
    local chain="$1"
    echo "$RULES" | sed -n "/chain $chain {/,/^[[:space:]]*}/p"
}

INPUT_RULES=$(extract_chain "input")
OUTPUT_RULES=$(extract_chain "output")
FORWARD_RULES=$(extract_chain "forward")

# -----------------------------------------------------------------------------
# Check policy
# -----------------------------------------------------------------------------
ERRORS=()
WARNINGS=()

check_policy() {
    local chain_rules="$1"
    local chain_name="$2"

    if ! echo "$chain_rules" | grep -q "policy drop"; then
        ERRORS+=("$chain_name: Policy is NOT 'drop' (Eddie requires drop)")
    fi
}

check_policy "$INPUT_RULES" "INPUT"
check_policy "$OUTPUT_RULES" "OUTPUT"
check_policy "$FORWARD_RULES" "FORWARD"

# -----------------------------------------------------------------------------
# Check required rules
# -----------------------------------------------------------------------------
check_required() {
    local chain_rules="$1"
    local chain_name="$2"
    local -n required_rules=$3

    for rule_name in "${!required_rules[@]}"; do
        pattern="${required_rules[$rule_name]}"
        if ! echo "$chain_rules" | grep -qE "$pattern"; then
            ERRORS+=("$chain_name: Missing required rule '$rule_name' (pattern: $pattern)")
        elif [[ $VERBOSE -eq 1 ]]; then
            echo -e "${GREEN}[OK] $chain_name.$rule_name${NC}"
        fi
    done
}

check_required "$INPUT_RULES" "INPUT" EDDIE_INPUT_REQUIRED
check_required "$OUTPUT_RULES" "OUTPUT" EDDIE_OUTPUT_REQUIRED
check_required "$FORWARD_RULES" "FORWARD" EDDIE_FORWARD_REQUIRED

# -----------------------------------------------------------------------------
# Check priority (Eddie uses priority -300 for guaranteed first evaluation)
# -----------------------------------------------------------------------------
check_priority() {
    local chain_rules="$1"
    local chain_name="$2"

    # Extract priority value.
    # nft may output "priority -300" or "priority filter - 300" (named base + offset).
    # Handle both formats. (grep can fail with no match; || true prevents pipefail exit)
    local prio_line
    prio_line=$(echo "$chain_rules" | grep -o 'priority [^;]*') || true

    priority=""
    if [[ -n "$prio_line" ]]; then
        if echo "$prio_line" | grep -qP 'priority\s+-?\d+$'; then
            # Simple format: "priority -300"
            priority=$(echo "$prio_line" | grep -oP '-?\d+') || true
        elif echo "$prio_line" | grep -qP 'priority\s+\w+\s*[+-]\s*\d+'; then
            # Named format: "priority filter - 300" → compute base + offset
            local base_name offset_sign offset_val
            base_name=$(echo "$prio_line" | grep -oP 'priority\s+\K\w+') || true
            offset_sign=$(echo "$prio_line" | grep -oP '\w+\s+\K[+-]') || true
            offset_val=$(echo "$prio_line" | grep -oP '[+-]\s*\K\d+') || true
            # Common named priorities: filter=0, raw=-300, mangle=-150
            local base_val=0
            case "$base_name" in
                filter) base_val=0 ;;
                raw) base_val=-300 ;;
                mangle) base_val=-150 ;;
                *) base_val=0 ;;
            esac
            if [[ "$offset_sign" == "-" ]]; then
                priority=$((base_val - offset_val))
            else
                priority=$((base_val + offset_val))
            fi
        elif echo "$prio_line" | grep -qP 'priority\s+\w+$'; then
            # Just a named priority: "priority filter" = 0, "priority raw" = -300
            local base_name
            base_name=$(echo "$prio_line" | grep -oP 'priority\s+\K\w+') || true
            case "$base_name" in
                filter) priority=0 ;;
                raw) priority=-300 ;;
                mangle) priority=-150 ;;
                *) priority="" ;;
            esac
        fi
    fi

    if [[ -z "$priority" ]]; then
        WARNINGS+=("$chain_name: Could not determine priority")
    elif [[ "$priority" -gt -200 ]]; then
        WARNINGS+=("$chain_name: Priority $priority may not run before other tables (Eddie uses -300)")
    elif [[ $VERBOSE -eq 1 ]]; then
        echo -e "${GREEN}[OK] $chain_name priority: $priority${NC}"
    fi
}

check_priority "$INPUT_RULES" "INPUT"
check_priority "$OUTPUT_RULES" "OUTPUT"
check_priority "$FORWARD_RULES" "FORWARD"

# -----------------------------------------------------------------------------
# Check for allowlisted IPs (VPN endpoint should be in OUTPUT)
# -----------------------------------------------------------------------------
if ! echo "$OUTPUT_RULES" | grep -qE 'ip6? daddr.*accept.*comment.*eddie_ip'; then
    WARNINGS+=("OUTPUT: No allowlisted IPs found (VPN endpoint should be allowlisted)")
fi

# Count allowlisted IPs
ALLOWLIST_COUNT=$(echo "$OUTPUT_RULES" | grep -cE 'comment.*eddie_ip') || ALLOWLIST_COUNT=0
if [[ $VERBOSE -eq 1 ]]; then
    echo -e "${CYAN}Allowlisted IPs in OUTPUT: $ALLOWLIST_COUNT${NC}"
fi

# -----------------------------------------------------------------------------
# Check for interface allowlist (wg/avpn interface)
# -----------------------------------------------------------------------------
WG_IFACE_RULES=$(echo "$RULES" | grep -E '(iifname|oifname).*"(wg|avpn)' || true)
if [[ -n "$WG_IFACE_RULES" && $VERBOSE -eq 1 ]]; then
    echo -e "${CYAN}WireGuard interface rules found${NC}"
fi

# -----------------------------------------------------------------------------
# Output results
# -----------------------------------------------------------------------------
if [[ $JSON_OUTPUT -eq 1 ]]; then
    # JSON output for automation
    echo "{"
    echo "  \"table\": \"$TABLE_NAME\","
    echo "  \"errors\": ["
    for i in "${!ERRORS[@]}"; do
        echo -n "    \"${ERRORS[$i]}\""
        [[ $i -lt $((${#ERRORS[@]} - 1)) ]] && echo "," || echo ""
    done
    echo "  ],"
    echo "  \"warnings\": ["
    for i in "${!WARNINGS[@]}"; do
        echo -n "    \"${WARNINGS[$i]}\""
        [[ $i -lt $((${#WARNINGS[@]} - 1)) ]] && echo "," || echo ""
    done
    echo "  ],"
    echo "  \"allowlisted_ips\": $ALLOWLIST_COUNT"
    echo "}"
else
    # Human-readable output
    echo ""
    echo "=== Rule Diff Report ==="
    echo ""

    if [[ ${#ERRORS[@]} -gt 0 ]]; then
        echo -e "${RED}ERRORS (Eddie compliance failures):${NC}"
        for err in "${ERRORS[@]}"; do
            echo -e "  ${RED}✗${NC} $err"
        done
        echo ""
    fi

    if [[ ${#WARNINGS[@]} -gt 0 ]]; then
        echo -e "${YELLOW}WARNINGS:${NC}"
        for warn in "${WARNINGS[@]}"; do
            echo -e "  ${YELLOW}!${NC} $warn"
        done
        echo ""
    fi

    if [[ ${#ERRORS[@]} -eq 0 && ${#WARNINGS[@]} -eq 0 ]]; then
        echo -e "${GREEN}All Eddie-required rules present and correct.${NC}"
    fi

    echo ""
    echo "Summary: ${#ERRORS[@]} errors, ${#WARNINGS[@]} warnings, $ALLOWLIST_COUNT allowlisted IPs"
fi

# Exit code
if [[ ${#ERRORS[@]} -gt 0 ]]; then
    exit 1
else
    exit 0
fi
