#!/bin/bash
# Test whether we can modify the persistent lock's ping_allow chain.
# Run with: sudo bash scripts/test-ping-allow.sh
set -euo pipefail

echo "=== 1. Current state of ping_allow ==="
nft list chain inet airvpn_persist ping_allow

echo ""
echo "=== 2. Adding test rule via 'nft add rule' ==="
nft add rule inet airvpn_persist ping_allow ip daddr 1.1.1.1 icmp type echo-request counter accept
echo "exit=$?"

echo ""
echo "=== 3. Check if it stuck ==="
nft list chain inet airvpn_persist ping_allow

echo ""
echo "=== 4. Now test via 'nft -f -' (pipe, same as helper uses) ==="
echo 'add rule inet airvpn_persist ping_allow ip daddr 2.2.2.2 icmp type echo-request counter accept' | nft -f -
echo "exit=$?"

echo ""
echo "=== 5. Check both rules ==="
nft list chain inet airvpn_persist ping_allow

echo ""
echo "=== 6. Test flush + add in single transaction (exactly what populate_ping_allow does) ==="
cat <<'EOF' | nft -f -
flush chain inet airvpn_persist ping_allow
add rule inet airvpn_persist ping_allow ip daddr 3.3.3.3 icmp type echo-request counter accept
add rule inet airvpn_persist ping_allow ip daddr 4.4.4.4 icmp type echo-request counter accept
EOF
echo "exit=$?"

echo ""
echo "=== 7. Final state (should have only 3.3.3.3 and 4.4.4.4) ==="
nft list chain inet airvpn_persist ping_allow

echo ""
echo "=== 8. Cleanup — flush back to empty ==="
nft flush chain inet airvpn_persist ping_allow
nft list chain inet airvpn_persist ping_allow
echo "Done."
