#!/usr/bin/env bash
# opssh.sh <host> — operator SSH into any lab host via the vpn-edge jump box (uses the op key).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INFRA="$ROOT/infra/do"; OPKEY="$ROOT/vpn/op.key"
HOST="${1:?usage: lab ssh <hostname>}"
EDGE_IP="$(terraform -chdir="$INFRA" output -raw edge_public_ip)"
if [ "$HOST" = "vpn-edge" ]; then
  exec ssh -i "$OPKEY" -o StrictHostKeyChecking=no root@"$EDGE_IP"
fi
PRIV="$(terraform -chdir="$INFRA" output -json host_private_ips | python3 -c "import sys,json;print(json.load(sys.stdin)['$HOST'])")"
exec ssh -i "$OPKEY" -o StrictHostKeyChecking=no \
  -o ProxyJump="root@${EDGE_IP}" root@"$PRIV"
