#!/usr/bin/env bash
# Shared seed helpers. Runs on edge (the controller); services reached by alias over the VPC.
# /etc/hosts on every host resolves gitea/gitlab/minio/vault/atlantis/registry/... to private IPs.
set -uo pipefail
OPKEY=/opt/minilab2/op.key
SSHO="ssh -i $OPKEY -o StrictHostKeyChecking=no -o ConnectTimeout=15"

# profile (passed through from the orchestrator); seed can branch on it later
PROFILE="${PROFILE:-realistic}"

# lab seed creds (match config/group_vars/all.yml)
ADMIN_USER="svc-admin"
ADMIN_PASS="Min2lab-Adm!n-2026"
MINIO_USER="minioadmin"
MINIO_PASS="Min2lab-M!nio-2026"

GITEA="http://gitea:3000"
GITLAB="http://gitlab"

# service -> host that runs it (for `on <host>` SSH calls)
HOST_GITEA=gitea
HOST_GITLAB=gitlab
HOST_MINIO=backend
HOST_VAULT=backend
HOST_ATLANTIS=atlantis
HOST_TFEXEC=atlantis
HOST_REGISTRY=registry
HOST_K8S=k8s
HOST_SIEM=siem

say(){ printf '\033[1;35m[seed]\033[0m %s\n' "$*"; }
on(){ host="$1"; shift; $SSHO root@"$host" "$@"; }   # run a command on a lab host via op key

# ---- scenario toggle + flags ----------------------------------------------
ENABLED_FILE=/opt/minilab2/enabled_scenarios
scenario_on(){ grep -qxF "$1" "$ENABLED_FILE" 2>/dev/null; }   # true if scenario <id> is enabled
# deterministic per-scenario flag (documented in SOLUTIONS.md)
flag(){ printf 'MINILAB{%s}' "$1"; }

# gitea API helper (admin basic auth)
gitea_api(){ local m="$1" path="$2"; shift 2; curl -sS -X "$m" -u "$ADMIN_USER:$ADMIN_PASS" \
  -H 'Content-Type: application/json' "$GITEA/api/v1$path" "$@"; }
