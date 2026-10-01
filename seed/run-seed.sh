#!/usr/bin/env bash
# run-seed.sh — populate the realistic org AFTER services are healthy.
# Runs on scm-ci; talks to each service over the VPC. Idempotent; per-section tolerant.
set -uo pipefail
cd "$(dirname "$0")"
. ./lib.sh

# deps the seed scripts need on the controller (edge)
need=""
for b in jq git curl openssl; do command -v "$b" >/dev/null 2>&1 || need="$need $b"; done
[ -n "$need" ] && { say "installing on controller:$need"; apt-get update -qq && apt-get install -y -qq $need >/dev/null; }
[ -f "$OPKEY" ] || { say "FATAL: operator key $OPKEY missing"; exit 1; }
chmod 600 "$OPKEY" 2>/dev/null || true

# ordered sections; a failure in one does not abort the rest (we want maximum seed).
SECTIONS=(10-gitea 15-gitlab 20-minio 30-vault 60-k8s 40-argo 90-decoys)
declare -A RESULT
for s in "${SECTIONS[@]}"; do
  say "=== $s ==="
  if bash "./$s.sh"; then RESULT[$s]=ok; else RESULT[$s]="FAIL($?)"; fi
done

echo
say "================ seed summary ================"
for s in "${SECTIONS[@]}"; do printf '[seed]  %-12s %s\n' "$s" "${RESULT[$s]}"; done
# non-zero exit if any section failed, so the orchestrator surfaces it
for s in "${SECTIONS[@]}"; do [ "${RESULT[$s]}" = ok ] || exit 1; done
say "all sections ok"
