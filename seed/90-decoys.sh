#!/usr/bin/env bash
# Decoys / realism filler: extra users, innocuous repos, side buckets, benign secrets.
# None of these are intentionally vulnerable — they raise the enumeration cost and
# make the lab look like a lived-in org rather than a staged target.
. "$(dirname "$0")/lib.sh"
say "decoys: extra users, repos, buckets, secrets"

# extra gitea users (not in the platform team)
for u in dave erin security-bot; do
  gitea_api POST /admin/users -d "{\"username\":\"$u\",\"email\":\"$u@minilab2.lab\",\"password\":\"Dec0y-$u-2026!\",\"must_change_password\":false}" >/dev/null 2>&1
done

# innocuous personal/legacy repos under alice (auto-init, no secrets)
for r in dotfiles internal-notes status-page; do
  curl -sS -u "alice:Dev-alice-2026!" -H 'Content-Type: application/json' \
    -X POST "$GITEA/api/v1/user/repos" \
    -d "{\"name\":\"$r\",\"private\":true,\"auto_init\":true}" >/dev/null 2>&1
done

# side buckets in minio (empty-ish, realistic ops buckets)
on "$HOST_MINIO" "mc mb -p local/backups local/logs local/ci-cache >/dev/null 2>&1; \
  echo 'nightly db dump placeholder' | mc pipe local/backups/README.txt >/dev/null 2>&1 || true"

# benign vault secret (not under ci/* or prod/*, so ci-read policy can't see it)
on "$HOST_VAULT" "export VAULT_ADDR=http://127.0.0.1:8200; export VAULT_TOKEN=\$(jq -r .root_token /etc/vault.d/init.json); \
  vault kv put secret/misc/smtp host=smtp.minilab2.lab port=587 username=noreply password='Smtp-N0reply-2026' >/dev/null 2>&1 || true"
say "decoys: done"
