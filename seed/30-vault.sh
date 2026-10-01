#!/usr/bin/env bash
# Vault seed (multi-team): per-team KV + scoped policies + per-team AppRole (ENFORCED isolation).
# Baseline = each team's role reads ONLY its own path. SEC-2 (k8s-auth over-broad) is added in M2.
. "$(dirname "$0")/lib.sh"
say "vault: per-team KV + scoped policies + approles"
H="$HOST_VAULT"
V="export VAULT_ADDR=http://127.0.0.1:8200; export VAULT_TOKEN=\$(jq -r .root_token /etc/vault.d/init.json)"

on "$H" "$V
  vault secrets list -format=json 2>/dev/null | grep -q '\"secret/\"' || vault secrets enable -path=secret kv-v2 >/dev/null 2>&1
  vault kv put secret/alpha/db     host=app port=5432 username=alpha_app password='Alpha-Db-2026!' >/dev/null
  vault kv put secret/beta/db      host=app port=5432 username=beta_app  password='Beta-Db-2026!'  >/dev/null
  vault kv put secret/platform/smtp host=smtp.minilab2.lab username=noreply password='Smtp-2026'   >/dev/null
  vault auth list -format=json 2>/dev/null | grep -q '\"approle/\"' || vault auth enable approle >/dev/null 2>&1"

for t in alpha beta; do
  on "$H" "$V
    printf 'path \"secret/data/$t/*\" { capabilities=[\"read\"] }\npath \"secret/metadata/$t/*\" { capabilities=[\"list\",\"read\"] }\n' > /tmp/$t.hcl
    vault policy write ${t}-read /tmp/$t.hcl >/dev/null
    vault write auth/approle/role/$t token_policies=${t}-read token_ttl=30m token_max_ttl=2h secret_id_ttl=24h >/dev/null
    rid=\$(vault read -field=role_id auth/approle/role/$t/role-id)
    sid=\$(vault write -f -field=secret_id auth/approle/role/$t/secret-id)
    printf 'VAULT_ADDR=http://vault:8200\nROLE_ID=%s\nSECRET_ID=%s\n' \"\$rid\" \"\$sid\" > /root/$t-approle.txt; chmod 600 /root/$t-approle.txt
    rm -f /tmp/$t.hcl"
done
say "vault: done (per-team approle creds in /root/<team>-approle.txt on vault host)"
