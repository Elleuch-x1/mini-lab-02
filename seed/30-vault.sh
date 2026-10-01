#!/usr/bin/env bash
# Vault seed: KV secrets + a least-privilege policy + an AppRole for CI.
# M1 baseline = tight policy. Attack layers add the over-broad path/token later.
. "$(dirname "$0")/lib.sh"
say "vault: kv secrets, policy, approle"
H="$HOST_VAULT"
V="export VAULT_ADDR=http://127.0.0.1:8200; export VAULT_TOKEN=\$(jq -r .root_token /etc/vault.d/init.json)"

# KV secrets (deep seed: db creds, prod api key, a registry cred)
on $H "$V
  vault kv put secret/ci/postgres host=app-prod port=5432 username=coffee_app password='Pg-C0ffee-App-2026!' >/dev/null
  vault kv put secret/prod/api    base_url=http://app-prod:8080 api_key='prod_ak_$(openssl rand -hex 12)' >/dev/null
  vault kv put secret/ci/registry server=http://state-backend:8080 username=mirror password='M1rror-Pull-2026' >/dev/null"

# least-privilege policy: CI may READ only secret/ci/* (not prod)
on $H "cat > /tmp/ci-policy.hcl" <<'HCL'
path "secret/data/ci/*"     { capabilities = ["read"] }
path "secret/metadata/ci/*" { capabilities = ["list","read"] }
HCL
on $H "$V
  vault policy write ci-read /tmp/ci-policy.hcl >/dev/null
  vault auth list -format=json | grep -q '\"approle/\"' || vault auth enable approle >/dev/null
  vault write auth/approle/role/ci token_policies=ci-read token_ttl=30m token_max_ttl=2h secret_id_ttl=24h >/dev/null
  rid=\$(vault read -field=role_id auth/approle/role/ci/role-id)
  sid=\$(vault write -f -field=secret_id auth/approle/role/ci/secret-id)
  printf 'role_id=%s\nsecret_id=%s\n' \"\$rid\" \"\$sid\" > /root/ci-approle.txt; chmod 600 /root/ci-approle.txt
  rm -f /tmp/ci-policy.hcl"
say "vault: done (CI AppRole creds in /root/ci-approle.txt on vault host)"
