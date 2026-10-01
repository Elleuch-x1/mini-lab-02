#!/usr/bin/env bash
# 50-scenarios.sh — apply ENABLED attack scenarios (hardened->vulnerable) + plant flags.
# A scenario sc_<id> runs only if `scenario_on <id>` AND the function exists. Implementations are
# added incrementally (M2) and each is verified by an actual exploit playthrough (verify/).
. "$(dirname "$0")/lib.sh"
say "scenarios: applying enabled toggles for profile=$PROFILE"
say "enabled: $(tr '\n' ' ' < "$ENABLED_FILE" 2>/dev/null)"

# ---- helpers shared by scenarios ----
gc(){ git -c user.email=atk@minilab2.lab -c user.name=atk "$@"; }
gclone_alpha(){ git clone -q "http://$ADMIN_USER:$ADMIN_PASS@gitea:3000/alpha/$1.git" "$2" 2>/dev/null; }

# ========================= scenario implementations (M2) =========================
# (added one track at a time; see SCENARIOS.md for the catalog)
#   PPE-*, PBAC-*, SUP-*, SEC-*, K8S-*, TF-*, POL-*

# ---- TF-3: cross-team remote state exfil (alpha pipeline reaches beta's state) ----
sc_tf_3(){
  say "TF-3 cross-team remote state"
  # a juicy flag in beta's state
  on "$HOST_MINIO" "mc alias set local http://127.0.0.1:9000 '$MINIO_USER' '$MINIO_PASS' >/dev/null 2>&1; \
    printf '{\"version\":4,\"terraform_version\":\"1.9.8\",\"serial\":2,\"lineage\":\"beta-state\",\"outputs\":{\"db_password\":{\"value\":\"%s\",\"type\":\"string\",\"sensitive\":true}},\"resources\":[]}' '$(flag tf_3-cross-team-state)' > /tmp/bst.json; \
    mc cp /tmp/bst.json local/tf-state-beta/prod/terraform.tfstate >/dev/null 2>&1; rm -f /tmp/bst.json"
  # leaked beta key reachable from the alpha apply host (the cross-team cred the attacker obtains)
  on "$HOST_TFEXEC" "install -d -m700 -o deployer -g deployer /home/deployer/.beta 2>/dev/null; \
    printf 'AWS_ACCESS_KEY_ID=beta-ci\nAWS_SECRET_ACCESS_KEY=beta-St4te-2026!\n' > /home/deployer/.beta/creds; \
    chown deployer:deployer /home/deployer/.beta/creds; chmod 600 /home/deployer/.beta/creds"
}

# ---- TF-5: transitive module exec (trusted module -> submodule with a provisioner) ----
sc_tf_5(){
  say "TF-5 transitive module exec"
  on "$HOST_TFEXEC" "echo '$(flag tf_5-transitive-module)' > /home/deployer/tf5-flag.txt; chown deployer:deployer /home/deployer/tf5-flag.txt; chmod 600 /home/deployer/tf5-flag.txt"
  local W; W=$(mktemp -d); if gclone_alpha tf-modules "$W/r"; then ( cd "$W/r"; mkdir -p note/inner
    grep -q 'module "inner"' note/main.tf 2>/dev/null || printf '\nmodule "inner" { source = "./inner" }\n' >> note/main.tf
    cat > note/inner/main.tf <<'TF'
resource "null_resource" "x" {
  provisioner "local-exec" { command = "cat /home/deployer/tf5-flag.txt > /tmp/tf5-proof 2>/dev/null" }
}
TF
    gc add -A && gc commit -q -m "note: use inner helper module" && gc push -q origin main 2>/dev/null ); fi; rm -rf "$W"
}

# ---- TF-6: over-privileged apply identity -> provisions a privileged k8s RBAC binding ----
sc_tf_6(){
  say "TF-6 over-priv apply identity -> k8s RBAC backdoor"
  # the apply identity holds a cluster-admin kubeconfig (over-privileged) on the atlantis host
  local kc; kc=$(on "$HOST_K8S" "cat /etc/rancher/k3s/k3s.yaml" 2>/dev/null | sed 's#https://127.0.0.1:6443#https://k8s:6443#')
  on "$HOST_TFEXEC" "install -d -m700 -o deployer -g deployer /home/deployer/.kube 2>/dev/null; cat > /home/deployer/.kube/config; chown deployer:deployer /home/deployer/.kube/config; chmod 600 /home/deployer/.kube/config" <<<"$kc"
  # a cluster-admin-only crown-jewel secret the backdoor grants access to
  on "$HOST_K8S" "k3s kubectl -n kube-system create secret generic crown --from-literal=flag='$(flag tf_6-k8s-rbac-backdoor)' --dry-run=client -o yaml | k3s kubectl apply -f - >/dev/null 2>&1"
}

# ---- TF-4: writable state + scheduled apply (deployer) -> poisoned module executes ----
sc_tf_4(){
  say "TF-4 writable state + scheduled apply (deployer identity)"
  on "$HOST_TFEXEC" "echo '$(flag tf_4-state-poisoning)' > /home/deployer/flag.txt; chown deployer:deployer /home/deployer/flag.txt; chmod 600 /home/deployer/flag.txt"
  # deployer automation holds a gitea deploy credential (clone private alpha/infra + fetch module)
  on "$HOST_TFEXEC" "printf 'http://%s:%s@gitea:3000\n' '$ADMIN_USER' '$ADMIN_PASS' > /home/deployer/.git-credentials; \
    chown deployer:deployer /home/deployer/.git-credentials; chmod 600 /home/deployer/.git-credentials; \
    su deployer -c 'git config --global credential.helper store; git config --global user.email deployer@minilab2.lab; git config --global user.name deployer'"
  on "$HOST_TFEXEC" "cat > /usr/local/bin/iac-apply.sh <<'SH'
#!/usr/bin/env bash
# scheduled drift-correction: pull alpha/infra + apply from the MinIO-backed state (as deployer)
export HOME=/home/deployer
cd /opt/iac || exit 0
[ -d infra/.git ] || git clone -q http://gitea:3000/alpha/infra.git infra 2>/dev/null
cd infra && git pull -q 2>/dev/null
export AWS_ACCESS_KEY_ID=alpha-ci AWS_SECRET_ACCESS_KEY='alpha-St4te-2026!'
/usr/local/bin/terraform init -input=false -reconfigure >/tmp/iac-apply.log 2>&1
/usr/local/bin/terraform apply -input=false -auto-approve >>/tmp/iac-apply.log 2>&1
SH
chmod +x /usr/local/bin/iac-apply.sh; chown deployer:deployer /usr/local/bin/iac-apply.sh"
  on "$HOST_TFEXEC" "( crontab -u deployer -l 2>/dev/null | grep -v iac-apply; echo '*/10 * * * * /usr/local/bin/iac-apply.sh' ) | crontab -u deployer -"
}

# ========================= GitOps / Kubernetes track (K8S-*) =====================

# ---- K8S-1: ArgoCD AppProject escape -> deploy into a restricted namespace -------------
# baseline (40-argo) pins alpha to a RESTRICTED project (ns alpha only, no cluster/other-ns).
# the gap widens that project so a committed manifest can escape into ns platform.
sc_k8s_1(){
  say "K8S-1 ArgoCD AppProject escape"
  on "$HOST_K8S" "k3s kubectl -n platform create secret generic crown --from-literal=flag='$(flag k8s_1-argo-project-escape)' --dry-run=client -o yaml | k3s kubectl apply -f - >/dev/null 2>&1
cat <<'YML' | k3s kubectl apply -f - >/dev/null 2>&1
apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata: { name: alpha, namespace: argocd }
spec:
  sourceRepos: ['*']
  destinations: [{ server: 'https://kubernetes.default.svc', namespace: '*' }]
  clusterResourceWhitelist: [{ group: '*', kind: '*' }]
  namespaceResourceWhitelist: [{ group: '*', kind: '*' }]
YML"
}

# ---- K8S-2: k8s RBAC escalation from a pipeline ServiceAccount -------------------------
# gap: an over-privileged SA (cluster-admin) is parked in a team namespace; the team's least-priv
# `create pods` right lets it launch a pod *as* that SA -> assumes cluster-admin -> cross-team secret.
sc_k8s_2(){
  say "K8S-2 pipeline-SA RBAC escalation"
  on "$HOST_K8S" "k3s kubectl -n beta create secret generic rbac-crown --from-literal=flag='$(flag k8s_2-rbac-escalation)' --dry-run=client -o yaml | k3s kubectl apply -f - >/dev/null 2>&1
k3s kubectl -n alpha create sa alpha-deploy --dry-run=client -o yaml | k3s kubectl apply -f - >/dev/null 2>&1
cat <<'YML' | k3s kubectl apply -f - >/dev/null 2>&1
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: alpha-deploy-admin }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin }
subjects: [{ kind: ServiceAccount, name: alpha-deploy, namespace: alpha }]
YML"
}

# ---- dispatcher ----
ALL="ppe_1 ppe_2 ppe_3 pbac_1 pbac_2 pbac_3 pbac_4 sup_1 sup_2 sup_3 sup_4 sec_1 sec_2 \
     k8s_1 k8s_2 k8s_3 k8s_4 tf_1 tf_2 tf_3 tf_4 tf_5 tf_6 pol_1 pol_2 pol_3"
for s in $ALL; do
  if scenario_on "$s"; then
    if declare -f "sc_${s}" >/dev/null 2>&1; then "sc_${s}" || say "WARN: sc_${s} had errors"
    else say "NOTE: $s enabled but not yet implemented"; fi
  fi
done
say "scenarios: done"
