# mini-lab-02 — validation log

## M1 — base + multi-team baseline ✅ (2026-10-01)
All 9 hosts deploy green (Ansible `failed=0`): edge, gitea, gitlab, runner, atlantis,
backend (MinIO built-from-source + Vault + mirror), registry, k8s (k3s + Argo + Flux + Kyverno +
app), siem (Loki + Grafana).

`lab status` → **14/14 healthy**: gitea, gitlab, atlantis, minio, vault, registry, mirror, argocd,
app, grafana endpoints + k3s-node Ready, flux controllers, kyverno admission, argocd server.

Multi-team baseline seed → **all sections ok**: alpha org (gitea) + beta group (gitlab) with
repos/CI/users; per-team MinIO state buckets + scoped keys; per-team Vault KV + policies + AppRoles;
per-team k8s namespaces + least-priv RBAC + Kyverno baseline (enforce no privileged/hostPath);
alpha Argo app. Nothing intentionally exploitable yet (mostly-secure baseline).

Fixes found during M1 bring-up (new roles mostly worked first try): gitlab `grafana[]` removed
(omnibus 16+); kyverno server-side apply + tolerant rollout; gitlab seed combined into one
gitlab-rails call. All prior mini-lab fixes carried over (MinIO-from-source, cloud-init timeout,
reserved-IP via doctl, atlantis/gitea config, etc.).

## M2 — scenarios (in progress)
Each scenario is a hardened⇄vulnerable toggle verified by an **actual exploit playthrough**
(`verify/playthrough.sh`, run on the edge over the VPC), per the mini-lab standard.

### Terraform / IaC track ✅ (2026-10-01) — 4/4 captured
`verify/playthrough.sh` → **tf_3, tf_4, tf_5, tf_6 all PASS**:
- **tf_3** cross-team remote-state exfil: foothold on alpha's apply host (atlantis) loots a leaked
  beta cloud key → reads team **beta's** MinIO-backed state → `MINILAB{tf_3-cross-team-state}`.
- **tf_4** writable auto-applied IaC + scheduled apply: attacker with SCM write poisons `alpha/infra`;
  the cron drift-apply (`iac-apply.sh`) runs it as the privileged **deployer** → `MINILAB{tf_4-state-poisoning}`.
- **tf_5** transitive module exec: the "trusted" `alpha/tf-modules//note` now sources a nested module
  whose `local-exec` fires on apply → `MINILAB{tf_5-transitive-module}`.
- **tf_6** over-privileged apply identity: the apply host holds a **cluster-admin kubeconfig**; its client
  cert reads a `kube-system` crown secret via the k8s API → `MINILAB{tf_6-k8s-rbac-backdoor}`.

Harness notes: nested ssh→su quoting is handled via a base64 `rsx` helper; tf_4 uses a `timestamp()`
trigger so the kill-chain re-fires on every run (repeatable). All four re-run green.

### GitOps / Kubernetes track ✅ (2026-10-01) — 4/4 captured
`verify/playthrough.sh` → **k8s_1, k8s_2, k8s_3, k8s_4 all PASS**:
- **k8s_1** ArgoCD AppProject escape: baseline pins alpha to a restricted project; the gap widens it so
  a committed Job escapes into the **platform** namespace and reads its crown secret → `MINILAB{k8s_1-argo-project-escape}`.
- **k8s_2** pipeline-SA RBAC escalation: least-priv `alpha-ci` (create pods) launches a pod *as* a parked
  cluster-admin SA → reads team **beta's** secret → `MINILAB{k8s_2-rbac-escalation}`.
- **k8s_3** Flux controller abuse: a Flux Kustomization watches an attacker-writable Git path; the
  cluster-admin kustomize-controller applies a Job into platform → `MINILAB{k8s_3-flux-controller-rce}`.
- **k8s_4** weak ArgoCD admin on the exposed NodePort API: login `admin:admin123` → create+sync an app
  that deploys into the restricted platform namespace → `MINILAB{k8s_4-argocd-weak-admin}`.

Harness notes: in-cluster attacker identities use short-lived SA tokens; GitOps kill-chains force-sync
(Argo refresh / Flux reconcile annotations) then poll the escaped Job's logs; Argo API login needs
`Content-Type: application/json`.

### IaC / policy / access-control (first slice) ✅ (2026-10-01) — 3/3 captured
- **tf_1** malicious provider via `.terraformrc` redirect: a `dev_overrides` entry points the null
  provider at an attacker dir; `terraform plan` launches that binary → RCE → `MINILAB{tf_1-malicious-provider}`.
- **pol_3** Kyverno admission bypass: the enforce policy is re-applied with a namespace **exclusion**,
  so a privileged hostPath pod in ns alpha is admitted → reads a node-only flag → `MINILAB{pol_3-kyverno-admission-bypass}`.
- **pbac_4** over-scoped token: a CI bot token (member of a team it shouldn't be) leaks onto the shared
  runner → clones another team's private repo → `MINILAB{pbac_4-overscoped-token}`.

### Remaining tracks (in progress)
**Done: 11/26** — tf_1/3/4/5/6, k8s_1/2/3/4, pol_3, pbac_4. Next: ppe (3), pbac_1/2/3, sup (4), sec (2), tf_2, pol_1/2.


## M3 — flagship chains · M4 — blue-team
Pending M2.
