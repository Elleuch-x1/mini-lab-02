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

## M2 — scenarios ✅ COMPLETE (2026-10-01) — 26/26 validated
Every scenario is a hardened⇄vulnerable toggle verified by an **actual exploit playthrough**
(`verify/playthrough.sh`, run on the edge over the VPC). **Final run: 26 passed, 0 failed**, both
per-scenario and all-26-together (regression-clean).

| Track | Scenarios (all PASS) |
|-------|----------------------|
| Terraform/IaC | tf_1 malicious provider (.terraformrc dev-override), tf_2 Atlantis custom-workflow run: RCE, tf_3 cross-team remote state, tf_4 writable state + scheduled apply, tf_5 transitive module exec, tf_6 over-priv apply → k8s RBAC backdoor |
| GitOps/k8s | k8s_1 Argo AppProject escape, k8s_2 pipeline-SA RBAC escalation, k8s_3 Flux controller abuse, k8s_4 weak ArgoCD admin API |
| Pipeline injection | ppe_1 expression injection, ppe_2 unprotected-secret branch pipeline, ppe_3 $GITHUB_ENV file injection |
| Access control | pbac_1 CI_JOB_TOKEN cross-project, pbac_2 rogue runner, pbac_3 branch-protection bypass, pbac_4 over-scoped token |
| Supply chain | sup_1 action mutable-ref re-point, sup_2 Zip-Slip artifact, sup_3 image :latest poisoning, sup_4 dependency confusion |
| Secrets/identity | sec_1 CI→cluster kubeconfig pivot, sec_2 Vault k8s-auth over-broad |
| Policy-as-code | pol_1 conftest coverage gap, pol_2 tfsec soft-fail, pol_3 Kyverno namespace-exclusion bypass |

**Infra bugs fixed during M2:** gitlab_runner `creates:`-guard skipped registration (GitLab CI never ran) →
guard on `[[runners]]`; concurrent=4. Cross-scenario interference removed: tf_1 override moved off
`hashicorp/null` (was breaking tf_4/tf_5); tf_2/pbac_3/sup_2 made idempotent (unique trigger per run);
sup_3 pod-log poll scans all pods. act_runner escapes `${{ }}` newlines (ppe_3 uses untrusted-file vector).

## M3 — flagship chains · M4 — blue-team

Pending M2.
