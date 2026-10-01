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

### Remaining tracks (in progress)
ppe (3), pbac (4), sup (4), sec (2), k8s (4), tf_1/tf_2, pol (3) — implemented + validated per track.


## M3 — flagship chains · M4 — blue-team
Pending M2.
