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
Each of the 26 scenarios is implemented as a hardened⇄vulnerable toggle and verified by an actual
exploit playthrough (static + dynamic harnesses), per the mini-lab standard. Status: framework +
`tf_4` landed; remainder in progress.

## M3 — flagship chains · M4 — blue-team
Pending M2.
