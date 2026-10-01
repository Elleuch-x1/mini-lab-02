# mini-lab-02 — build plan

Harder sibling of the mini-lab. Same two-layer architecture (swappable infra; portable config/seed),
scaled to **9 hosts** with **multi-team segmentation**, **real enforcement**, and a **blue-team track**.
Scenario catalog + counts: `SCENARIOS.md` (26 attacks + 4 chains + 6 blue-team = 36 challenges).

## Locked scope
- **Platforms:** Gitea Actions + GitLab CI + ArgoCD (+ Flux). No Jenkins.
- **No cloud-IAM** — enforcement comes from **k8s RBAC, Vault, Kyverno/OPA-Gatekeeper, OPA/Conftest,
  checkov/tfsec, MinIO bucket policies** (all self-hostable and genuinely enforcing).
- **Medium, 9 hosts**, two product teams (`alpha`, `beta`) + shared platform.
- **Zero overlap** with the mini-lab's 19 scenarios.

## Topology (9 hosts, 3 segments + edge)

| # | Host | Segment | Runs | Primary scenarios |
|---|------|---------|------|-------------------|
| 1 | `edge` | edge | WireGuard + Ansible controller + reverse proxy | access only |
| 2 | `gitea` | scm | Gitea + Gitea Actions (team **alpha**) | PPE-1/3, SUP-1, PBAC-3/4 |
| 3 | `gitlab` | scm | GitLab CE + runner controller (team **beta**) | PPE-2, PBAC-1, SUP-2/4 |
| 4 | `runner` | run | shared self-hosted runners (act_runner host-mode + gitlab-runner) | PPE-*, PBAC-2, SUP-*, SEC-1 |
| 5 | `atlantis` | iac | Atlantis + terraform/tofu | TF-2/4/5, POL-1/2 |
| 6 | `backend` | plat | MinIO (per-team state buckets) + Vault (k8s-auth, enforced) + provider-mirror | TF-1/3, SEC-2, bucket policies |
| 7 | `registry` | plat | container/artifact registry (+ cosign provenance) | SUP-3/4, SEC-1 |
| 8 | `k8s` | int | k3s + ArgoCD + Flux + Kyverno/Gatekeeper + team workloads | K8S-1..4, TF-6, POL-3 |
| 9 | `siem` | plat | log aggregation (Loki/Grafana or Wazuh-lite) + scoreboard/flag submit | all BLUE-* |

Firewalls enforce segment isolation so **lateral movement requires a chain** (e.g., alpha's runner
can't directly reach beta's state — you must pivot via CI_JOB_TOKEN / Vault / remote-state).

## Enforcement (what makes privesc real, not simulated)
- **k8s RBAC** (k3s): per-team namespaces + ServiceAccounts scoped least-privilege; escalation
  scenarios exploit real verbs (`pods/exec`, `create pods`, `escalate`, `bind`).
- **Kyverno or OPA-Gatekeeper**: admission policies (no privileged/hostPath) — POL-3 / K8S gating.
- **Vault**: real policies + Kubernetes auth method; SEC-2 and cross-team access actually denied/allowed.
- **OPA/Conftest + checkov/tfsec** in the Terraform pipeline: POL-1/2 are genuine gate bypasses.
- **MinIO bucket policies**: per-team state isolation; TF-3 cross-team access is a real policy gap.
- **Registry**: image provenance (cosign) so SUP-3 is a real signature/trust bypass.

## Reuse from the mini-lab (repo `mini-lab`)
Port ~verbatim: `common`, `gitea`, `gitea_runner`, `atlantis`, `minio`, `provider_mirror`, `vault`,
`tf_exec`, `k3s`, `argocd`, `wireguard_edge`, the orchestrator (`lab`/`configure.sh`/keep-main TF
split + persistent WG/reserved-IP, with all the fixes from the mini-lab validation), the
profile/scenario toggle system, and the `verify/playthrough*.sh` harness pattern.

Build new: `gitlab` + `gitlab_runner`, `registry` (+cosign), `flux`, `kyverno`/`gatekeeper`,
`opa`/`conftest`+`checkov`/`tfsec` pipeline steps, `siem` (log shippers + dashboards), the
multi-team seed (alpha/beta orgs, repos, k8s namespaces, Vault roles, MinIO buckets), the **26
scenario seeds**, the **4 chains**, and the **6 blue-team** detection/hardening exercises.

## Milestones
- **M1 — base**: 9 hosts up; alpha/beta/platform seeded; all services healthy; enforcement baselines
  (RBAC/Vault/Kyverno/OPA) in place and *correct* (nothing exploitable yet). `lab up/down/status`.
- **M2 — scenarios**: implement the 26 as hardened⇄vulnerable toggles; **each verified by an actual
  exploit playthrough** (the mini-lab standard) — static + dynamic harnesses.
- **M3 — chains**: wire + verify the 4 flagship chains end-to-end in `insane` profile.
- **M4 — blue-team**: ship audit logs to `siem`; author the 6 detection/hardening exercises; scoreboard.

## Validation standard (carried from the mini-lab)
Every scenario must be **captured via its real kill-chain** by `verify/playthrough*.sh`, not just
artifact-checked. Deploy → exploit all → fix failures → `lab down`. Documented in a `VALIDATION.md`.

## Lifecycle & cost
On-demand `lab up`/`down` (destroy droplets, keep reserved IP + WG). Offline build = zero cost;
deploy only to validate, then down. 9 hosts (several need ~4GB: gitlab, k8s, registry) → modest.
Portable DO → Proxmox later.
