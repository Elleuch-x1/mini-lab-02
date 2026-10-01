# mini-lab-02 — scenario catalog (CI/CD + IaC + GitOps/k8s, common & complex)

A second, harder lab focused on **real-world-common and multi-stage** CI/CD, Terraform, and
GitOps/Kubernetes attacks — with **real enforcement** (k8s RBAC, Vault, policy-as-code, MinIO
bucket policies) so privilege escalation is genuine, not simulated. Multi-team segmentation; a
built-in blue-team track. Mapped to the **OWASP CI/CD Top-10**.

> **No overlap with the mini-lab.** Every scenario here uses a mechanism the mini-lab did NOT
> implement. Deliberately excluded (already in the mini-lab): i-PPE via a dev-editable build
> script, secret-in-CI-logs, weak/hardcoded creds & recon pitfalls, hardcoded tfvars/non-sensitive
> outputs, `local-exec`/`external` primitives, Atlantis plan-time-via-external, world-readable /
> backend-creds state reads, generic writable-state poisoning, unpinned **module** poisoning,
> Vault AppRole over-broad path, moto "cloud" backdoor, Argo hostPath→node-escape.

## Status: ✅ COMPLETE — all 26 scenarios + 4 chains + 6 blue-team implemented & validated (see VALIDATION.md / SOLUTIONS.md).

## Counts
- **26 attack scenarios** (all distinct from the mini-lab), across 7 tracks
- **4 flagship cross-domain chains** (compose the atomic scenarios)
- **6 blue-team detection/hardening exercises**
- **= 36 total challenges**

Difficulty skews harder than the mini-lab (mostly T2–T4). Each is a profile toggle
(`trainer` / `realistic` / `insane`); `insane` leaves only the flagship chains solvable.

---

## Track A — Pipeline execution & injection (CICD-SEC-4) · 3
| ID | Scenario | Why common / complex |
|----|----------|----------------------|
| PPE-1 | **Expression/template injection** — untrusted PR title/branch/issue body flows into a `run:` step | #1 real GitHub-Actions bug class; defeats "protected workflow" assumptions |
| PPE-2 | **Fork-PR / `pull_request_target`-style privileged run** — GitLab MR from a fork executes with protected vars/secrets in context | the modern secret-exfil primitive |
| PPE-3 | **Workflow-command injection** — poison `$GITHUB_ENV`/`set-output`/`add-path` in an early step to hijack a later privileged step | subtle, chains within one pipeline |

## Track B — Access control & lateral movement (CICD-SEC-1/5) · 4
| ID | Scenario | Why common / complex |
|----|----------|----------------------|
| PBAC-1 | **GitLab `CI_JOB_TOKEN` cross-project** — allowlist misconfig → clone/trigger another team's project | the canonical GitLab lateral-movement bug |
| PBAC-2 | **Rogue runner registration** — steal a runner registration token → register an attacker runner → intercept another team's jobs + secrets | distinct from "loot a prior job" |
| PBAC-3 | **Branch-protection / approval bypass** — merge to a protected branch via a bot/CODEOWNERS gap → privileged release pipeline | flow-control failure |
| PBAC-4 | **Over-scoped org/group token → cross-repo write** — poison a shared repo other pipelines consume | blast-radius via one token |

## Track C — Supply chain (CICD-SEC-3/8/9) · 4
| ID | Scenario | Why common / complex |
|----|----------|----------------------|
| SUP-1 | **3rd-party CI action pinned by tag, not SHA** → re-tag attack → RCE in a privileged pipeline | the literal tj-actions/changed-files (CVE-2025-30066) class |
| SUP-2 | **Artifact poisoning / Zip-Slip** — downstream job consumes an untrusted upstream artifact (path traversal) | cross-pipeline, integrity-validation gap |
| SUP-3 | **Container image supply chain** — poison a base image / `:latest` in the internal registry → RCE in the consuming build/deploy | registry-trust failure |
| SUP-4 | **Dependency confusion** — internal package/module name shadowed by a malicious public-ish one in the build | classic, still everywhere |

## Track D — Secrets & identity pivots (CICD-SEC-6) · 2
| ID | Scenario | Why common / complex |
|----|----------|----------------------|
| SEC-1 | **CI → registry/kubeconfig pivot** — a harvested deploy credential is *used* to push a malicious image / reach the cluster | the pivot, not the "find" |
| SEC-2 | **Vault Kubernetes-auth over-broad role** — any pod ServiceAccount can fetch another team's secrets (Vault **enforced**) | k8s↔Vault trust, real gate |

## Track E — GitOps / Kubernetes (Argo + k3s, RBAC enforced) · 4
| ID | Scenario | Why common / complex |
|----|----------|----------------------|
| K8S-1 | **ArgoCD app-of-apps / AppProject escape** → deploy to a restricted namespace / cluster-admin | GitOps flagship |
| K8S-2 | **k8s RBAC escalation from a pipeline ServiceAccount** — `pods/exec` or `create pods` → steal a privileged SA token; or `escalate`/`bind` verbs | real RBAC, very common |
| K8S-3 | **Flux Kustomize `postBuild` / Helm post-renderer RCE** (or Argo CMP plugin RCE) in the GitOps controller | controller-level RCE |
| K8S-4 | **Exposed ArgoCD API/UI + weak admin** → sync arbitrary manifests | config/exposure failure |

## Track F — Terraform / IaC (new mechanisms) · 6
| ID | Scenario | Why common / complex |
|----|----------|----------------------|
| TF-1 | **Malicious provider** via network-mirror / `.terraformrc` redirect — a provider plugin runs code on `init` | RCE-by-design, under-practiced |
| TF-2 | **Atlantis repo-level `atlantis.yaml` custom workflow `run:`** → arbitrary commands | config-as-RCE (≠ plan-time external) |
| TF-3 | **Cross-team remote-state exfil** via `terraform_remote_state` → steal another team's outputs/secrets | cross-tenant pivot |
| TF-4 | **Resource adoption / hijack via state edit** — rewrite a resource ID so the next apply adopts/destroys a *real* resource | advanced state abuse |
| TF-5 | **Transitive module exec** — a trusted module pulls a submodule carrying a provisioner/`external` | review-depth evasion |
| TF-6 | **Over-privileged apply identity → provisions a privileged k8s RBAC binding/SA** (TF k8s provider) → cluster-admin | enforced k8s privesc endgame |

## Track G — Policy-as-code / governance bypass · 3
| ID | Scenario | Why common / complex |
|----|----------|----------------------|
| POL-1 | **OPA/Conftest coverage gap** — policy misses a resource type or module path → malicious resource ships | "governance theatre" |
| POL-2 | **checkov/tfsec skip-comment / soft-fail abuse** (`#checkov:skip`) | trivially bypassed gate |
| POL-3 | **Kyverno / OPA-Gatekeeper admission bypass** — a policy gap admits a privileged pod | enforced admission, real |

---

## Flagship chains (T4) · 4
- **CHAIN-1 — action→cluster-admin:** SUP-1 → runner RCE → SEC-1 (registry cred) → SUP-3 (poison image) → Argo deploys it → K8S-2 (RBAC escalation) → cluster-admin.
- **CHAIN-2 — cross-team pivot:** PPE-2 (fork MR injection) → PBAC-1 (CI_JOB_TOKEN cross-project) → SEC-2 (Vault k8s-auth) → TF-3 (cross-team remote state) → other team's prod secrets.
- **CHAIN-3 — PR→RBAC backdoor:** PPE-1 → TF-2 (atlantis.yaml RCE) → state creds → TF-4 (state hijack) → TF-6 → privileged RBAC binding → cluster-admin.
- **CHAIN-4 — GitOps worm:** K8S-1 (app-of-apps escape) + POL-3 (admission bypass) → cluster-admin → write back to the GitOps repo → fleet persistence.

## Blue-team track · 6
- **BLUE-1** detect PPE/injection in Gitea/GitLab CI run logs.
- **BLUE-2** detect rogue-runner registration + CI_JOB_TOKEN cross-project in audit logs.
- **BLUE-3** detect malicious action/image/provider via provenance + registry logs.
- **BLUE-4** detect k8s RBAC escalation / privileged pod via the k8s audit log.
- **BLUE-5** detect state tampering / unexpected apply via Atlantis + MinIO + Vault audit.
- **BLUE-6** harden & re-verify — fix the misconfig (SHA-pin, scope tokens, tighten RBAC/Vault/OPA), re-run the playthrough, confirm the path is closed.
