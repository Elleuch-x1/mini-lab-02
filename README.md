# mini-lab-02

A harder, real-world-focused **CI/CD + Terraform + GitOps/Kubernetes attack lab** — common and
multi-stage techniques, with **genuine enforcement** (k8s RBAC, Vault, policy-as-code, MinIO
policies) so privilege escalation is real. Multi-team segmentation, built-in blue-team track.

- **[`SCENARIOS.md`](SCENARIOS.md)** — the catalog: **26 attack scenarios + 4 flagship chains + 6
  blue-team exercises = 36 challenges**, mapped to the OWASP CI/CD Top-10. No overlap with the mini-lab.
- **[`PLAN.md`](PLAN.md)** — 9-host topology, enforcement design, reuse strategy, milestones.

## How it differs from the mini-lab
The mini-lab covered the canonical catalog (19 scenarios). This one goes after what shows up in real
breaches/pentests and the **harder, chained, enforcement-gated** variants: template/`CI_JOB_TOKEN`/
supply-chain (tj-actions-style) attacks, ArgoCD/Flux + k8s RBAC escalation, malicious providers,
cross-team remote-state pivots, state hijacking, and policy-as-code bypass — plus a defender track.

## Platforms
Gitea Actions · GitLab CI · ArgoCD/Flux · k3s (Kyverno/Gatekeeper) · Atlantis · Vault · MinIO · registry.

## Status
**Planning only.** No build started — see `PLAN.md` → milestones. Much of the service layer ports from
the sibling `mini-lab`; new work is GitLab/registry/Flux/Kyverno/OPA/SIEM + the 36 challenges.

> Self-contained, authorized training lab. Seed credentials are intentional lab creds. Never commit
> real secrets, VPN keys, cloud tokens, or tfstate (see `.gitignore`).
