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
**✅ COMPLETE — 36/36 challenges built & validated by real exploitation** (26 attacks + 4 chains + 6
blue-team). 9 hosts deploy green; `verify/playthrough.sh` → **26/26**, `verify/blue.sh` → **7/7**. See
[`VALIDATION.md`](VALIDATION.md) (validation log) and [`SOLUTIONS.md`](SOLUTIONS.md) (operator answer key).

### Run it
- `./orchestrator/lab up --profile trainer` — deploy 9 hosts + configure + seed (all scenarios on).
  Profiles: `trainer` (all), `realistic` (curated subset + decoys), `insane` (chain links only).
- `./orchestrator/lab vpn` — print the WireGuard client config; connect, then attack over the tunnel.
- `./orchestrator/lab verify` — exploit every enabled scenario and check the flags (red team).
  Add `--blue` to also run the detection + harden/re-verify exercises.
- `./orchestrator/lab status` — 14-point health probe. `./orchestrator/lab reset --profile <p>` — change difficulty.
- `./orchestrator/lab down` — destroy droplets to stop cost; keeps the reserved IP + VPC + WG identity
  (next `up` reuses the same VPN endpoint).

> Self-contained, authorized training lab. Seed credentials are intentional lab creds. Never commit
> real secrets, VPN keys, cloud tokens, or tfstate (see `.gitignore`).
