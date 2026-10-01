# mini-lab-02 — SOLUTIONS (operator answer key)

> Spoilers. Every flag is `MINILAB{<id>}`. Each kill-chain below is exactly what
> `verify/playthrough.sh` performs and is validated end-to-end (26/26). Enable scenarios with a
> profile (`trainer` = all on) or per-scenario in `config/group_vars/all.yml`.

Foothold model: the player reaches the estate over WireGuard and holds low-trust SCM access
(seed creds in `seed/lib.sh`, intentional). Enforcement is real (k8s RBAC, Vault, Kyverno, MinIO
bucket scoping, GitLab protected vars / job-token scope) — each win needs the specific misconfig.

## Terraform / IaC
- **tf_1 · malicious provider** `MINILAB{tf_1-malicious-provider}` — the apply host's `~/.terraformrc`
  has a `dev_overrides` for `hashicorp/random` → `/opt/evilmirror`. `terraform plan` launches that
  attacker binary → RCE as `deployer` (reads the flag).
- **tf_2 · atlantis.yaml run:** `MINILAB{tf_2-atlantis-custom-workflow}` — server allows repo-level
  custom workflows; open a PR on `alpha/infra` whose `atlantis.yaml` plan step runs arbitrary
  commands → RCE at plan time (gitea→atlantis webhook auto-plans).
- **tf_3 · cross-team state** `MINILAB{tf_3-cross-team-state}` — loot leaked beta cloud creds on the
  alpha apply host; read team beta's MinIO-backed state.
- **tf_4 · writable state + scheduled apply** `MINILAB{tf_4-state-poisoning}` — poison `alpha/infra`;
  the cron `iac-apply.sh` applies it as the privileged `deployer`.
- **tf_5 · transitive module** `MINILAB{tf_5-transitive-module}` — `alpha/tf-modules//note` now
  sources a nested module whose `local-exec` fires on apply.
- **tf_6 · over-priv apply → k8s** `MINILAB{tf_6-k8s-rbac-backdoor}` — the apply host holds a
  cluster-admin kubeconfig; its client cert reads a `kube-system` crown secret.

## GitOps / Kubernetes
- **k8s_1 · Argo AppProject escape** `MINILAB{k8s_1-argo-project-escape}` — the widened project lets a
  committed Job escape into ns `platform` and read its crown secret.
- **k8s_2 · pipeline-SA RBAC escalation** `MINILAB{k8s_2-rbac-escalation}` — least-priv `alpha-ci`
  (create pods) launches a pod *as* a parked cluster-admin SA → reads beta's secret.
- **k8s_3 · Flux controller abuse** `MINILAB{k8s_3-flux-controller-rce}` — a Flux Kustomization watches
  an attacker-writable Git path; the cluster-admin kustomize-controller applies a Job into platform.
- **k8s_4 · weak ArgoCD admin** `MINILAB{k8s_4-argocd-weak-admin}` — login `admin:admin123` on the
  NodePort API, create+sync an app into the restricted platform namespace.

## Pipeline execution & injection
- **ppe_1 · expression injection** `MINILAB{ppe_1-expression-injection}` — commit message →
  `${{ github.event.head_commit.message }}` in a `run:` step → RCE on the Gitea host-mode runner.
- **ppe_2 · unprotected CI secret** `MINILAB{ppe_2-fork-mr-secret-exfil}` — a branch pipeline reads a
  non-protected GitLab variable on the shell runner.
- **ppe_3 · $GITHUB_ENV injection** `MINILAB{ppe_3-github-env-injection}` — edit the config file a step
  pipes into `$GITHUB_ENV`; define `$DEPLOY_CMD` which a later step runs.

## Access control & lateral movement
- **pbac_1 · CI_JOB_TOKEN cross-project** `MINILAB{pbac_1-cijobtoken-crossproject}` — target's inbound
  job-token allowlist admits web-store → a web-store job clones `beta/infra-beta`.
- **pbac_2 · rogue runner** `MINILAB{pbac_2-rogue-runner}` — leaked PAT → register a rogue runner with
  an env-dumping `pre_build_script`; pause the legit runner → it steals a victim job's secret.
- **pbac_3 · branch-protection bypass** `MINILAB{pbac_3-branch-protection-bypass}` — push straight to
  protected `main` → the protected release secret is in scope.
- **pbac_4 · over-scoped token** `MINILAB{pbac_4-overscoped-token}` — a CI bot token (wrongly a member
  of `platform`) leaks on the runner → clone another team's private repo.

## Supply chain
- **sup_1 · action re-point** `MINILAB{sup_1-action-retag}` — the pipeline pins a mutable ref
  `marketplace/deploy-action@v1`; re-point it → malicious action runs on the next CI run.
- **sup_2 · Zip-Slip artifact** `MINILAB{sup_2-zip-slip-artifact}` — a `../` tar member escapes the
  extraction dir (python `extractall`) and overwrites a trusted script the job then runs.
- **sup_3 · image supply chain** `MINILAB{sup_3-image-supply-chain}` — poison `registry:5000/alpha/web:latest`
  (insecure registry); the deploy pulls it → attacker code runs in the pod and leaks its secret.
- **sup_4 · dependency confusion** `MINILAB{sup_4-dependency-confusion}` — publish a higher-version
  `alpha-utils` on the internal mirror; CI pip-installs it → `setup.py` RCE.

## Secrets & identity pivots
- **sec_1 · CI→cluster kubeconfig pivot** `MINILAB{sec_1-ci-kubeconfig-pivot}` — harvest the CI deploy
  token off the runner; hit the k8s API and read a ns `alpha` secret.
- **sec_2 · Vault k8s-auth over-broad** `MINILAB{sec_2-vault-k8s-overbroad}` — any pod SA token logs
  into Vault's over-broad role and reads team beta's KV secret.

## Policy-as-code bypass
- **pol_1 · conftest coverage gap** `MINILAB{pol_1-conftest-coverage-gap}` — the Rego checks only
  `aws_s3_bucket`; a malicious `kubernetes_cluster_role_binding` ships past the gate.
- **pol_2 · tfsec soft-fail / skip** `MINILAB{pol_2-tfsec-skip-comment}` — `--soft-fail` (and an inline
  `#tfsec:ignore`) pass a wide-open security group.
- **pol_3 · Kyverno admission bypass** `MINILAB{pol_3-kyverno-admission-bypass}` — the enforce policy
  excludes ns `alpha`; a privileged hostPath pod there reads a node-only flag.

---

## Flagship chains (compose the validated atomics)
- **CHAIN-1 — action → cluster-admin:** sup_1 (re-point action) ⇒ RCE on the runner ⇒ sec_1 (harvest the
  deploy token on that host) ⇒ sup_3 (poison `alpha/web:latest`) ⇒ the deploy runs it ⇒ k8s_2 (assume the
  parked cluster-admin SA) ⇒ cluster-admin.
- **CHAIN-2 — cross-team pivot:** ppe_2 (branch-pipeline secret on web-store) ⇒ pbac_1 (CI_JOB_TOKEN into
  infra-beta) ⇒ sec_2 (Vault k8s-auth from a pod) ⇒ tf_3 (beta's remote state) ⇒ beta prod secrets.
- **CHAIN-3 — PR → RBAC backdoor:** ppe_1 (injection foothold) ⇒ tf_2 (atlantis.yaml RCE) ⇒ loot the
  state creds in atlantis.env ⇒ tf_4 (poison the scheduled apply) ⇒ tf_6 (cluster-admin kubeconfig) ⇒
  privileged RBAC on the cluster.
- **CHAIN-4 — GitOps worm:** k8s_1 (Argo project escape) + pol_3 (Kyverno bypass for a privileged pod) ⇒
  cluster-admin ⇒ write back to the GitOps repo (alpha/app) ⇒ fleet persistence (Argo re-applies it).

Each link is an individually-validated scenario above; a chain is solvable when its links are enabled
(see the `insane` preset for the chain-relevant subset).
