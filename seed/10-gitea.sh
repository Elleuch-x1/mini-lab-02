#!/usr/bin/env bash
# Gitea seed — TEAM ALPHA. Org + devs + repos (app w/ passing Actions CI, infra w/ MinIO backend,
# tf-modules, shared-actions). Mostly-secure baseline; scenarios layer on top.
. "$(dirname "$0")/lib.sh"
say "gitea(alpha): users, org, repos"

for u in alice bob; do
  gitea_api POST /admin/users -d "{\"username\":\"$u\",\"email\":\"$u@minilab2.lab\",\"password\":\"Dev-$u-2026!\",\"must_change_password\":false}" >/dev/null 2>&1
done
gitea_api POST /orgs -d '{"username":"alpha","visibility":"private"}' >/dev/null 2>&1
tid=$(gitea_api GET /orgs/alpha/teams | jq -r '.[]|select(.name=="Owners").id' 2>/dev/null)
for u in alice bob; do gitea_api PUT "/orgs/alpha/teams/$tid/members/$u" >/dev/null 2>&1; done
for r in app tf-modules infra shared-actions; do
  gitea_api POST /orgs/alpha/repos -d "{\"name\":\"$r\",\"private\":true,\"auto_init\":true,\"default_branch\":\"main\"}" >/dev/null 2>&1
done

W=$(mktemp -d); cd "$W"
gc(){ git -c user.email=ci@minilab2.lab -c user.name=ci "$@"; }
clone(){ git clone -q "http://$ADMIN_USER:$ADMIN_PASS@gitea:3000/alpha/$1.git" "$1"; }

# app: passing Gitea Actions CI (with checkout) + a GitOps deploy manifest (Argo syncs it)
clone app && cd app && mkdir -p .gitea/workflows scripts deploy
cat > scripts/build.sh <<'SH'
#!/usr/bin/env bash
echo "build+test ok for alpha/app"; date
SH
cat > .gitea/workflows/ci.yml <<'YML'
name: ci
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: bash scripts/build.sh
YML
cat > deploy/deployment.yaml <<'YML'
apiVersion: apps/v1
kind: Deployment
metadata: { name: app, namespace: alpha, labels: { app: app } }
spec:
  replicas: 1
  selector: { matchLabels: { app: app } }
  template:
    metadata: { labels: { app: app } }
    spec:
      containers: [{ name: web, image: nginx:1.27-alpine, ports: [{ containerPort: 80 }] }]
YML
gc add -A && gc commit -q -m "app + CI + deploy manifest" && gc push -q origin main 2>/dev/null
cd "$W"

# tf-modules: a hardened, self-contained module (no cloud, no exec primitives)
clone tf-modules && cd tf-modules && mkdir -p note
cat > note/main.tf <<'TF'
variable "name" { type = string }
resource "local_file" "note" {
  filename = "/tmp/alpha-${var.name}.txt"
  content  = "managed by terraform: ${var.name}\n"
}
output "path" { value = local_file.note.filename }
TF
gc add -A && gc commit -q -m "note module (hardened)" && gc push -q origin main 2>/dev/null
cd "$W"

# shared-actions: a composite action alpha/app's CI could consume (SHA-pinning scenario later)
clone shared-actions && cd shared-actions
cat > action.yml <<'YML'
name: deploy-helper
description: shared composite action
runs:
  using: composite
  steps:
    - run: echo "shared deploy-helper v1"
      shell: bash
YML
gc add -A && gc commit -q -m "shared composite action" && gc push -q origin main 2>/dev/null
cd "$W"

# infra: MinIO-backed state (team alpha bucket) + a hardened baseline (null resource; no cloud)
clone infra && cd infra
cat > backend.tf <<'TF'
terraform {
  backend "s3" {
    bucket                      = "tf-state-alpha"
    key                         = "prod/terraform.tfstate"
    region                      = "eu-west-3"
    endpoints                   = { s3 = "http://minio:9000" }
    skip_credentials_validation = true
    skip_metadata_api_check     = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
    use_path_style              = true
  }
}
TF
cat > main.tf <<'TF'
# hardened baseline: module pinned by ref; no exec primitives, no cloud.
module "note" {
  source = "git::http://gitea:3000/alpha/tf-modules.git//note?ref=main"
  name   = "prod"
}
TF
gc add -A && gc commit -q -m "infra: note via module, state in MinIO" && gc push -q origin main 2>/dev/null
cd /; rm -rf "$W"
say "gitea(alpha): done"
