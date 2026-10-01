#!/usr/bin/env bash
# Gitea seed: dev users, an org + team, repos with real content/history, a passing Actions workflow.
. "$(dirname "$0")/lib.sh"
say "gitea: users, org, repos"

# --- dev users (idempotent: 422 if exists) ---
for u in alice bob carol; do
  gitea_api POST /admin/users -d "{\"username\":\"$u\",\"email\":\"$u@driftwood.lab\",\"password\":\"Dev-$u-2026!\",\"must_change_password\":false}" >/dev/null
done

# --- org + team ---
gitea_api POST /orgs -d '{"username":"vultara","visibility":"private"}' >/dev/null
gitea_api POST /orgs/vultara/teams -d '{"name":"platform","permission":"write","units":["repo.code","repo.actions","repo.pulls"]}' >/dev/null
for u in alice bob; do gitea_api PUT "/orgs/vultara/teams/$(gitea_api GET /orgs/vultara/teams | jq -r '.[]|select(.name=="platform").id')/members/$u" >/dev/null 2>&1; done

# --- repos ---
for r in coffeeshop-api tf-modules infra; do
  gitea_api POST /orgs/vultara/repos -d "{\"name\":\"$r\",\"private\":true,\"auto_init\":true,\"default_branch\":\"main\"}" >/dev/null
done

# --- push content (clone over http with admin creds) ---
W=$(mktemp -d); cd "$W"
git config --global user.email "ci@driftwood.lab"; git config --global user.name "CI Bot"
clone(){ git clone -q "http://$ADMIN_USER:$ADMIN_PASS@gitea:3000/vultara/$1.git" "$1"; }

# app repo + a PASSING Gitea Actions workflow (no external actions -> works host-mode/offline)
clone coffeeshop-api && cd coffeeshop-api
mkdir -p .gitea/workflows src deploy
cat > .gitea/workflows/ci.yml <<'YML'
name: ci
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "build+test ok for coffeeshop-api"; date; git --version
YML
cat > src/app.py <<'PY'
def health(): return {"status": "ok", "service": "coffeeshop-api"}
PY
cat > deploy/deployment.yaml <<'YML'
apiVersion: apps/v1
kind: Deployment
metadata: { name: coffeeshop-api, labels: { app: coffeeshop-api } }
spec:
  replicas: 1
  selector: { matchLabels: { app: coffeeshop-api } }
  template:
    metadata: { labels: { app: coffeeshop-api } }
    spec:
      containers:
        - name: web
          image: nginx:1.27-alpine
          ports: [{ containerPort: 80 }]
---
apiVersion: v1
kind: Service
metadata: { name: coffeeshop-api }
spec:
  selector: { app: coffeeshop-api }
  ports: [{ port: 80, targetPort: 80 }]
YML
cat > README.md <<'MD'
# coffeeshop-api
Vultara ordering API. CI runs on Gitea Actions (self-hosted runner);
deploy/ is reconciled to the cluster by Argo CD (GitOps).
MD
git add -A && git commit -q -m "add app + CI workflow" && git push -q origin main
cd "$W"

# tf-modules: a small, hardened module (pinned, no exec primitives)
clone tf-modules && cd tf-modules
mkdir -p bucket
cat > bucket/main.tf <<'TF'
variable "name" { type = string }
resource "aws_s3_bucket" "this" { bucket = var.name }
resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
output "id" { value = aws_s3_bucket.this.id }
TF
git add -A && git commit -q -m "s3 bucket module (hardened)" && git push -q origin main
cd "$W"

# infra: root config using the module + an S3(MinIO) backend (state lives in MinIO)
clone infra && cd infra
cat > backend.tf <<'TF'
terraform {
  backend "s3" {
    bucket                      = "tf-state"
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
cat > providers.tf <<'TF'
# AWS provider points at the in-lab mock cloud (Moto). Resources are created there; state is in MinIO.
provider "aws" {
  region                      = "eu-west-3"
  access_key                  = "seed"
  secret_key                  = "seed"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true
  endpoints {
    s3  = "http://moto:5000"
    iam = "http://moto:5000"
    sts = "http://moto:5000"
    ec2 = "http://moto:5000"
  }
}
TF
cat > main.tf <<'TF'
# hardened baseline: module pinned to a commit SHA in real use (CI enforces it)
module "reports_bucket" {
  source = "git::http://gitea:3000/vultara/tf-modules.git//bucket?ref=main"
  name   = "vultara-reports"
}
TF
git add -A && git commit -q -m "infra root: reports bucket via module, aws->moto, state in MinIO" && git push -q origin main
cd /; rm -rf "$W"
say "gitea: done"
