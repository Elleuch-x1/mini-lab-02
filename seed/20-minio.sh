#!/usr/bin/env bash
# MinIO seed: tf-state bucket + a realistic sample state object, plus scoped "IAM" users/policies.
# M1 baseline = PROPERLY scoped (least-privilege). Attack layers loosen these later.
. "$(dirname "$0")/lib.sh"
say "minio: buckets, sample state, scoped users/policies"
H="$HOST_MINIO"

# mc alias to the local minio (root creds from the env file the role wrote)
on $H "mc alias set local http://127.0.0.1:9000 '$MINIO_USER' '$MINIO_PASS' >/dev/null 2>&1"

# buckets: tf-state (versioned), artifacts
on $H "mc mb -p local/tf-state local/artifacts >/dev/null 2>&1; mc version enable local/tf-state >/dev/null 2>&1 || true"

# a realistic sample Terraform state (so the bucket isn't empty; matches infra repo key)
on $H "cat > /tmp/sample.tfstate" <<'JSON'
{
  "version": 4,
  "terraform_version": "1.9.8",
  "serial": 7,
  "lineage": "a1b2c3d4-driftwood-state",
  "outputs": {},
  "resources": [
    {
      "mode": "managed", "type": "aws_s3_bucket", "name": "this",
      "module": "module.reports_bucket", "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [{ "attributes": { "bucket": "vultara-reports", "id": "vultara-reports", "region": "eu-west-3" } }]
    }
  ]
}
JSON
on $H "mc cp /tmp/sample.tfstate local/tf-state/prod/terraform.tfstate >/dev/null 2>&1; rm -f /tmp/sample.tfstate"

# --- scoped policies (least-privilege, the enforced 'cloud IAM' surface) ---
# terraform CI user: read/write ONLY the tf-state bucket.
on $H "cat > /tmp/p-tfstate.json" <<'JSON'
{ "Version": "2012-10-17", "Statement": [
  { "Effect": "Allow", "Action": ["s3:GetBucketLocation","s3:ListBucket"], "Resource": ["arn:aws:s3:::tf-state"] },
  { "Effect": "Allow", "Action": ["s3:GetObject","s3:PutObject","s3:DeleteObject"], "Resource": ["arn:aws:s3:::tf-state/*"] }
] }
JSON
# read-only auditor: list + get on everything, no writes.
on $H "cat > /tmp/p-ro.json" <<'JSON'
{ "Version": "2012-10-17", "Statement": [
  { "Effect": "Allow", "Action": ["s3:GetObject","s3:ListBucket","s3:GetBucketLocation"], "Resource": ["arn:aws:s3:::*","arn:aws:s3:::*/*"] }
] }
JSON
on $H "mc admin policy create local tf-state-rw /tmp/p-tfstate.json >/dev/null 2>&1 || true
       mc admin policy create local readonly-all /tmp/p-ro.json   >/dev/null 2>&1 || true
       mc admin user add local terraform-ci  'Tf-St4te-RW-2026!'  >/dev/null 2>&1 || true
       mc admin user add local audit-ro       'Aud1t-R0-2026!'    >/dev/null 2>&1 || true
       mc admin policy attach local tf-state-rw --user terraform-ci >/dev/null 2>&1 || true
       mc admin policy attach local readonly-all --user audit-ro    >/dev/null 2>&1 || true
       rm -f /tmp/p-*.json"
say "minio: done"
