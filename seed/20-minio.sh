#!/usr/bin/env bash
# MinIO seed (multi-team): per-team state buckets + per-team scoped keys (ENFORCED isolation).
# Baseline = each team's CI key can touch ONLY its own bucket. TF-3 (cross-team state) is the gap
# the attacker must pivot to reach the other team's bucket.
. "$(dirname "$0")/lib.sh"
say "minio: per-team state buckets + scoped keys"
H="$HOST_MINIO"
on $H "mc alias set local http://127.0.0.1:9000 '$MINIO_USER' '$MINIO_PASS' >/dev/null 2>&1"
on $H "mc mb -p local/tf-state-alpha local/tf-state-beta local/artifacts >/dev/null 2>&1; \
       mc version enable local/tf-state-alpha >/dev/null 2>&1 || true; \
       mc version enable local/tf-state-beta  >/dev/null 2>&1 || true"

# sample state per team (so buckets aren't empty)
for t in alpha beta; do
  on $H "printf '{\"version\":4,\"terraform_version\":\"1.9.8\",\"serial\":1,\"lineage\":\"%s-state\",\"outputs\":{},\"resources\":[]}' '$t' > /tmp/st-$t.json; \
         mc cp /tmp/st-$t.json local/tf-state-$t/prod/terraform.tfstate >/dev/null 2>&1; rm -f /tmp/st-$t.json"
done

# per-team policies: RW ONLY that team's bucket; per-team CI access keys
for t in alpha beta; do
  pw="${t}-St4te-2026!"
  on $H "cat > /tmp/p-$t.json" <<JSON
{ "Version":"2012-10-17","Statement":[
  { "Effect":"Allow","Action":["s3:GetBucketLocation","s3:ListBucket"],"Resource":["arn:aws:s3:::tf-state-$t"] },
  { "Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:DeleteObject"],"Resource":["arn:aws:s3:::tf-state-$t/*"] }
] }
JSON
  on $H "mc admin policy create local ${t}-state-rw /tmp/p-$t.json >/dev/null 2>&1 || true; \
         mc admin user add local ${t}-ci '$pw' >/dev/null 2>&1 || true; \
         mc admin policy attach local ${t}-state-rw --user ${t}-ci >/dev/null 2>&1 || true; \
         rm -f /tmp/p-$t.json"
done
say "minio: done"
