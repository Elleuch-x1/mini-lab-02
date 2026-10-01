#!/usr/bin/env bash
# blue.sh — BLUE-TEAM detection + hardening checks (M4). Runs on the edge AFTER the attacks
# (verify/playthrough.sh) so the signals are in Loki. BLUE-1..5 are LogQL detections; BLUE-6
# hardens one misconfig and re-verifies the kill-chain is closed.
OP=/opt/minilab2/op.key
S="ssh -i $OP -o StrictHostKeyChecking=no -o ConnectTimeout=15"
on(){ h="$1"; shift; $S root@"$h" "$@"; }
PASS=0; FAIL=0; declare -a FAILED
ok(){ printf '  \033[1;32mPASS\033[0m %-7s %s\n' "$1" "$2"; PASS=$((PASS+1)); }
no(){ printf '  \033[1;31mFAIL\033[0m %-7s %s\n' "$1" "$2"; FAIL=$((FAIL+1)); FAILED+=("$1"); }

# loki_has <id> <desc> <logql>  — PASS if the query returns >=1 log line in the last 2h
loki_has(){
  local id="$1" desc="$2" q="$3" start n
  start=$(( ($(date +%s) - 7200) * 1000000000 ))
  n=$(curl -sG "http://loki:3100/loki/api/v1/query_range" \
        --data-urlencode "query=$q" --data-urlencode "start=$start" --data-urlencode "limit=5" 2>/dev/null \
      | python3 -c "import sys,json
try:
  d=json.load(sys.stdin); print(sum(len(r.get('values',[])) for r in d.get('data',{}).get('result',[])))
except: print(0)" 2>/dev/null)
  if [ "${n:-0}" -ge 1 ]; then ok "$id" "$desc ($n hits)"; else no "$id" "$desc (no hits) :: $q"; fi
}

echo "### BLUE-TEAM detections (Loki) ###"

# BLUE-1 — pipeline injection in Gitea Actions logs (ppe_1/ppe_3 rendered malicious run: steps)
loki_has BLUE-1 "detect PPE/injection in CI logs" \
  '{job="gitea-actions"} |~ "ppe1-proof|ppe3-proof|/opt/minilab2/ppe"'

# BLUE-2 — rogue-runner registration + CI_JOB_TOKEN use in GitLab audit (gitlab-rails)
loki_has BLUE-2 "detect rogue-runner / CI_JOB_TOKEN in GitLab audit" \
  '{job="gitlab-rails"} |~ "/api/v4/user/runners|job_token|ci_job_token"'

# BLUE-3 — malicious dependency / image pull via the internal mirror + registry logs
loki_has BLUE-3 "detect malicious dep pull (mirror)" \
  '{job="mirror-access"} |~ "alpha_utils|9.9.9"'
loki_has BLUE-3b "detect poisoned image push/pull (registry)" \
  '{host="registry"} |~ "alpha/web|manifests|blobs"'

# BLUE-4 — k8s RBAC escalation / cross-team secret read in the audit log
loki_has BLUE-4 "detect k8s RBAC escalation in audit log" \
  '{job="k8s-audit"} |~ "rbac-crown|clusterrolebindings|pods/exec|crown"'

# BLUE-5 — unexpected Atlantis plan/apply (state tampering path)
loki_has BLUE-5 "detect unexpected atlantis plan/apply" \
  '{host="atlantis"} |~ "atlantis.yaml|[Pp]lan|[Aa]pply|workflow"'

echo "### BLUE-6 harden & re-verify (close pol_3) ###"
# restore the STRICT Kyverno policy (no namespace exclusion), then prove the privileged pod is DENIED
on k8s "cat <<'YML' | k3s kubectl apply -f - >/dev/null 2>&1
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata: { name: baseline-restrict }
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: no-privileged
      match: { any: [{ resources: { kinds: ['Pod'] } }] }
      validate:
        message: 'privileged containers are not allowed'
        pattern:
          spec:
            =(containers):
              - =(securityContext):
                  =(privileged): 'false'
    - name: no-hostpath
      match: { any: [{ resources: { kinds: ['Pod'] } }] }
      validate:
        message: 'hostPath volumes are not allowed'
        pattern:
          spec:
            =(volumes):
              - X(hostPath): 'null'
YML"
sleep 3
deny=$(on k8s "k3s kubectl -n alpha delete pod pol3-reverify --ignore-not-found >/dev/null 2>&1
cat <<'POD' | k3s kubectl apply -f - 2>&1
apiVersion: v1
kind: Pod
metadata: { name: pol3-reverify, namespace: alpha }
spec:
  restartPolicy: Never
  containers:
    - name: x
      image: busybox:1.36
      securityContext: { privileged: true }
      command: ['sh','-c','cat /host/pol3-flag.txt']
      volumeMounts: [{ name: h, mountPath: /host }]
  volumes:
    - name: h
      hostPath: { path: /opt/minilab2 }
POD")
if echo "$deny" | grep -qiE "denied|blocked|not allowed|admission webhook"; then
  ok BLUE-6 "pol_3 hardened: privileged pod DENIED by Kyverno"
else
  no BLUE-6 "pol_3 still admits the pod: $(echo "$deny" | tr -d '\n' | head -c120)"
fi

echo
printf '### blue-team: %d passed, %d failed ###\n' "$PASS" "$FAIL"
[ "$FAIL" -gt 0 ] && echo "FAILED: ${FAILED[*]}"
exit 0
