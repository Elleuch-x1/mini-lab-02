#!/usr/bin/env bash
# healthcheck.sh — runs ON edge; probes every mini-lab-02 service over the VPC. Used by `lab status`.
. "$(dirname "$0")/lib.sh" 2>/dev/null || { OPKEY=/opt/minilab2/op.key; SSHO="ssh -i $OPKEY -o StrictHostKeyChecking=no -o ConnectTimeout=10"; HOST_K8S=k8s; }
PASS=0; FAIL=0
ok(){ printf '  \033[1;32mok\033[0m  %-12s %s\n' "$1" "$2"; PASS=$((PASS+1)); }
no(){ printf '  \033[1;31mX\033[0m   %-12s %s\n' "$1" "$2"; FAIL=$((FAIL+1)); }
http(){ local n="$1" u="$2" re="${3:-200}"; local c
  c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$u" 2>/dev/null)
  [[ "$c" =~ ^($re)$ ]] && ok "$n" "$u -> $c" || no "$n" "$u -> ${c:-timeout}"; }

echo "[health] service endpoints"
http gitea     "http://gitea:3000/api/v1/version"            "200"
http gitlab    "http://gitlab/users/sign_in"                 "200|302"
http atlantis  "http://atlantis:4141/healthz"                "200"
http minio     "http://minio:9000/minio/health/live"         "200"
http vault     "http://vault:8200/v1/sys/health"             "200|429|472|473|501"
http registry  "http://registry:5000/v2/"                    "200|401"
http mirror    "http://mirror:8080/"                         "200|403|404"
http argocd    "http://argocd:30080/"                        "200|307|308|302"
http app       "http://app/"                                  "200|403|404"
http grafana   "http://grafana:3000/api/health"             "200"

echo "[health] k8s / gitops / policy"
if $SSHO root@"$HOST_K8S" 'k3s kubectl get nodes --no-headers 2>/dev/null | grep -q " Ready "'; then ok "k3s-node" "Ready"; else no "k3s-node" "not Ready"; fi
if $SSHO root@"$HOST_K8S" 'k3s kubectl -n flux-system get deploy source-controller >/dev/null 2>&1'; then ok "flux" "controllers present"; else no "flux" "missing"; fi
if $SSHO root@"$HOST_K8S" 'k3s kubectl -n kyverno get deploy kyverno-admission-controller >/dev/null 2>&1'; then ok "kyverno" "admission present"; else no "kyverno" "missing"; fi
if $SSHO root@"$HOST_K8S" 'k3s kubectl -n argocd get deploy argocd-server >/dev/null 2>&1'; then ok "argocd" "server present"; else no "argocd" "missing"; fi

echo
printf '[health] %d ok, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
