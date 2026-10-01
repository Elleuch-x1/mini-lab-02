#!/usr/bin/env bash
# Argo CD seed: register the (private) gitea repo + a sample Application doing GitOps onto k3s.
# NOTE: Argo's repo-server runs inside k3s and uses CLUSTER DNS, which does NOT know the host
# /etc/hosts alias "gitea". So we use gitea's resolved IP in the repo URLs (reachable from pods
# via the node). The IP is recomputed every seed, so it stays correct across lab up/down.
. "$(dirname "$0")/lib.sh"
say "argo: repo credential + sample Application"
H=k8s
K="k3s kubectl"
GIP="$(getent hosts gitea | awk '{print $1}' | head -1)"
[ -n "$GIP" ] || { say "argo: cannot resolve gitea IP"; exit 1; }
REPO="http://$GIP:3000/vultara/coffeeshop-api.git"
say "argo: using repo $REPO"

# declarative private-repo registration (labeled secret in argocd ns)
on $H "cat <<'YML' | $K apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: repo-coffeeshop-api
  namespace: argocd
  labels: { argocd.argoproj.io/secret-type: repository }
stringData:
  type: git
  url: $REPO
  username: $ADMIN_USER
  password: $ADMIN_PASS
YML"

# target namespace + the Application (auto-sync + prune + selfHeal)
on $H "$K get ns coffeeshop >/dev/null 2>&1 || $K create ns coffeeshop >/dev/null
cat <<'YML' | $K apply -f -
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: coffeeshop-api
  namespace: argocd
spec:
  project: default
  source:
    repoURL: $REPO
    targetRevision: main
    path: deploy
  destination:
    server: https://kubernetes.default.svc
    namespace: coffeeshop
  syncPolicy:
    automated: { prune: true, selfHeal: true }
    syncOptions: [CreateNamespace=true]
YML"
say "argo: done"
