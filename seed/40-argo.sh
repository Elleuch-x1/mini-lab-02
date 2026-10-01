#!/usr/bin/env bash
# Argo CD seed (team alpha GitOps): register the private gitea repo (by IP — repo-server uses cluster
# DNS which can't resolve the host alias) + an Application syncing alpha/app deploy/ -> ns alpha.
. "$(dirname "$0")/lib.sh"
say "argo: alpha GitOps app"
H="$HOST_K8S"
K="k3s kubectl"
GIP="$(getent hosts gitea | awk '{print $1}' | head -1)"
[ -n "$GIP" ] || { say "argo: cannot resolve gitea IP"; exit 1; }
REPO="http://$GIP:3000/alpha/app.git"
say "argo: using repo $REPO"

on $H "cat <<'YML' | $K apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: repo-alpha-app
  namespace: argocd
  labels: { argocd.argoproj.io/secret-type: repository }
stringData:
  type: git
  url: $REPO
  username: $ADMIN_USER
  password: $ADMIN_PASS
YML"

on $H "$K get ns alpha >/dev/null 2>&1 || $K create ns alpha >/dev/null
cat <<'YML' | $K apply -f -
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: alpha-app
  namespace: argocd
spec:
  project: default
  source:
    repoURL: $REPO
    targetRevision: main
    path: deploy
  destination:
    server: https://kubernetes.default.svc
    namespace: alpha
  syncPolicy:
    automated: { prune: true, selfHeal: true }
    syncOptions: [CreateNamespace=true]
YML"
say "argo: done"
