#!/usr/bin/env bash
# k8s baseline — per-team namespaces + least-privilege RBAC + ServiceAccounts + a Kyverno baseline
# policy that ENFORCES (no privileged / hostPath). This is the mostly-secure foundation; the
# K8S-*/POL-* scenarios introduce deliberate gaps on top. Multi-team: alpha, beta, platform.
. "$(dirname "$0")/lib.sh"
say "k8s: per-team namespaces + RBAC + Kyverno baseline"
K="k3s kubectl"

on "$HOST_K8S" "cat <<'YML' | $K apply -f -
apiVersion: v1
kind: Namespace
metadata: { name: alpha, labels: { team: alpha } }
---
apiVersion: v1
kind: Namespace
metadata: { name: beta, labels: { team: beta } }
---
apiVersion: v1
kind: Namespace
metadata: { name: platform, labels: { team: platform } }
---
# per-team CI service accounts
apiVersion: v1
kind: ServiceAccount
metadata: { name: alpha-ci, namespace: alpha }
---
apiVersion: v1
kind: ServiceAccount
metadata: { name: beta-ci, namespace: beta }
---
# least-privilege: a CI SA may manage ONLY workloads in its own namespace
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: { name: ci-deployer, namespace: alpha }
rules:
  - apiGroups: ['apps','']
    resources: ['deployments','services','configmaps','pods']
    verbs: ['get','list','watch','create','update','patch']
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: { name: alpha-ci-deployer, namespace: alpha }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: ci-deployer }
subjects: [{ kind: ServiceAccount, name: alpha-ci, namespace: alpha }]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: { name: ci-deployer, namespace: beta }
rules:
  - apiGroups: ['apps','']
    resources: ['deployments','services','configmaps','pods']
    verbs: ['get','list','watch','create','update','patch']
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: { name: beta-ci-deployer, namespace: beta }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: ci-deployer }
subjects: [{ kind: ServiceAccount, name: beta-ci, namespace: beta }]
YML"

# Kyverno baseline: ENFORCE no privileged containers / hostPath (the POL-3/K8S scenarios punch a gap)
on "$HOST_K8S" "cat <<'YML' | $K apply -f -
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
say "k8s: done"
