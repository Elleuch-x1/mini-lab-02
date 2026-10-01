#!/usr/bin/env bash
# 70-blue.sh — BLUE-TEAM infra (M4): ship logs from every host to Loki via promtail + enable k3s
# audit logging. Makes the detection exercises (BLUE-1..6) solvable against live data.
. "$(dirname "$0")/lib.sh"
say "blue: promtail shippers + k3s audit"
LOKI_URL="http://loki:3100/loki/api/v1/push"
PV="3.1.1"

# install_promtail <host> <extra scrape_configs YAML (already indented under scrape_configs)>
install_promtail(){
  local host="$1" extra="$2"
  on "$host" "bash -s" <<EOF
set -e
if ! command -v promtail >/dev/null 2>&1; then
  command -v unzip >/dev/null 2>&1 || { apt-get update -y >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y unzip >/dev/null 2>&1; }
  cd /tmp; curl -sL https://github.com/grafana/loki/releases/download/v$PV/promtail-linux-amd64.zip -o p.zip
  unzip -o p.zip >/dev/null 2>&1; install -m755 promtail-linux-amd64 /usr/local/bin/promtail; rm -f p.zip promtail-linux-amd64
fi
install -d -m755 /var/lib/promtail /etc/promtail
cat > /etc/promtail/config.yml <<CFG
server: { http_listen_port: 9080, grpc_listen_port: 0 }
positions: { filename: /var/lib/promtail/positions.yaml }
clients:
  - url: $LOKI_URL
scrape_configs:
  - job_name: journal
    journal:
      max_age: 12h
      labels: { job: journal, host: $host }
    relabel_configs:
      - source_labels: ['__journal__systemd_unit']
        target_label: unit
$extra
CFG
cat > /etc/systemd/system/promtail.service <<SVC
[Unit]
Description=Promtail
After=network-online.target
[Service]
ExecStart=/usr/local/bin/promtail -config.file=/etc/promtail/config.yml
Restart=always
[Install]
WantedBy=multi-user.target
SVC
systemctl daemon-reload; systemctl enable promtail >/dev/null 2>&1; systemctl restart promtail
EOF
}

# --- k3s audit logging (for BLUE-4) ---
on "$HOST_K8S" "bash -s" <<'EOF'
set -e
cat > /etc/rancher/k3s/audit.yaml <<'POL'
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Metadata
POL
cat > /etc/rancher/k3s/config.yaml <<'CFG'
kube-apiserver-arg:
  - "audit-log-path=/var/log/k3s-audit.log"
  - "audit-policy-file=/etc/rancher/k3s/audit.yaml"
  - "audit-log-maxage=2"
  - "audit-log-maxbackup=2"
CFG
grep -q 'audit-log-path' /var/log/k3s-audit.log 2>/dev/null || { systemctl restart k3s; sleep 10; }
EOF

# --- per-host file scrapes ---
install_promtail gitea '  - job_name: gitea-actions
    static_configs:
      - targets: [localhost]
        labels: { job: gitea-actions, host: gitea, __path__: /var/lib/gitea/data/actions_log/**/*.log }'

install_promtail gitlab '  - job_name: gitlab-rails
    static_configs:
      - targets: [localhost]
        labels: { job: gitlab-rails, host: gitlab, __path__: /var/log/gitlab/gitlab-rails/*.log }'

install_promtail backend '  - job_name: mirror-access
    static_configs:
      - targets: [localhost]
        labels: { job: mirror-access, host: backend, __path__: /var/log/nginx/access.log }'

install_promtail atlantis ''
install_promtail runner ''
install_promtail registry ''

install_promtail k8s '  - job_name: k8s-audit
    static_configs:
      - targets: [localhost]
        labels: { job: k8s-audit, host: k8s, __path__: /var/log/k3s-audit.log }'

say "blue: shippers up (journal on all; gitea-actions/gitlab-rails/mirror-access/k8s-audit files)"
