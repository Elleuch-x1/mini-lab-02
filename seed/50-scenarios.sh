#!/usr/bin/env bash
# 50-scenarios.sh — apply ENABLED attack scenarios (hardened->vulnerable) + plant flags.
# A scenario sc_<id> runs only if `scenario_on <id>` AND the function exists. Implementations are
# added incrementally (M2) and each is verified by an actual exploit playthrough (verify/).
. "$(dirname "$0")/lib.sh"
say "scenarios: applying enabled toggles for profile=$PROFILE"
say "enabled: $(tr '\n' ' ' < "$ENABLED_FILE" 2>/dev/null)"

# ---- helpers shared by scenarios ----
gc(){ git -c user.email=atk@minilab2.lab -c user.name=atk "$@"; }
gclone_alpha(){ git clone -q "http://$ADMIN_USER:$ADMIN_PASS@gitea:3000/alpha/$1.git" "$2" 2>/dev/null; }

# ========================= scenario implementations (M2) =========================
# (added one track at a time; see SCENARIOS.md for the catalog)
#   PPE-*, PBAC-*, SUP-*, SEC-*, K8S-*, TF-*, POL-*

# ---- TF-4: writable state + scheduled apply (deployer) -> poisoned module executes ----
sc_tf_4(){
  say "TF-4 writable state + scheduled apply (deployer identity)"
  on "$HOST_TFEXEC" "echo '$(flag tf_4-state-poisoning)' > /home/deployer/flag.txt; chown deployer:deployer /home/deployer/flag.txt; chmod 600 /home/deployer/flag.txt"
  # deployer automation holds a gitea deploy credential (clone private alpha/infra + fetch module)
  on "$HOST_TFEXEC" "printf 'http://%s:%s@gitea:3000\n' '$ADMIN_USER' '$ADMIN_PASS' > /home/deployer/.git-credentials; \
    chown deployer:deployer /home/deployer/.git-credentials; chmod 600 /home/deployer/.git-credentials; \
    su deployer -c 'git config --global credential.helper store; git config --global user.email deployer@minilab2.lab; git config --global user.name deployer'"
  on "$HOST_TFEXEC" "cat > /usr/local/bin/iac-apply.sh <<'SH'
#!/usr/bin/env bash
# scheduled drift-correction: pull alpha/infra + apply from the MinIO-backed state (as deployer)
export HOME=/home/deployer
cd /opt/iac || exit 0
[ -d infra/.git ] || git clone -q http://gitea:3000/alpha/infra.git infra 2>/dev/null
cd infra && git pull -q 2>/dev/null
export AWS_ACCESS_KEY_ID=alpha-ci AWS_SECRET_ACCESS_KEY='alpha-St4te-2026!'
/usr/local/bin/terraform init -input=false -reconfigure >/tmp/iac-apply.log 2>&1
/usr/local/bin/terraform apply -input=false -auto-approve >>/tmp/iac-apply.log 2>&1
SH
chmod +x /usr/local/bin/iac-apply.sh; chown deployer:deployer /usr/local/bin/iac-apply.sh"
  on "$HOST_TFEXEC" "( crontab -u deployer -l 2>/dev/null | grep -v iac-apply; echo '*/10 * * * * /usr/local/bin/iac-apply.sh' ) | crontab -u deployer -"
}

# ---- dispatcher ----
ALL="ppe_1 ppe_2 ppe_3 pbac_1 pbac_2 pbac_3 pbac_4 sup_1 sup_2 sup_3 sup_4 sec_1 sec_2 \
     k8s_1 k8s_2 k8s_3 k8s_4 tf_1 tf_2 tf_3 tf_4 tf_5 tf_6 pol_1 pol_2 pol_3"
for s in $ALL; do
  if scenario_on "$s"; then
    if declare -f "sc_${s}" >/dev/null 2>&1; then "sc_${s}" || say "WARN: sc_${s} had errors"
    else say "NOTE: $s enabled but not yet implemented"; fi
  fi
done
say "scenarios: done"
