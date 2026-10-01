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
