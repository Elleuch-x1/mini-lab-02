#!/usr/bin/env bash
# GitLab seed — TEAM BETA. Group + project w/ passing CI (shell runner) + users. Mostly-secure baseline.
. "$(dirname "$0")/lib.sh"
say "gitlab(beta): group, project, CI, users"
H="$HOST_GITLAB"
GLURL="http://gitlab.${LABDOMAIN:-minilab2.lab}"
PAT=glpat-minilab2automation01

# admin PAT (fixed) + users in ONE gitlab-rails call (Rails startup is ~90s; don't pay it 3x)
on "$H" "gitlab-rails runner \"
  r=User.find_by_username('root'); t=r.personal_access_tokens.find_or_initialize_by(name:'automation'); t.scopes=['api']; t.expires_at=365.days.from_now; t.set_token('$PAT'); t.save!;
  ['carol','dave'].each { |n| u=User.find_by_username(n) || User.new; u.username=n; u.name=n; u.email=\\\"#{n}@minilab2.lab\\\"; u.password='Dev-'+n+'-2026!'; u.password_confirmation='Dev-'+n+'-2026!'; u.skip_confirmation!; u.save! }
\" >/dev/null 2>&1"

gl(){ curl -sS -H "PRIVATE-TOKEN: $PAT" "$@"; }
# group beta + projects
gl -X POST "$GLURL/api/v4/groups" -d "name=beta" -d "path=beta" -d "visibility=private" >/dev/null 2>&1
GID=$(gl "$GLURL/api/v4/groups?search=beta" | jq -r '.[0].id' 2>/dev/null)
for p in web-store infra-beta; do
  gl -X POST "$GLURL/api/v4/projects" -d "name=$p" -d "path=$p" -d "namespace_id=$GID" -d "visibility=private" -d "initialize_with_readme=true" >/dev/null 2>&1
done

# passing CI on web-store (shell runner)
PID=$(gl "$GLURL/api/v4/projects?search=web-store" | jq -r '.[0].id' 2>/dev/null)
BR=$(gl "$GLURL/api/v4/projects/$PID" | jq -r '.default_branch // "main"')
CI='stages: [build, test]
build:
  stage: build
  tags: [shell]
  script: ["echo building web-store", "date"]
test:
  stage: test
  tags: [shell]
  script: ["echo tests passed"]'
gl -X POST "$GLURL/api/v4/projects/$PID/repository/files/.gitlab-ci.yml" \
  --data-urlencode "branch=$BR" --data-urlencode "content=$CI" \
  --data-urlencode "commit_message=add CI" >/dev/null 2>&1 \
|| gl -X PUT "$GLURL/api/v4/projects/$PID/repository/files/.gitlab-ci.yml" \
  --data-urlencode "branch=$BR" --data-urlencode "content=$CI" \
  --data-urlencode "commit_message=update CI" >/dev/null 2>&1
say "gitlab(beta): done (group beta, projects web-store/infra-beta)"
