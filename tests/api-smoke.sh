#!/usr/bin/env bash
set -euo pipefail
trap 'echo "CI HTTP smoke failed at ${BASH_SOURCE[0]} line ${LINENO}" >&2' ERR
mkdir -p storage
cat >storage/config.php <<'EOF'
<?php return ['db_host'=>'127.0.0.1','db_port'=>3306,'db_name'=>'phonehub_ci','db_user'=>'root','db_pass'=>'ci_password'];
EOF
PHONEHUB_PERF_SAMPLE_PERCENT=100 PHONEHUB_AUTOMATION_TEST_ALLOW_HTTP=1 php -S 127.0.0.1:18765 -t . >/tmp/phonehub-ci-server.log 2>&1 &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true; rm -f storage/config.php' EXIT
for i in $(seq 1 40); do
  if curl -fsS 'http://127.0.0.1:18765/api/phonehub.php?action=health' >/dev/null 2>&1; then break; fi
  sleep 0.5
done
# Render the PHP management entry point and authenticated update page. This catches
# the class of post-update 500 errors caused by a missing app/accounts.php.
adminHtml=$(mktemp)
adminCookies=$(mktemp)
curl -fsS -c "$adminCookies" 'http://127.0.0.1:18765/index.php?view=update' -o "$adminHtml"
grep -q '登录管理后台' "$adminHtml"
CSRF=$(python3 -c 'import re,sys; s=open(sys.argv[1],encoding="utf-8").read(); m=re.search(r"name=.csrf. content=.([0-9a-f]{64}).",s); assert m; print(m.group(1))' "$adminHtml")
adminLogin=$(curl -fsS -b "$adminCookies" -c "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=login" \
  --data-urlencode "username=ci_ai_owner" --data-urlencode "password=ci-owner-test-123456")
TEST_RESPONSE="$adminLogin" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"],j'
curl -fsS -b "$adminCookies" 'http://127.0.0.1:18765/index.php?view=update' -o "$adminHtml"
grep -q '系统维护' "$adminHtml"
grep -q '运行环境自检' "$adminHtml"
grep -q 'Curve25519 备份密钥' "$adminHtml"
if grep -q 'href="?view=gateway"\|href="?view=backup_keys"\|href="?view=group_bulk"' "$adminHtml"; then
  echo 'obsolete duplicate or gateway menu still visible' >&2; exit 1
fi
curl -fsS -b "$adminCookies" 'http://127.0.0.1:18765/index.php?view=groups' -o "$adminHtml"
grep -q '客户分组与批量配置' "$adminHtml"
grep -q 'id="group-bulk-form"' "$adminHtml"
grep -q 'id="group-list"' "$adminHtml"
for retired_alias in 'group_bulk|groups#group-bulk' 'backup_keys|update#maintenance-backup'; do
  alias_page="${retired_alias%%|*}"
  target="${retired_alias#*|}"
  redirect=$(curl -sS -b "$adminCookies" -o /dev/null -w '%{http_code} %{redirect_url}' "http://127.0.0.1:18765/index.php?view=$alias_page")
  [[ "$redirect" == 302*"$target"* ]] || { echo "Merged admin route $alias_page not redirected: $redirect" >&2;exit 1; }
done
retired_page_status=$(curl -sS -b "$adminCookies" -o "$adminHtml" -w '%{http_code}' 'http://127.0.0.1:18765/index.php?view=gateway')
test "$retired_page_status" = 404 || { echo 'Retired gateway route still reachable' >&2;exit 1; }
retired_action_status=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
    --data-urlencode "csrf=$CSRF" --data-urlencode 'action=gateway_install' -o "$adminHtml" -w '%{http_code}')
test "$retired_action_status" = 403 || { echo 'Retired gateway action still callable' >&2;exit 1; }
python3 -c 'import json,sys; j=json.load(open(sys.argv[1]));assert not j["ok"],j' "$adminHtml"
# Consolidated pages: old owner links redirect, and the combined views render.
aiRedirect=$(curl -sS -b "$adminCookies" -o /dev/null -w '%{http_code} %{redirect_url}' 'http://127.0.0.1:18765/index.php?view=ai')
[[ "$aiRedirect" == 302*cloud_features* ]] || { echo 'AI view did not redirect to capability management' >&2; exit 1; }
packageRedirect=$(curl -sS -b "$adminCookies" -o /dev/null -w '%{http_code} %{redirect_url}' 'http://127.0.0.1:18765/index.php?view=packages')
[[ "$packageRedirect" == 302*releases* ]] || { echo 'Legacy package owner view did not redirect' >&2; exit 1; }
curl -fsS -b "$adminCookies" 'http://127.0.0.1:18765/index.php?view=cloud_features' -o "$adminHtml"
grep -q '客户端能力与 AI' "$adminHtml"
grep -q '服务端 AI 中转' "$adminHtml"
curl -fsS -b "$adminCookies" 'http://127.0.0.1:18765/index.php?view=releases' -o "$adminHtml"
grep -q '操作包管理中心' "$adminHtml"
grep -q 'data-ajax="package_publish"' "$adminHtml"
# Owner uploads encrypted JSON (not a ZIP) without exposing the 32-byte key.
operationFixture=$(mktemp)
invalidFixture=$(mktemp)
python3 - "$operationFixture" <<'PY'
import base64,json,os,sys
b=lambda data:base64.b64encode(data).decode('ascii')
payload={
  'package_id':'douyin','version':2,
  'envelope':{
    'manifest':b(b'{"format":1,"platform":"douyin","version":2}'),
    'signature':b(os.urandom(64)),'nonce':b(os.urandom(24)),
    'ciphertext':b(os.urandom(96))
  },
  'content_key':b(os.urandom(32))
}
open(sys.argv[1],'w').write(json.dumps(payload))
PY
printf '{"envelope":"not-an-object","content_key":"unsafe"}' > "$invalidFixture"
operationCreated=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --form "csrf=$CSRF" --form 'action=package_publish' \
  --form 'package_id=douyin' --form 'version=2' \
  --form "file=@$operationFixture;filename=ci-encrypted.json;type=application/json")
export TEST_RESPONSE="$operationCreated"
operationId=$(python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert j["ok"] and j["package_id"]=="douyin" and j["version"]==2 and j["id"]>0 and "content_key" not in str(j) and "envelope" not in j,j;print(j["id"])')
operationDuplicate=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --form "csrf=$CSRF" --form 'action=package_publish' \
  --form 'package_id=douyin' --form 'version=2' \
  --form "file=@$operationFixture;filename=ci-encrypted.json;type=application/json")
TEST_RESPONSE="$operationDuplicate" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert not j["ok"] and "已存在" in j["error"],j'
operationBad=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --form "csrf=$CSRF" --form 'action=package_publish' \
  --form 'package_id=douyin' --form 'version=3' \
  --form "file=@$invalidFixture;filename=broken.json;type=application/json")
TEST_RESPONSE="$operationBad" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert not j["ok"],j'
rm -f "$operationFixture" "$invalidFixture"
operationDisabled=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode 'action=package_toggle' \
  --data-urlencode "id=$operationId")
TEST_RESPONSE="$operationDisabled" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert j["ok"] and j["enabled"]==0,j'
operationEnabled=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode 'action=package_toggle' \
  --data-urlencode "id=$operationId")
TEST_RESPONSE="$operationEnabled" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert j["ok"] and j["enabled"]==1,j'
curl -fsS -b "$adminCookies" 'http://127.0.0.1:18765/index.php?view=releases' -o "$adminHtml"
grep -q 'v2' "$adminHtml"
grep -q '停用' "$adminHtml"
if grep -q 'name="content_key"\|name="envelope"' "$adminHtml"; then
  echo 'Encrypted secrets must not be editable or visible in admin HTML' >&2; exit 1
fi
curl -fsS -b "$adminCookies" 'http://127.0.0.1:18765/index.php?view=devices' -o "$adminHtml"
if grep -q '<th>IMEI</th>\|<th>手机号</th>\|name="phone_number"\|name="imei"\|data-action="device-reveal"' "$adminHtml"; then
  echo 'Sensitive device controls were not removed' >&2; exit 1
fi

runtimeJson=$(curl -fsS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=update_diagnostics")
TEST_RESPONSE="$runtimeJson" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and isinstance(j.get("checks"),list) and isinstance(j.get("summary"),dict),j'
curl -fsS -b "$adminCookies" 'http://127.0.0.1:18765/index.php?view=update' -o "$adminHtml"
grep -q '运行环境自检' "$adminHtml"
if grep -q '复制故障报告' "$adminHtml"; then echo 'legacy diagnostic link is still present' >&2; exit 1; fi
curl -fsS -b "$adminCookies" 'http://127.0.0.1:18765/index.php?view=diagnostics' -o "$adminHtml"
if grep -q '<h1>故障诊断</h1>' "$adminHtml"; then echo 'diagnostic page is still available' >&2; exit 1; fi
removedReport=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=diagnostic_report")
TEST_RESPONSE="$removedReport" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert not j["ok"],j'
planCreated=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=account_save" \
  --data-urlencode "username=ci_open_plan_user" --data-urlencode "opening_plan=personal" \
  --data-urlencode "device_limit=99" --data-urlencode "mobile_limit=999" \
  --data-urlencode "enabled=on" --data-urlencode "entitlements[]=douyin")
TEST_RESPONSE="$planCreated" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and j["id"]>0 and len(j["password"])>=12,j'
php -r '
$cfg=require "storage/config.php";
$p=new PDO("mysql:host=".$cfg["db_host"].";port=".$cfg["db_port"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$s=$p->query("SELECT u.device_limit,m.mobile_limit,m.opening_plan_code FROM phonehub_users u JOIN phonehub_user_meta m ON m.user_id=u.id WHERE u.username=CHAR(99,105,95,111,112,101,110,95,112,108,97,110,95,117,115,101,114)");
$row=$s->fetch(PDO::FETCH_ASSOC);
if (!$row || (int)$row["device_limit"]!==1 || (int)$row["mobile_limit"]!==1 || $row["opening_plan_code"]!=="personal") exit(2);
'
# HTTP regression: owner creates a read-only administrator. Its authenticated
# GET and forged POST paths must both be blocked by server-side permissions.
viewerCreated=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=admin_create" \
  --data-urlencode "username=ci_readonly_operator" --data-urlencode "role=viewer")
viewerPassword=$(TEST_RESPONSE="$viewerCreated" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and len(j["password"])>=12,j; print(j["password"])')
viewerCookies=$(mktemp)
viewerHtml=$(mktemp)
curl -fsS -c "$viewerCookies" 'http://127.0.0.1:18765/index.php' -o "$viewerHtml"
viewerCsrf=$(python3 -c 'import re,sys; s=open(sys.argv[1]).read(); m=re.search(r"name=.csrf. content=.([0-9a-f]{64}).",s); assert m; print(m.group(1))' "$viewerHtml")
viewerLogin=$(curl -sS -b "$viewerCookies" -c "$viewerCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$viewerCsrf" --data-urlencode "action=login" \
  --data-urlencode "username=ci_readonly_operator" --data-urlencode "password=$viewerPassword")
TEST_RESPONSE="$viewerLogin" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"],j'
curl -fsS -b "$viewerCookies" 'http://127.0.0.1:18765/index.php?view=packages' -o "$viewerHtml"
grep -q '操作包管理中心' "$viewerHtml"
if grep -q 'data-ajax="package_publish"\|data-action="package-toggle"' "$viewerHtml"; then
  echo 'Read-only account can see package write controls' >&2; exit 1
fi
for action in package_toggle package_publish; do
  denied=$(curl -sS -b "$viewerCookies" -o "$viewerHtml" -w '%{http_code}' -X POST 'http://127.0.0.1:18765/index.php' \
    --data-urlencode "csrf=$viewerCsrf" --data-urlencode "action=$action" \
    --data-urlencode "id=$operationId")
  test "$denied" = 403 || { echo "Unauthorized package operation $action allowed: $denied" >&2;exit 1; }
done
curl -fsS -b "$viewerCookies" 'http://127.0.0.1:18765/index.php?view=accounts' -o "$viewerHtml"
grep -q '只读查看，不允许修改授权' "$viewerHtml"
if grep -q 'data-action="new-account"' "$viewerHtml"; then echo "viewer can see account editor" >&2; exit 9; fi
for page in admins devices audit update group_bulk; do
  status=$(curl -sS -b "$viewerCookies" -o "$viewerHtml" -w '%{http_code}' "http://127.0.0.1:18765/index.php?view=$page")
  test "$status" = 403 || { echo "viewer GET bypassed $page ($status)" >&2; exit 9; }
done
for operation in group_create account_save group_bulk_preview plan_save backup_key_generate update_apply device_reveal; do
  status=$(curl -sS -b "$viewerCookies" -o "$viewerHtml" -w '%{http_code}' \
    -X POST 'http://127.0.0.1:18765/index.php' \
    --data-urlencode "csrf=$viewerCsrf" --data-urlencode "action=$operation" \
    --data-urlencode "name=forbidden_group" --data-urlencode "username=forbidden_account")
  test "$status" = 403 || { echo "viewer POST bypassed $operation ($status)" >&2; exit 9; }
  python3 -c 'import json,sys; j=json.load(open(sys.argv[1])); assert not j["ok"] and "无权" in j["error"],j' "$viewerHtml"
done
viewerLogout=$(curl -sS -b "$viewerCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$viewerCsrf" --data-urlencode "action=logout")
TEST_RESPONSE="$viewerLogout" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"],j'
rm -f "$viewerCookies" "$viewerHtml"
# Existing normal administrators retain the previous authorization maintenance
# capability, while owner-only operations remain forbidden through direct POST.
normalCreated=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=admin_create" \
  --data-urlencode "username=ci_normal_operator" --data-urlencode "role=admin")
normalPassword=$(TEST_RESPONSE="$normalCreated" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"],j; print(j["password"])')
normalCookies=$(mktemp)
normalHtml=$(mktemp)
curl -fsS -c "$normalCookies" 'http://127.0.0.1:18765/index.php' -o "$normalHtml"
normalCsrf=$(python3 -c 'import re,sys; s=open(sys.argv[1]).read(); m=re.search(r"name=.csrf. content=.([0-9a-f]{64}).",s); assert m; print(m.group(1))' "$normalHtml")
normalLogin=$(curl -sS -b "$normalCookies" -c "$normalCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$normalCsrf" --data-urlencode "action=login" \
  --data-urlencode "username=ci_normal_operator" --data-urlencode "password=$normalPassword")
TEST_RESPONSE="$normalLogin" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"],j'
allowedWrite=$(curl -sS -b "$normalCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$normalCsrf" --data-urlencode "action=group_create" \
  --data-urlencode "name=CI Normal Admin Allowed Group")
TEST_RESPONSE="$allowedWrite" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"],j'
status=$(curl -sS -b "$normalCookies" -o "$normalHtml" -w '%{http_code}' \
  -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$normalCsrf" --data-urlencode "action=plan_save" \
  --data-urlencode "name=Forbidden plan" --data-urlencode "device_limit=2")
test "$status" = 403
python3 -c 'import json,sys; j=json.load(open(sys.argv[1])); assert not j["ok"],j' "$normalHtml"
rm -f "$normalCookies" "$normalHtml"
# Owner-managed templates apply only to newly created accounts; edits and
# deactivations must not retroactively alter existing authorizations.
curl -fsS -b "$adminCookies" 'http://127.0.0.1:18765/index.php?view=plans' -o "$adminHtml"
grep -q '套餐管理' "$adminHtml"
newPlan=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=plan_save" \
  --data-urlencode "name=CI Enterprise" --data-urlencode "device_limit=7" \
  --data-urlencode "mobile_limit=11" --data-urlencode "sort_order=90")
planId=$(TEST_RESPONSE="$newPlan" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"],j; print(j["id"])')
planCode=$(PLAN_ID="$planId" php -r '
$cfg=require "storage/config.php";
$p=new PDO("mysql:host=".$cfg["db_host"].";port=".$cfg["db_port"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$s=$p->prepare("SELECT plan_code FROM phonehub_plan_templates WHERE id=?");
$s->execute([(int)getenv("PLAN_ID")]);echo $s->fetchColumn();
')
newAccount=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=account_save" \
  --data-urlencode "username=ci_dynamic_plan_user" --data-urlencode "opening_plan=$planCode" \
  --data-urlencode "device_limit=99" --data-urlencode "mobile_limit=999" \
  --data-urlencode "enabled=on")
TEST_RESPONSE="$newAccount" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and j["id"]>0,j'
planEdited=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=plan_save" \
  --data-urlencode "id=$planId" --data-urlencode "name=CI Enterprise Renamed" \
  --data-urlencode "device_limit=12" --data-urlencode "mobile_limit=19" --data-urlencode "sort_order=91")
TEST_RESPONSE="$planEdited" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"],j'
PLAN_CODE="$planCode" php -r '
$cfg=require "storage/config.php";
$p=new PDO("mysql:host=".$cfg["db_host"].";port=".$cfg["db_port"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$s=$p->prepare("SELECT u.device_limit,m.mobile_limit,m.opening_plan_code FROM phonehub_users u JOIN phonehub_user_meta m ON m.user_id=u.id WHERE u.username=?");
$s->execute(["ci_dynamic_plan_user"]);$row=$s->fetch(PDO::FETCH_ASSOC);
if(!$row || (int)$row["device_limit"]!==7 || (int)$row["mobile_limit"]!==11 || $row["opening_plan_code"]!==getenv("PLAN_CODE"))exit(2);
'
planToggle=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=plan_toggle" --data-urlencode "id=$planId")
TEST_RESPONSE="$planToggle" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"],j'
disabledPlanAttempt=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=account_save" \
  --data-urlencode "username=ci_disabled_plan_user" --data-urlencode "opening_plan=$planCode")
TEST_RESPONSE="$disabledPlanAttempt" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert not j["ok"] and "套餐" in j["error"],j'
# Filtered customer listing: real server SQL filtering, not a browser-only hide.
curl -fsS -b "$adminCookies" 'http://127.0.0.1:18765/index.php?view=accounts&q=ci_open_plan_user&plan=personal' -o "$adminHtml"
grep -q 'ci_open_plan_user' "$adminHtml"
grep -q '每页 30 位' "$adminHtml"
curl -fsS -b "$adminCookies" 'http://127.0.0.1:18765/index.php?view=accounts&q=ci_nonexistent_user' -o "$adminHtml"
grep -q '没有符合条件的客户' "$adminHtml"


# Existing customer plan reassignment: only a changed preset overrides forged quotas.
# The account_save path remains usable for clients that omit opening_plan.
planSwitchId=$(TEST_RESPONSE="$planCreated" python3 -c 'import os,json; print(json.loads(os.environ["TEST_RESPONSE"])["id"])')
curl -fsS -b "$adminCookies" 'http://127.0.0.1:18765/index.php?view=accounts&q=ci_open_plan_user' -o "$adminHtml"
grep -q '客户套餐（创建后可修改）' "$adminHtml"
grep -q 'opening_plan_code' "$adminHtml"
switchedAccount=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=account_save" \
  --data-urlencode "id=$planSwitchId" --data-urlencode "username=ci_open_plan_user" \
  --data-urlencode "opening_plan=standard" --data-urlencode "device_limit=99" \
  --data-urlencode "mobile_limit=999" --data-urlencode "enabled=on" \
  --data-urlencode "entitlements[]=douyin")
TEST_RESPONSE="$switchedAccount" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"],j'
PLAN_USER_ID="$planSwitchId" php -r '
$cfg=require "storage/config.php";$p=new PDO("mysql:host=".$cfg["db_host"].";port=".$cfg["db_port"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$s=$p->prepare("SELECT u.device_limit,m.mobile_limit,m.opening_plan_code,u.entitlements FROM phonehub_users u JOIN phonehub_user_meta m ON m.user_id=u.id WHERE u.id=?");$s->execute([(int)getenv("PLAN_USER_ID")]);$r=$s->fetch(PDO::FETCH_ASSOC);
if(!$r || (int)$r["device_limit"]!==3 || (int)$r["mobile_limit"]!==5 || $r["opening_plan_code"]!=="standard" || json_decode($r["entitlements"],true)!==["douyin"])exit(2);
$s=$p->prepare("SELECT COUNT(*) FROM phonehub_admin_audit WHERE action=? AND target LIKE ?");$s->execute(["account_plan_change","ci_open_plan_user personal -> standard%"]);if((int)$s->fetchColumn()<1) {
  $rows=$p->query("SELECT action,target FROM phonehub_admin_audit ORDER BY id DESC LIMIT 8")->fetchAll(PDO::FETCH_ASSOC);
  fwrite(STDERR,"Missing expected plan audit: ".json_encode($rows,JSON_UNESCAPED_UNICODE)."\n");
  exit(3);
}
'
# Same-plan saves allow manual quota edits, and legacy edits with the field
# omitted must preserve the current stored plan label.
samePlanEdit=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=account_save" \
  --data-urlencode "id=$planSwitchId" --data-urlencode "username=ci_open_plan_user" \
  --data-urlencode "opening_plan=standard" --data-urlencode "device_limit=4" \
  --data-urlencode "mobile_limit=6" --data-urlencode "enabled=on" \
  --data-urlencode "entitlements[]=douyin")
TEST_RESPONSE="$samePlanEdit" python3 -c 'import os,json; assert json.loads(os.environ["TEST_RESPONSE"])["ok"]'
legacyEdit=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=account_save" \
  --data-urlencode "id=$planSwitchId" --data-urlencode "username=ci_open_plan_user" \
  --data-urlencode "device_limit=4" --data-urlencode "mobile_limit=6" \
  --data-urlencode "enabled=on" --data-urlencode "entitlements[]=douyin")
TEST_RESPONSE="$legacyEdit" python3 -c 'import os,json; assert json.loads(os.environ["TEST_RESPONSE"])["ok"]'
PLAN_USER_ID="$planSwitchId" php -r '
$cfg=require "storage/config.php";$p=new PDO("mysql:host=".$cfg["db_host"].";port=".$cfg["db_port"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$s=$p->prepare("SELECT u.device_limit,m.mobile_limit,m.opening_plan_code FROM phonehub_users u JOIN phonehub_user_meta m ON m.user_id=u.id WHERE u.id=?");$s->execute([(int)getenv("PLAN_USER_ID")]);$r=$s->fetch(PDO::FETCH_ASSOC);
if(!$r || (int)$r["device_limit"]!==4 || (int)$r["mobile_limit"]!==6 || $r["opening_plan_code"]!=="standard")exit(2);
'
# A disabled template cannot be assigned to another customer by forged POST.
illegalPlanEdit=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=account_save" \
  --data-urlencode "id=$planSwitchId" --data-urlencode "username=ci_open_plan_user" \
  --data-urlencode "opening_plan=$planCode" --data-urlencode "device_limit=1" \
  --data-urlencode "mobile_limit=1" --data-urlencode "enabled=on")
TEST_RESPONSE="$illegalPlanEdit" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert not j["ok"] and "套餐" in j["error"],j'
# Historical disabled plan may remain on the same user without resetting quota.
originalDynamicId=$(TEST_RESPONSE="$newAccount" python3 -c 'import os,json; print(json.loads(os.environ["TEST_RESPONSE"])["id"])')
inactivePlanEdit=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=account_save" \
  --data-urlencode "id=$originalDynamicId" --data-urlencode "username=ci_dynamic_plan_user" \
  --data-urlencode "opening_plan=$planCode" --data-urlencode "device_limit=7" \
  --data-urlencode "mobile_limit=11" --data-urlencode "enabled=on")
TEST_RESPONSE="$inactivePlanEdit" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"],j'
# Custom means intentionally user-specified limits and updated plan label.
customPlanEdit=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=account_save" \
  --data-urlencode "id=$planSwitchId" --data-urlencode "username=ci_open_plan_user" \
  --data-urlencode "opening_plan=custom" --data-urlencode "device_limit=2" \
  --data-urlencode "mobile_limit=8" --data-urlencode "enabled=on" \
  --data-urlencode "entitlements[]=douyin")
TEST_RESPONSE="$customPlanEdit" python3 -c 'import os,json; assert json.loads(os.environ["TEST_RESPONSE"])["ok"]'
PLAN_USER_ID="$planSwitchId" php -r '
$cfg=require "storage/config.php";$p=new PDO("mysql:host=".$cfg["db_host"].";port=".$cfg["db_port"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$s=$p->prepare("SELECT u.device_limit,m.mobile_limit,m.opening_plan_code FROM phonehub_users u JOIN phonehub_user_meta m ON m.user_id=u.id WHERE u.id=?");$s->execute([(int)getenv("PLAN_USER_ID")]);$r=$s->fetch(PDO::FETCH_ASSOC);
if(!$r || (int)$r["device_limit"]!==2 || (int)$r["mobile_limit"]!==8 || $r["opening_plan_code"]!=="custom")exit(2);
'

# Bulk authorization: server preview, reject stale member snapshot, then apply
# the same request after fresh preview. No production data is used.
groupCreated=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=group_create" \
  --data-urlencode "name=CI Bulk Preview Group")
TEST_RESPONSE="$groupCreated" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"],j'
groupId=$(php -r '
$cfg=require "storage/config.php";
$p=new PDO("mysql:host=".$cfg["db_host"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$s=$p->query("SELECT id FROM phonehub_groups WHERE name=CHAR(67,73,32,66,117,108,107,32,80,114,101,118,105,101,119,32,71,114,111,117,112)");
echo $s->fetchColumn();
')
GROUP_ID="$groupId" php -r '
$cfg=require "storage/config.php";
$p=new PDO("mysql:host=".$cfg["db_host"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$s=$p->prepare("UPDATE phonehub_user_meta m JOIN phonehub_users u ON u.id=m.user_id SET m.group_id=? WHERE u.username=?");
$s->execute([(int)getenv("GROUP_ID"),"ci_open_plan_user"]);
'
preview=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=group_bulk_preview" \
  --data-urlencode "group_id=$groupId" --data-urlencode "apply_device_limit=on" --data-urlencode "device_limit=6")
snapshot=$(TEST_RESPONSE="$preview" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and j["members"]==1 and "电脑名额" in j["fields"] and len(j["snapshot"])==64,j; print(j["snapshot"])')
# Change membership between preview and apply: must reject and not update.
GROUP_ID="$groupId" php -r '
$cfg=require "storage/config.php";
$p=new PDO("mysql:host=".$cfg["db_host"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$s=$p->prepare("UPDATE phonehub_user_meta m JOIN phonehub_users u ON u.id=m.user_id SET m.group_id=? WHERE u.username=?");
$s->execute([(int)getenv("GROUP_ID"),"ci_dynamic_plan_user"]);
'
stale=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=group_bulk" \
  --data-urlencode "group_id=$groupId" --data-urlencode "apply_device_limit=on" \
  --data-urlencode "device_limit=6" --data-urlencode "preview_snapshot=$snapshot")
TEST_RESPONSE="$stale" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert not j["ok"] and "分组成员" in j["error"],j'
php -r '
$cfg=require "storage/config.php";
$p=new PDO("mysql:host=".$cfg["db_host"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$r=$p->query("SELECT username,device_limit FROM phonehub_users WHERE username IN (CHAR(99,105,95,111,112,101,110,95,112,108,97,110,95,117,115,101,114),CHAR(99,105,95,100,121,110,97,109,105,99,95,112,108,97,110,95,117,115,101,114)) ORDER BY username")->fetchAll(PDO::FETCH_KEY_PAIR);
if ((int)$r["ci_open_plan_user"]!==2 || (int)$r["ci_dynamic_plan_user"]!==7) exit(3);
'
fresh=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=group_bulk_preview" \
  --data-urlencode "group_id=$groupId" --data-urlencode "apply_device_limit=on" --data-urlencode "device_limit=6")
freshSnapshot=$(TEST_RESPONSE="$fresh" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and j["members"]==2,j; print(j["snapshot"])')
applied=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=group_bulk" \
  --data-urlencode "group_id=$groupId" --data-urlencode "apply_device_limit=on" \
  --data-urlencode "device_limit=6" --data-urlencode "preview_snapshot=$freshSnapshot")
TEST_RESPONSE="$applied" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and "2" in j["message"],j'
GROUP_ID="$groupId" php -r '
$cfg=require "storage/config.php";
$p=new PDO("mysql:host=".$cfg["db_host"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$s=$p->prepare("SELECT u.device_limit FROM phonehub_users u JOIN phonehub_user_meta m ON m.user_id=u.id WHERE m.group_id=?");
$s->execute([(int)getenv("GROUP_ID")]);
$v=$s->fetchAll(PDO::FETCH_COLUMN);
if(count($v)!==2 || array_filter($v,static fn($x)=>(int)$x!==6)) exit(4);
'
# A backup decryption key can be downloaded only once by the owner.
curl -fsS -b "$adminCookies" 'http://127.0.0.1:18765/index.php?view=update' -o "$adminHtml"
grep -q 'Curve25519' "$adminHtml"
downloadedKey=$(mktemp)
downloadHeaders=$(mktemp)
curl -fsS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=backup_key_generate" \
  -D "$downloadHeaders" -o "$downloadedKey"
test "$(wc -c < "$downloadedKey")" -eq 32
test "$(wc -c < storage/backup-recipient.pub)" -eq 32
grep -qi 'application/octet-stream' "$downloadHeaders"
BACKUP_KEY_FILE="$downloadedKey" php -r '
$public=file_get_contents("storage/backup-recipient.pub");
$secret=file_get_contents(getenv("BACKUP_KEY_FILE"));
$sample="ci-backup-roundtrip";
$sealed=sodium_crypto_box_seal($sample,$public);
$pair=sodium_crypto_box_keypair_from_secretkey_and_publickey($secret,$public);
if(sodium_crypto_box_seal_open($sealed,$pair)!==$sample)exit(3);
'
secondAttempt=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=backup_key_generate")
TEST_RESPONSE="$secondAttempt" python3 -c 'import json,os; j=json.loads(os.environ["TEST_RESPONSE"]); assert not j["ok"],j'
rm -f "$downloadedKey" "$downloadHeaders" storage/backup-recipient.pub
echo 'CI HTTP smoke: entering automation scenarios'
source tests/automation-smoke.sh
echo 'CI HTTP smoke: client log filters and 50-record pagination'
source tests/client-log-smoke.sh
rm -f "$adminCookies" "$adminHtml"
BASE='http://127.0.0.1:18765/api/phonehub.php?action='
DEVICE='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
PHONE='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
login=$(curl -fsS -X POST "$BASE""login" -H 'Content-Type: application/json' \
  --data "{\"username\":\"phonehub_ci_user\",\"password\":\"test-secret-123456\",\"device_id\":\"$DEVICE\"}")
export TEST_LOGIN="$login"
TOKEN=$(python3 -c 'import os,json; x=json.loads(os.environ["TEST_LOGIN"]); assert x["ok"]; print(x["token"])')
api() {
  local action="$1"; shift
  curl -sS -X POST "$BASE$action" -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $TOKEN" --data "$*"
}
before=$(api package "{\"device_id\":\"$DEVICE\",\"package_id\":\"douyin\"}")
TEST_RESPONSE="$before" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] is False and "绑定" in j["error"],j'
bound=$(api mobile_bind "{\"device_id\":\"$DEVICE\",\"phone_id\":\"$PHONE\",\"display_name\":\"CI Android\",\"phone_model\":\"Test Galaxy\",\"phone_number\":\"+8613912345678\",\"imei\":\"490154203237518\"}")
TEST_RESPONSE="$bound" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and j["bound"] and "imei_bound" not in j and "phone_number_bound" not in j,j'
# New binding and repeated legacy heartbeat must ignore sensitive fields.
php -r '
$cfg=require "storage/config.php";
$p=new PDO("mysql:host=".$cfg["db_host"].";port=".$cfg["db_port"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$r=$p->query("SELECT imei_hash,imei_encrypted,phone_number_hash,phone_number_encrypted,phone_model FROM phonehub_mobile_devices WHERE phone_id=REPEAT(CHAR(98),64) LIMIT 1")->fetch(PDO::FETCH_ASSOC);
if (!$r || $r["phone_model"]!=="Test Galaxy" || $r["imei_hash"]!==null || $r["imei_encrypted"]!==null ||
    $r["phone_number_hash"]!==null || $r["phone_number_encrypted"]!==null) exit(3);
'
legacyIdentityHeartbeat=$(api mobile_heartbeat "{\"device_id\":\"$DEVICE\",\"phone_id\":\"$PHONE\",\"imei\":\"490154203237518\",\"phone_number\":\"13912345678\"}")
TEST_RESPONSE="$legacyIdentityHeartbeat" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and j["bound"] and "imei_bound" not in j and "phone_number_bound" not in j,j'
legacyIdentityCheck=$(api mobile_check "{\"device_id\":\"$DEVICE\",\"phone_id\":\"$PHONE\",\"imei\":\"490154203237520\"}")
TEST_RESPONSE="$legacyIdentityCheck" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and j["bound"] and "imei_bound" not in j,j'
php -r '
$cfg=require "storage/config.php";
$p=new PDO("mysql:host=".$cfg["db_host"].";port=".$cfg["db_port"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$r=$p->query("SELECT imei_hash,imei_encrypted,phone_number_hash,phone_number_encrypted FROM phonehub_mobile_devices WHERE phone_id=REPEAT(CHAR(98),64) LIMIT 1")->fetch(PDO::FETCH_ASSOC);
if (!$r || array_filter(array_values($r),static fn($v)=>$v!==null)) exit(4);
'

after=$(api package "{\"device_id\":\"$DEVICE\",\"package_id\":\"douyin\"}")
TEST_RESPONSE="$after" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and "envelope" in j,j'
TEST_RESPONSE="$after" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert j["ok"] and len(j["envelope"]["nonce"])>12 and len(j["content_key"])>=43,j'
# The download audit is keyed by package ID; older records do not identify version.
php -r '
$cfg=require "storage/config.php";
$p=new PDO("mysql:host=".$cfg["db_host"].";port=".$cfg["db_port"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$count=$p->query("SELECT COUNT(*) FROM phonehub_package_downloads WHERE package_id=CHAR(100,111,117,121,105,110)")->fetchColumn();
if ((int)$count<1) exit(4);
'

# Old heartbeat keeps its legacy field names, new batch validates each phone.
legacyHeartbeat=$(api client_heartbeat "{\"device_id\":\"$DEVICE\"}")
TEST_RESPONSE="$legacyHeartbeat" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and "batch" not in j and "features" in j,j'
batchHeartbeat=$(api client_heartbeat "{\"device_id\":\"$DEVICE\",\"batch\":{\"phones\":[{\"phone_id\":\"$PHONE\"}],\"package_versions\":{\"douyin\":0}}}")
TEST_RESPONSE="$batchHeartbeat" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); b=j["batch"]; p=b["phones"]; a=b["ai"]; packs=b["packages"]; assert j["ok"] and "computer" in j and "session_expires_at" in j and len(p)==1 and p[0]["bound"] and p[0]["status"]=="bound",j; assert any(x["package_id"]=="douyin" and x["download_allowed"] and x["update_available"] for x in packs),j; assert set(a)=={"enabled","server_mode_available","client_key_allowed"},j; assert "content_key" not in str(b) and "envelope" not in str(b) and "api_key" not in str(b),j'
batchNoPhone=$(api client_heartbeat "{\"device_id\":\"$DEVICE\",\"batch\":{\"phones\":[],\"package_versions\":{\"douyin\":0}}}")
TEST_RESPONSE="$batchNoPhone" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and j["batch"]["phones"]==[] and not any(x["download_allowed"] for x in j["batch"]["packages"]),j'
unknownPhone=$(printf 'd%.0s' {1..64})
batchUnknown=$(api client_heartbeat "{\"device_id\":\"$DEVICE\",\"batch\":{\"phones\":[{\"phone_id\":\"$unknownPhone\"}],\"package_versions\":{\"douyin\":0}}}")
TEST_RESPONSE="$batchUnknown" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and not j["batch"]["phones"][0]["bound"] and j["batch"]["phones"][0]["status"]=="not_bound" and not any(x["download_allowed"] for x in j["batch"]["packages"]),j'
# Retired identity fields in old batch payloads are ignored.
legacyBatch=$(api client_heartbeat "{\"device_id\":\"$DEVICE\",\"batch\":{\"phones\":[{\"phone_id\":\"$PHONE\",\"imei\":\"490154203237520\",\"phone_number\":\"13912345679\"}],\"package_versions\":{\"douyin\":0}}}")
TEST_RESPONSE="$legacyBatch" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); p=j["batch"]["phones"][0]; assert j["ok"] and p["bound"] and p["status"]=="bound" and "imei_bound" not in p,j'
batchDuplicate=$(api client_heartbeat "{\"device_id\":\"$DEVICE\",\"batch\":{\"phones\":[{\"phone_id\":\"$PHONE\"},{\"phone_id\":\"$PHONE\"}]}}")
TEST_RESPONSE="$batchDuplicate" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert not j["ok"] and j["error_code"]=="DUPLICATE_PHONE_ID",j'
batchBadVersion=$(api client_heartbeat "{\"device_id\":\"$DEVICE\",\"batch\":{\"phones\":[],\"package_versions\":{\"douyin\":\"not-an-int\"}}}")
TEST_RESPONSE="$batchBadVersion" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert not j["ok"] and j["error_code"]=="INVALID_PACKAGE_VERSION",j'
tooMany=$(python3 -c 'import json; print(json.dumps({"device_id":"a"*64,"batch":{"phones":[{"phone_id":format(i,"064x")} for i in range(9)]}}))')
batchTooMany=$(api client_heartbeat "$tooMany")
TEST_RESPONSE="$batchTooMany" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert not j["ok"] and j["error_code"]=="HEARTBEAT_BATCH_LIMIT",j'
listed=$(api mobile_list "{\"device_id\":\"$DEVICE\"}")
TEST_RESPONSE="$listed" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and j["active_count"]==1 and "imei_bound" not in j["devices"][0],j'
# Historical hashed bans on existing rows continue to work without
# exposing old IMEI/number creation APIs.
php -r '
$cfg=require "storage/config.php";
$p=new PDO("mysql:host=".$cfg["db_host"].";port=".$cfg["db_port"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$hash=hash("sha256","historical-row-fixture");
$p->prepare("UPDATE phonehub_mobile_devices SET phone_number_hash=? WHERE phone_id=?")
  ->execute([$hash,str_repeat("b",64)]);
$p->prepare("INSERT INTO phonehub_mobile_blacklist(identifier_type,identifier_hash,reason,enabled,created_by) VALUES(?,?,?,1,0)")
  ->execute(["phone_hash",$hash,"CI historical block"]);
'
numberBlocked=$(api mobile_check "{\"device_id\":\"$DEVICE\",\"phone_id\":\"$PHONE\"}")
TEST_RESPONSE="$numberBlocked" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert not j["ok"] and j["error_code"]=="DEVICE_BLACKLISTED",j'
batchBlocked=$(api client_heartbeat "{\"device_id\":\"$DEVICE\",\"batch\":{\"phones\":[{\"phone_id\":\"$PHONE\"}],\"package_versions\":{\"douyin\":0}}}")
TEST_RESPONSE="$batchBlocked" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); p=j["batch"]["phones"][0]; assert j["ok"] and not p["bound"] and p["status"]=="blacklisted",j'
php -r '
$cfg=require "storage/config.php";
$p=new PDO("mysql:host=".$cfg["db_host"].";port=".$cfg["db_port"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$p->prepare("UPDATE phonehub_mobile_blacklist SET enabled=0 WHERE identifier_type=? AND reason=?")->execute(["phone_hash","CI historical block"]);
'
# Lowering a mobile quota must prevent excess, newer devices from passing mobile_check.
php -r '
$cfg=require "storage/config.php";
$p=new PDO("mysql:host=".$cfg["db_host"].";port=".$cfg["db_port"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$account=$p->prepare("SELECT id FROM phonehub_users WHERE username=?");
$account->execute(["phonehub_ci_user"]);
$customerId=(int)$account->fetchColumn();
if($customerId<1) exit(2);
$p->prepare("UPDATE phonehub_user_meta SET mobile_limit=1 WHERE user_id=?")->execute([$customerId]);
$s=$p->prepare("INSERT INTO phonehub_mobile_devices(user_id,phone_id,display_name,enabled,last_seen) VALUES(?,?,?,1,UTC_TIMESTAMP())");
$s->execute([$customerId,str_repeat("c",64),"CI excess phone"]);
'
firstAllowed=$(api mobile_check "{\"device_id\":\"$DEVICE\",\"phone_id\":\"$PHONE\"}")
TEST_RESPONSE="$firstAllowed" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and j["bound"],j'
excessDenied=$(api mobile_check "{\"device_id\":\"$DEVICE\",\"phone_id\":\"$(printf 'c%.0s' {1..64})\"}")
TEST_RESPONSE="$excessDenied" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and not j["bound"],j'

excessPhone=$(printf 'c%.0s' {1..64})
batchQuota=$(api client_heartbeat "{\"device_id\":\"$DEVICE\",\"batch\":{\"phones\":[{\"phone_id\":\"$PHONE\"},{\"phone_id\":\"$excessPhone\"}],\"package_versions\":{\"douyin\":0}}}")
TEST_RESPONSE="$batchQuota" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); p=j["batch"]["phones"]; assert j["ok"] and len(p)==2 and p[0]["bound"] and p[0]["status"]=="bound" and not p[1]["bound"] and p[1]["status"]=="quota_exceeded",j'
php -r '
$cfg=require "storage/config.php";
$p=new PDO("mysql:host=".$cfg["db_host"].";port=".$cfg["db_port"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$account=$p->prepare("SELECT id FROM phonehub_users WHERE username=?");
$account->execute(["phonehub_ci_user"]);
$customerId=(int)$account->fetchColumn();
if($customerId<1) exit(2);
$p->prepare("UPDATE phonehub_user_meta SET mobile_limit=8 WHERE user_id=?")->execute([$customerId]);
$p->prepare("DELETE FROM phonehub_mobile_devices WHERE phone_id=? AND user_id=?")->execute([str_repeat("c",64),$customerId]);
'
# Capability discovery returns only true-valued fields; disabled keys are omitted.
for action in license_status capabilities client_config client_heartbeat; do
  cap=$(api "$action" "{\"device_id\":\"$DEVICE\"}")
  TEST_RESPONSE="$cap" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); f=j["features"]; assert j["ok"] and all(v is True for v in f.values()),j; assert not any(k in f for k in ("mcp_available","skill_available","mcp_codex_available","mcp_harness_available")),j'
done
# Positive permissions must appear as true; ungranted features remain entirely absent.
php -r '
$cfg=require "storage/config.php";
$p=new PDO("mysql:host=".$cfg["db_host"].";port=".$cfg["db_port"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$p->exec("UPDATE phonehub_users SET entitlements=\x27[\x22douyin\x22,\x22mcp\x22,\x22mcp-codex\x22]\x27 WHERE username=\x27phonehub_ci_user\x27");
$p->exec("UPDATE phonehub_feature_settings SET setting_value=\x271\x27 WHERE setting_key IN (\x27mcp_enabled\x27,\x27mcp_codex_enabled\x27)");
'
capEnabled=$(api capabilities "{\"device_id\":\"$DEVICE\"}")
TEST_RESPONSE="$capEnabled" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); f=j["features"]; assert f["mcp_available"] is True and f["mcp_codex_available"] is True and "mcp_harness_available" not in f and "skill_available" not in f and all(v is True for v in f.values()),j'
php -r '
$cfg=require "storage/config.php";
$p=new PDO("mysql:host=".$cfg["db_host"].";port=".$cfg["db_port"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$p->exec("UPDATE phonehub_users SET entitlements=\x27[\x22douyin\x22]\x27 WHERE username=\x27phonehub_ci_user\x27");
$p->exec("UPDATE phonehub_feature_settings SET setting_value=\x270\x27 WHERE setting_key IN (\x27mcp_enabled\x27,\x27mcp_codex_enabled\x27)");
'
mcpDisabled=$(api update_check "{\"device_id\":\"$DEVICE\",\"platform\":\"mcp\",\"channel\":\"stable\",\"current_version\":\"0.0.0\"}")
TEST_RESPONSE="$mcpDisabled" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert not j["ok"] and j["error_code"]=="FEATURE_DISABLED",j'
for platform in mcp-codex mcp-harness; do
  denied=$(api update_check "{\"device_id\":\"$DEVICE\",\"platform\":\"$platform\",\"channel\":\"stable\",\"current_version\":\"0.0.0\"}")
  TEST_RESPONSE="$denied" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert not j["ok"] and j["error_code"]=="FEATURE_DISABLED",j'
done
aiStatus=$(api ai_status "{\"device_id\":\"$DEVICE\"}")
TEST_RESPONSE="$aiStatus" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and j["enabled"] is True and "client_key_allowed" not in j and "server_mode_available" not in j and "server_key_configured" not in j,j'
byokDenied=$(api ai_chat "{\"device_id\":\"$DEVICE\",\"credential_mode\":\"client\",\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}]}")
TEST_RESPONSE="$byokDenied" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert not j["ok"] and j["error_code"]=="CLIENT_KEY_FORBIDDEN",j'
serverMissing=$(api ai_chat "{\"device_id\":\"$DEVICE\",\"credential_mode\":\"server\",\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}]}")
TEST_RESPONSE="$serverMissing" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert not j["ok"] and j["error_code"]=="AI_NOT_CONFIGURED",j'
logs=$(api log_batch "{\"device_id\":\"$DEVICE\",\"logs\":[{\"level\":\"info\",\"event\":\"ci\",\"message\":\"hello\"}]}")
TEST_RESPONSE="$logs" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and j["received"]==1,j'
update=$(api update_check "{\"device_id\":\"$DEVICE\",\"platform\":\"core\",\"channel\":\"stable\",\"current_version\":\"0.7.1\"}")
TEST_RESPONSE="$update" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and not j["available"],j'
read -r releaseId releaseHash <<< "$(php tests/seed-release.php | tr '|' ' ')"
newer=$(api update_check "{\"device_id\":\"$DEVICE\",\"platform\":\"core\",\"channel\":\"stable\",\"current_version\":\"0.7.1\"}")
TEST_RESPONSE="$newer" php -r '$j=json_decode(getenv("TEST_RESPONSE"),true);if(!$j["ok"]||!$j["available"])exit(1);$r=$j["release"];$pub=base64_decode($r["public_key"],true);$raw=base64_decode($r["manifest"],true);$signature=base64_decode($r["signature"],true);if(!sodium_crypto_sign_verify_detached($signature,$raw,$pub))exit(2);'
curl -fsS -X POST "$BASE""update_download" -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" -o /tmp/phonehub-ci-update.zip \
  --data "{\"device_id\":\"$DEVICE\",\"release_id\":$releaseId}"
actualHash=$(sha256sum /tmp/phonehub-ci-update.zip | cut -d ' ' -f1)
[ "$actualHash" = "$releaseHash" ] || { echo 'Signed update download has wrong SHA256';exit 1; }
rangeCode=$(curl -sS -w '%{http_code}' -X POST "$BASE""update_download" \
  -H 'Content-Type: application/json' -H 'Range: bytes=0-9' \
  -H "Authorization: Bearer $TOKEN" -o /tmp/phonehub-ci-range.bin \
  --data "{\"device_id\":\"$DEVICE\",\"release_id\":$releaseId}")
[ "$rangeCode" = 206 ] && [ "$(wc -c </tmp/phonehub-ci-range.bin)" = 10 ]
rm -f /tmp/phonehub-ci-update.zip /tmp/phonehub-ci-range.bin
# New blacklist action uses only phone fingerprint, not IMEI/SIM number.
php -r '
$cfg=require "storage/config.php";
$pdo=new PDO("mysql:host=".$cfg["db_host"].";port=".$cfg["db_port"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$s=$pdo->prepare("INSERT INTO phonehub_mobile_blacklist(identifier_type,identifier_hash,reason,enabled,created_by) VALUES(?,?,?,1,0)");
$s->execute(["phone_id",str_repeat("b",64),"CI fingerprint blacklist"]);
'
blocked=$(api mobile_check "{\"device_id\":\"$DEVICE\",\"phone_id\":\"$PHONE\"}")
TEST_RESPONSE="$blocked" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert not j["ok"] and j["error_code"]=="DEVICE_BLACKLISTED",j'
rebind=$(api mobile_bind "{\"device_id\":\"$DEVICE\",\"phone_id\":\"$PHONE\"}")
TEST_RESPONSE="$rebind" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert not j["ok"] and "拉黑" in j["error"],j'
blockedPackage=$(api package "{\"device_id\":\"$DEVICE\",\"package_id\":\"douyin\"}")
TEST_RESPONSE="$blockedPackage" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert not j["ok"] and "绑定" in j["error"],j'
unbound=$(api mobile_unbind "{\"device_id\":\"$DEVICE\",\"phone_id\":\"$PHONE\"}")
TEST_RESPONSE="$unbound" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and j["unbound"],j'
again=$(api package "{\"device_id\":\"$DEVICE\",\"package_id\":\"douyin\"}")
TEST_RESPONSE="$again" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] is False and "绑定" in j["error"],j'
devices=$(api device_list "{\"device_id\":\"$DEVICE\"}")
TEST_RESPONSE="$devices" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and len(j["devices"])>=1,j'
# Blacklisting a computer ID immediately rejects existing sessions and future logins.
php -r '
require "app/core.php"; require "app/devices.php";
$cfg=require "storage/config.php";
$p=new PDO("mysql:host=".$cfg["db_host"].";port=".$cfg["db_port"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
device_insert_blacklist($p,"computer_id",str_repeat("a",64),"CI computer block",0);
'
pcBlocked=$(api session "{\"device_id\":\"$DEVICE\"}")
TEST_RESPONSE="$pcBlocked" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert not j["ok"] and j["error"],j'
loginBlocked=$(curl -sS -X POST "$BASE""login" -H 'Content-Type: application/json' --data "{\"username\":\"phonehub_ci_user\",\"password\":\"test-secret-123456\",\"device_id\":\"$DEVICE\"}")
TEST_RESPONSE="$loginBlocked" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert not j["ok"] and "禁止" in j["error"],j'
# PHP timing telemetry must be opt-in, structured and free of client secrets.
grep -q 'PhoneHub heartbeat_perf status=200 ' /tmp/phonehub-ci-server.log
grep -q 'connect_ms=.*auth_ms=.*db_ms=.*package_ms=.*response_ms=' /tmp/phonehub-ci-server.log
if grep -Fq "$TOKEN" /tmp/phonehub-ci-server.log; then echo 'Bearer leaked to timing logs' >&2; exit 10; fi
echo 'PASS: authenticated mobile/model/IMEI/phone ciphertext, phone and computer blacklist, authorization, logs and signed updates + automation'
