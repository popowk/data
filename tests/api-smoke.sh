#!/usr/bin/env bash
set -euo pipefail
mkdir -p storage
cat >storage/config.php <<'EOF'
<?php return ['db_host'=>'127.0.0.1','db_port'=>3306,'db_name'=>'phonehub_ci','db_user'=>'root','db_pass'=>'ci_password'];
EOF
php -S 127.0.0.1:18765 -t . >/tmp/phonehub-ci-server.log 2>&1 &
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
grep -q '系统更新' "$adminHtml"
curl -fsS -b "$adminCookies" 'http://127.0.0.1:18765/index.php?view=diagnostics' -o "$adminHtml"
grep -q '复制完整报告' "$adminHtml"
reportJson=$(curl -fsS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=diagnostic_report")
TEST_RESPONSE="$reportJson" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); r=j.get("report",""); assert j["ok"] and "PhoneHub 故障诊断报告" in r and "MySQL 版本" in r and len(r)<8000 and isinstance(j.get("checks"),list),j'
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
if ((int)$r["ci_open_plan_user"]!==1 || (int)$r["ci_dynamic_plan_user"]!==7) exit(3);
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
curl -fsS -b "$adminCookies" 'http://127.0.0.1:18765/index.php?view=backup_keys' -o "$adminHtml"
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
TEST_RESPONSE="$bound" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and j["bound"] and j["imei_bound"],j'
php -r '
require "app/core.php";require "app/devices.php";
$cfg=require "storage/config.php";
$p=new PDO("mysql:host=".$cfg["db_host"].";port=".$cfg["db_port"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$row=$p->query("SELECT imei_encrypted,phone_number_encrypted,phone_number_hash,phone_model FROM phonehub_mobile_devices WHERE phone_id=REPEAT(CHAR(98),64) LIMIT 1")->fetch(PDO::FETCH_ASSOC);
if(!$row || $row["phone_model"]!=="Test Galaxy" || $row["imei_encrypted"]==="490154203237518" ||
    device_decrypt($row["imei_encrypted"])!=="490154203237518" ||
    device_decrypt($row["phone_number_encrypted"])!=="+8613912345678" ||
    $row["phone_number_hash"]!==device_phone_hash("+8613912345678")) exit(3);
'

after=$(api package "{\"device_id\":\"$DEVICE\",\"package_id\":\"douyin\"}")
TEST_RESPONSE="$after" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and "envelope" in j,j'
listed=$(api mobile_list "{\"device_id\":\"$DEVICE\"}")
TEST_RESPONSE="$listed" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and j["active_count"]==1 and j["devices"][0]["imei_bound"],j'
# A number-only blacklist must reject bound devices without blocking other identifiers.
php -r '
require "app/core.php"; require "app/devices.php";
$cfg=require "storage/config.php";
$p=new PDO("mysql:host=".$cfg["db_host"].";port=".$cfg["db_port"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$hash=device_phone_hash("+8613912345678");
$p->prepare("INSERT INTO phonehub_mobile_blacklist(identifier_type,identifier_hash,reason,enabled,created_by) VALUES(?,?,?,1,0)")->execute(["phone_hash",$hash,"CI number block"]);
'
numberBlocked=$(api mobile_check "{\"device_id\":\"$DEVICE\",\"phone_id\":\"$PHONE\"}")
TEST_RESPONSE="$numberBlocked" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert not j["ok"] and j["error_code"]=="DEVICE_BLACKLISTED",j'
php -r '
$cfg=require "storage/config.php";
$p=new PDO("mysql:host=".$cfg["db_host"].";port=".$cfg["db_port"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$p->exec("UPDATE phonehub_mobile_blacklist SET enabled=0 WHERE identifier_type=\x27phone_hash\x27 AND reason=\x27CI number block\x27");
'

# Lowering a mobile quota must prevent excess, newer devices from passing mobile_check.
php -r '
$cfg=require "storage/config.php";
$p=new PDO("mysql:host=".$cfg["db_host"].";port=".$cfg["db_port"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$p->exec("UPDATE phonehub_user_meta SET mobile_limit=1 WHERE user_id=1");
$s=$p->prepare("INSERT INTO phonehub_mobile_devices(user_id,phone_id,display_name,enabled,last_seen) VALUES(1,?,?,1,UTC_TIMESTAMP())");
$s->execute([str_repeat("c",64),"CI excess phone"]);
'
firstAllowed=$(api mobile_check "{\"device_id\":\"$DEVICE\",\"phone_id\":\"$PHONE\"}")
TEST_RESPONSE="$firstAllowed" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and j["bound"],j'
excessDenied=$(api mobile_check "{\"device_id\":\"$DEVICE\",\"phone_id\":\"$(printf 'c%.0s' {1..64})\"}")
TEST_RESPONSE="$excessDenied" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and not j["bound"],j'
php -r '
$cfg=require "storage/config.php";
$p=new PDO("mysql:host=".$cfg["db_host"].";port=".$cfg["db_port"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$p->exec("UPDATE phonehub_user_meta SET mobile_limit=8 WHERE user_id=1");
$p->exec("DELETE FROM phonehub_mobile_devices WHERE phone_id=REPEAT(CHAR(99),64)");
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
# Blacklist the keyed IMEI digest. Raw IMEI is never stored in the blacklist.
php -r '
define("APP_STORE",getcwd()."/storage");
require "app/mobile.php";
$cfg=require "storage/config.php";
$pdo=new PDO("mysql:host=".$cfg["db_host"].";port=".$cfg["db_port"].";dbname=".$cfg["db_name"].";charset=utf8mb4",$cfg["db_user"],$cfg["db_pass"]);
$hash=mobile_imei_hash("490154203237518");
$s=$pdo->prepare("INSERT INTO phonehub_mobile_blacklist(identifier_type,identifier_hash,reason,enabled,created_by) VALUES(?,?,?,1,0)");
$s->execute(["imei_hash",$hash,"CI blacklist"]);
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
echo 'PASS: authenticated mobile/model/IMEI/phone ciphertext, phone and computer blacklist, authorization, logs and signed updates'
