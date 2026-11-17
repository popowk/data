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
TEST_RESPONSE="$reportJson" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); r=j.get("report",""); assert j["ok"] and "PhoneHub 故障诊断报告" in r and "MySQL 版本" in r and len(r)<8000,j'
planCreated=$(curl -fsS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
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
