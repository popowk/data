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
bound=$(api mobile_bind "{\"device_id\":\"$DEVICE\",\"phone_id\":\"$PHONE\",\"display_name\":\"CI Android\",\"imei\":\"490154203237518\"}")
TEST_RESPONSE="$bound" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and j["bound"] and j["imei_bound"],j'
after=$(api package "{\"device_id\":\"$DEVICE\",\"package_id\":\"douyin\"}")
TEST_RESPONSE="$after" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and "envelope" in j,j'
listed=$(api mobile_list "{\"device_id\":\"$DEVICE\"}")
TEST_RESPONSE="$listed" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and j["active_count"]==1 and j["devices"][0]["imei_bound"],j'
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
mcpDisabled=$(api update_check "{\"device_id\":\"$DEVICE\",\"platform\":\"mcp\",\"channel\":\"stable\",\"current_version\":\"0.0.0\"}")
TEST_RESPONSE="$mcpDisabled" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert not j["ok"] and j["error_code"]=="FEATURE_DISABLED",j'
aiStatus=$(api ai_status "{\"device_id\":\"$DEVICE\"}")
TEST_RESPONSE="$aiStatus" python3 -c 'import os,json; j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and j["enabled"] and not j["client_key_allowed"] and not j["server_key_configured"],j'
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
echo 'PASS: login, IMEI HMAC binding, blacklist enforcement, MCP default-deny, mobile package gating, AI/BYOK, logs and signed updates'
