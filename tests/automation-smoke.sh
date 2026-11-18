#!/usr/bin/env bash
# Sourced by tests/api-smoke.sh (shares owner CSRF, cookie, running test server).
set -euo pipefail
AUTO='http://127.0.0.1:18765/automation/v1/index.php?route='
TMP_AUTO=$(mktemp -d)
# Test fixture contains no customer files or secrets.
php -r '
$z=new ZipArchive();
if ($z->open($argv[1],ZipArchive::CREATE|ZipArchive::OVERWRITE)!==true) exit(2);
$z->addFromString("core/version.txt","9.0.0"); $z->addFromString("core/README.txt","CI only");
$z->close();
' "$TMP_AUTO/phonehub-ci-9.0.0.zip"
SHA_AUTO=$(sha256sum "$TMP_AUTO/phonehub-ci-9.0.0.zip" | awk '{print $1}')
curl -fsS -b "$adminCookies" 'http://127.0.0.1:18765/index.php?view=releases' -o "$adminHtml"
grep -q 'AI / CI 专用发布令牌' "$adminHtml"
# Owner creates a scoped one-time machine token. No admin Cookie used for API.
issued=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=automation_token_create" \
  --data-urlencode "label=CI release bot" --data-urlencode "expires_days=3" \
  --data-urlencode "platforms[]=core" \
  --data-urlencode "channels[]=beta" --data-urlencode "channels[]=stable" \
  --data-urlencode "permissions[]=release:prepare" \
  --data-urlencode "permissions[]=release:read" \
  --data-urlencode "permissions[]=release:publish" \
  --data-urlencode "permissions[]=release:disable")
AUTOTOKEN=$(TEST_RESPONSE="$issued" python3 -c 'import os,json
j=json.loads(os.environ["TEST_RESPONSE"]); assert j["ok"] and j["token"].startswith("phat_") and len(j["token"])==69,j;print(j["token"])')
ownerTokenId=$(TEST_RESPONSE="$issued" python3 -c 'import os,json;print(json.loads(os.environ["TEST_RESPONSE"])["token_id"])')
# Machine endpoints require explicit Bearer token.
noAuth=$(curl -sS "$AUTO"releases)
TEST_RESPONSE="$noAuth" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert not j["ok"] and j["error_code"]=="UNAUTHORIZED",j'
list=$(curl -sS "$AUTO"releases -H "Authorization: Bearer $AUTOTOKEN")
TEST_RESPONSE="$list" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert j["ok"] and isinstance(j["releases"],list) and isinstance(j["published_releases"],list),j'
prepare=$(curl -sS -H "Authorization: Bearer $AUTOTOKEN" \
  -F "platform=core" -F "channel=beta" -F "version=9.0.0" \
  -F "min_client=0.7.1" -F "sha256=$SHA_AUTO" \
  -F "idempotency_key=ci-test-beta-nine" \
  -F "commit_sha=1111111111111111111111111111111111111111" \
  -F "build_run_id=ci-101" \
  -F "file=@$TMP_AUTO/phonehub-ci-9.0.0.zip;type=application/zip" \
  "$AUTO"releases/prepare)
TEST_RESPONSE="$prepare" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert j["ok"] and j["release"]["status"]=="prepared" and not j["replayed"],j'
stageId=$(TEST_RESPONSE="$prepare" python3 -c 'import os,json;print(json.loads(os.environ["TEST_RESPONSE"])["release"]["id"])')
replay=$(curl -sS -H "Authorization: Bearer $AUTOTOKEN" \
  -F "platform=core" -F "channel=beta" -F "version=9.0.0" \
  -F "sha256=$SHA_AUTO" -F "idempotency_key=ci-test-beta-nine" \
  "$AUTO"releases/prepare)
TEST_RESPONSE="$replay" STAGED="$stageId" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert j["ok"] and j["replayed"] and j["release"]["id"]==int(os.environ["STAGED"]),j'
conflict=$(curl -sS -H "Authorization: Bearer $AUTOTOKEN" \
  -F "platform=core" -F "channel=beta" -F "version=9.0.2" \
  -F "sha256=$SHA_AUTO" -F "idempotency_key=ci-test-beta-nine" \
  "$AUTO"releases/prepare)
TEST_RESPONSE="$conflict" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert not j["ok"] and j["error_code"]=="IDEMPOTENCY_CONFLICT",j'
badSha=$(curl -sS -H "Authorization: Bearer $AUTOTOKEN" \
  -F "platform=core" -F "channel=beta" -F "version=9.0.4" \
  -F "sha256=$(printf '0%.0s' {1..64})" -F "idempotency_key=ci-test-bad-hash" \
  -F "file=@$TMP_AUTO/phonehub-ci-9.0.0.zip;type=application/zip" \
  "$AUTO"releases/prepare)
TEST_RESPONSE="$badSha" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert not j["ok"] and j["error_code"]=="SHA256_MISMATCH",j'
published=$(curl -sS -X POST "$AUTO"releases/"$stageId"/publish -H "Authorization: Bearer $AUTOTOKEN")
TEST_RESPONSE="$published" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert j["ok"] and j["release"]["status"]=="published" and j["public_release_id"]>0 and not j["replayed"],j'
publicId=$(TEST_RESPONSE="$published" python3 -c 'import os,json;print(json.loads(os.environ["TEST_RESPONSE"])["public_release_id"])')
publishedAgain=$(curl -sS -X POST "$AUTO"releases/"$stageId"/publish -H "Authorization: Bearer $AUTOTOKEN")
TEST_RESPONSE="$publishedAgain" PUBLIC_ID="$publicId" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert j["ok"] and j["replayed"] and j["release"]["release_id"]==int(os.environ["PUBLIC_ID"]),j'
# Ed25519 detached signature must validate with only the public key.
PUBLISH_ID="$publicId" php -r '
require "app/core.php"; require "app/releases.php";
$r=sql("SELECT manifest,signature,sha256 FROM phonehub_releases WHERE id=?",[(int)getenv("PUBLISH_ID")])->fetch();
if (!$r) exit(2);
$pub=base64_decode(release_public_key(),true);
if (!sodium_crypto_sign_verify_detached(base64_decode($r["signature"],true),$r["manifest"],$pub)) exit(3);
$m=json_decode($r["manifest"],true);
if ($m["version"]!=="9.0.0" || $m["platform"]!=="core" || !hash_equals($m["sha256"],$r["sha256"])) exit(4);
'
disabled=$(curl -sS -X POST "$AUTO"releases/"$stageId"/disable -H "Authorization: Bearer $AUTOTOKEN")
TEST_RESPONSE="$disabled" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert j["ok"] and j["release"]["status"]=="disabled",j'
disabledAgain=$(curl -sS -X POST "$AUTO"releases/"$stageId"/disable -H "Authorization: Bearer $AUTOTOKEN")
TEST_RESPONSE="$disabledAgain" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert j["ok"] and j["release"]["status"]=="disabled",j'
PUBLISH_ID="$publicId" php -r '
require "app/core.php";
$v=sql("SELECT enabled FROM phonehub_releases WHERE id=?",[(int)getenv("PUBLISH_ID")])->fetchColumn();
if ((int)$v!==0) exit(2);
'
# Stable must remain private until separately approved by the owner.
stableStage=$(curl -sS -H "Authorization: Bearer $AUTOTOKEN" \
  -F "platform=core" -F "channel=stable" -F "version=9.0.1" \
  -F "sha256=$SHA_AUTO" -F "idempotency_key=ci-test-stable-nine" \
  -F "file=@$TMP_AUTO/phonehub-ci-9.0.0.zip;type=application/zip" \
  "$AUTO"releases/prepare)
stableId=$(TEST_RESPONSE="$stableStage" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert j["ok"] and j["release"]["status"]=="prepared",j;print(j["release"]["id"])')
unapproved=$(curl -sS -X POST "$AUTO"releases/"$stableId"/publish -H "Authorization: Bearer $AUTOTOKEN")
TEST_RESPONSE="$unapproved" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert not j["ok"] and j["error_code"]=="APPROVAL_REQUIRED",j'
approved=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=automation_release_approve" \
  --data-urlencode "id=$stableId")
TEST_RESPONSE="$approved" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert j["ok"],j'
stablePublished=$(curl -sS -X POST "$AUTO"releases/"$stableId"/publish -H "Authorization: Bearer $AUTOTOKEN")
TEST_RESPONSE="$stablePublished" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert j["ok"] and j["release"]["status"]=="published" and j["release"]["approved"],j'
stableDisabled=$(curl -sS -X POST "$AUTO"releases/"$stableId"/disable -H "Authorization: Bearer $AUTOTOKEN")
TEST_RESPONSE="$stableDisabled" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert j["ok"],j'
# Token must be removed from access control immediately after rotation.
rotated=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=automation_token_rotate" \
  --data-urlencode "id=$ownerTokenId")
NEW_AUTOTOKEN=$(TEST_RESPONSE="$rotated" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert j["ok"] and len(j["token"])==69,j;print(j["token"])')
rotatedId=$(TEST_RESPONSE="$rotated" python3 -c 'import os,json;print(json.loads(os.environ["TEST_RESPONSE"])["token_id"])')
oldRejected=$(curl -sS "$AUTO"releases -H "Authorization: Bearer $AUTOTOKEN")
TEST_RESPONSE="$oldRejected" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert not j["ok"] and j["error_code"]=="UNAUTHORIZED",j'
newWorks=$(curl -sS "$AUTO"releases -H "Authorization: Bearer $NEW_AUTOTOKEN")
TEST_RESPONSE="$newWorks" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert j["ok"] and len(j["releases"])>=2,j'
revoke=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=automation_token_revoke" \
  --data-urlencode "id=$rotatedId")
TEST_RESPONSE="$revoke" python3 -c 'import os,json;assert json.loads(os.environ["TEST_RESPONSE"])["ok"]'
revokedRejected=$(curl -sS "$AUTO"releases -H "Authorization: Bearer $NEW_AUTOTOKEN")
TEST_RESPONSE="$revokedRejected" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert not j["ok"] and j["error_code"]=="UNAUTHORIZED",j'
# IP allowlist and denied permissions validated by backend, not only by UI.
ipBound=$(curl -sS -b "$adminCookies" -X POST 'http://127.0.0.1:18765/index.php' \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=automation_token_create" \
  --data-urlencode "label=CI IP restricted" --data-urlencode "expires_days=1" \
  --data-urlencode "source_ip=203.0.113.42" \
  --data-urlencode "platforms[]=core" --data-urlencode "channels[]=beta" \
  --data-urlencode "permissions[]=release:read")
IPTOKEN=$(TEST_RESPONSE="$ipBound" python3 -c 'import os,json;print(json.loads(os.environ["TEST_RESPONSE"])["token"])')
wrongIp=$(curl -sS "$AUTO"releases -H "Authorization: Bearer $IPTOKEN")
TEST_RESPONSE="$wrongIp" python3 -c 'import os,json;j=json.loads(os.environ["TEST_RESPONSE"]);assert not j["ok"] and j["error_code"]=="SOURCE_DENIED",j'
# Audit tables must identify task events but never hold the raw machine token.
php -r '
require "app/core.php";
$n=(int)sql("SELECT COUNT(*) FROM phonehub_automation_audit WHERE event IN (?,?,?)",["prepare","publish","disable"])->fetchColumn();
if ($n<4) exit(2);
'
if grep -Fq "$AUTOTOKEN" /tmp/phonehub-ci-server.log; then echo 'automation token leaked to PHP logs' >&2; exit 9; fi
rm -rf "$TMP_AUTO"
echo 'PASS: automation scoped tokens, beta/stable approval, idempotent publish/disable, ZIP verification, revocation'
