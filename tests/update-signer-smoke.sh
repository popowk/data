#!/usr/bin/env bash
set -euo pipefail
offline=$(mktemp -d)
cleanup(){
  rm -rf "$offline"
  rm -f deploy/self-update-manifest-v3.json deploy/self-update-manifest-v3.sig
}
trap cleanup EXIT
export PHONEHUB_OFFLINE_TEST="$offline"
php -r '
$p=sodium_crypto_sign_keypair();
file_put_contents(getenv("PHONEHUB_OFFLINE_TEST")."/signing.key",sodium_crypto_sign_secretkey($p));
file_put_contents(getenv("PHONEHUB_OFFLINE_TEST")."/signing.pub",sodium_crypto_sign_publickey($p));
'
php tools/sign-self-update.php "$offline/signing.key"
php -r '
require "app/core.php";require "app/updater.php";
$files=[];foreach(UPDATE_FILES as $p)$files[$p]=file_get_contents(APP_ROOT."/".$p);
$v=json_decode($files["version.json"],true,512,JSON_THROW_ON_ERROR)["version"];
$pub=file_get_contents(getenv("PHONEHUB_OFFLINE_TEST")."/signing.pub");
$v3=update_v3_verify_catalog($v,
    file_get_contents("deploy/self-update-manifest-v3.json"),
    file_get_contents("deploy/self-update-manifest-v3.sig"),$pub);
update_v3_verify_files($files,$v3);
if ($v3["remove"]!==["app/gateway.php"] || $v3["format"]!==2)
    throw new RuntimeException("V3-only release must sign retired gateway removal");
if (defined("UPDATE_LEGACY_FILES") || is_file("deploy/self-update-manifest.json") ||
    is_file("deploy/self-update-manifest.sig") ||
    is_file("deploy/self-update-manifest-v2.json") ||
    is_file("deploy/self-update-manifest-v2.sig"))
    throw new RuntimeException("Retired V1/V2 manifest was unexpectedly emitted");
echo "PASS: V3-only signer authenticates retired gateway deletion; no V1/V2 files\n";
'
