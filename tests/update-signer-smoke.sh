#!/usr/bin/env bash
set -euo pipefail
offline=$(mktemp -d)
cleanup(){
  rm -rf "$offline"
  rm -f deploy/self-update-manifest.json deploy/self-update-manifest.sig
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
$fs=[];foreach(UPDATE_FILES as $p)$fs[$p]=file_get_contents(APP_ROOT."/".$p);
$v=json_decode($fs["version.json"],true)["version"];
update_verify_signed_archive($fs,$v,
    file_get_contents("deploy/self-update-manifest.json"),
    file_get_contents("deploy/self-update-manifest.sig"),
    file_get_contents(getenv("PHONEHUB_OFFLINE_TEST")."/signing.pub"));
echo "PASS: offline signer emits valid signed manifest covering exact runtime files\n";
'
