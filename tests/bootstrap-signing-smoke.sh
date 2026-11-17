#!/usr/bin/env bash
set -euo pipefail
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
php tools/bootstrap-self-update.php --prepare-only --key-dir="$temp/keys"
test "$(wc -c < "$temp/keys/server-signing.secret" | tr -d ' ')" -eq 64
test "$(wc -c < "$temp/keys/server-signing.pub" | tr -d ' ')" -eq 32
private_before=$(sha256sum "$temp/keys/server-signing.secret" | cut -d' ' -f1)
php tools/bootstrap-self-update.php --prepare-only --key-dir="$temp/keys"
private_after=$(sha256sum "$temp/keys/server-signing.secret" | cut -d' ' -f1)
test "$private_before" = "$private_after"
php -r '
$secret=file_get_contents($argv[1]);$pub=file_get_contents($argv[2]);
if (!hash_equals(sodium_crypto_sign_publickey_from_secretkey($secret),$pub)) exit(2);
' "$temp/keys/server-signing.secret" "$temp/keys/server-signing.pub"
printf '%s' 'corrupt' > "$temp/keys/server-signing.pub"
if php tools/bootstrap-self-update.php --prepare-only --key-dir="$temp/keys" >/dev/null 2>&1; then
  echo 'bootstrap accepted mismatched existing keypair' >&2; exit 1
fi
echo "PASS: signing bootstrap creates a safe local keypair, is idempotent and rejects key mismatches"
