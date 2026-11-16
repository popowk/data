#!/usr/bin/env bash
set -euo pipefail
root=$(mktemp -d)
mkdir -p "$root/out"
cleanup(){
  rm -rf "$root"
  rm -f storage/backup-recipient.pub storage/config.php
}
trap cleanup EXIT
mkdir -p storage
cat > storage/config.php <<'EOF'
<?php return ['db_host'=>'127.0.0.1','db_port'=>3306,'db_name'=>'phonehub_ci','db_user'=>'root','db_pass'=>'ci_dummy_password'];
EOF
export PH_BACKUP_TEST_ROOT="$root"
php -r '
$pair=sodium_crypto_box_keypair();
file_put_contents("storage/backup-recipient.pub",sodium_crypto_box_publickey($pair));
file_put_contents(getenv("PH_BACKUP_TEST_ROOT")."/offline.key",sodium_crypto_box_secretkey($pair));
'
cat > "$root/mock-mysqldump" <<'SH'
#!/bin/sh
case "$1" in
  --defaults-extra-file=*) test -r "$(printf '%s' "$1" | sed 's/^--defaults-extra-file=//')" || exit 3 ;;
  *) exit 2 ;;
esac
printf '%s\n' 'CREATE DATABASE phonehub_ci;' 'CREATE TABLE ci (id INT);' 'INSERT INTO ci VALUES (17);'
SH
chmod 700 "$root/mock-mysqldump"
PHONEHUB_MYSQLDUMP="$root/mock-mysqldump" php tools/backup-server.php create "$root/out"
archive=$(find "$root/out" -maxdepth 1 -name 'phonehub-*.phbk' -print -quit)
test -n "$archive"
test "$(find "$root/out" -name '*.part' | wc -l)" -eq 0
php tools/backup-server.php verify "$archive" "$root/offline.key"
php tools/backup-server.php restore "$archive" "$root/offline.key" "$root/restore"
grep -q 'INSERT INTO ci VALUES (17)' "$root/restore/database.sql"
cmp storage/config.php "$root/restore/storage/config.php"
if grep -aq 'ci_dummy_password' "$archive"; then echo 'plaintext leaked in encrypted backup' >&2; exit 1; fi
if php tools/backup-server.php restore "$archive" "$root/offline.key" "$root/restore" >/dev/null 2>&1; then
  echo 'restore into existing directory should have failed' >&2; exit 1
fi
echo 'PASS: CLI create, sealed backup verify, isolated restore, private key never on server, plaintext not exposed'
