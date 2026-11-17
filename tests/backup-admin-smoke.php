<?php
declare(strict_types=1);
require dirname(__DIR__).'/app/core.php';
require dirname(__DIR__).'/app/backup_admin.php';
if(!extension_loaded('sodium')) throw new RuntimeException('libsodium unavailable');
$temp=sys_get_temp_dir().'/phonehub-key-test-'.bin2hex(random_bytes(5));
if (!mkdir($temp,0700)) throw new RuntimeException('cannot create isolated key test dir');
try {
    $initial=backup_recipient_status($temp);
    if ($initial['configured']!==false) throw new RuntimeException('recipient unexpectedly configured');
    $key=backup_recipient_generate($temp);
    if (strlen($key['secret'])!==SODIUM_CRYPTO_BOX_SECRETKEYBYTES)
        throw new RuntimeException('private key has wrong length');
    $public=file_get_contents($temp.'/backup-recipient.pub');
    if (!is_string($public) || strlen($public)!==SODIUM_CRYPTO_BOX_PUBLICKEYBYTES)
        throw new RuntimeException('public key has wrong length');
    $state=backup_recipient_status($temp);
    if (!$state['configured'] || $state['fingerprint']!==hash('sha256',$public))
        throw new RuntimeException('recipient public fingerprint mismatch');
    $message=random_bytes(32);
    $cipher=sodium_crypto_box_seal($message,$public);
    $pair=sodium_crypto_box_keypair_from_secretkey_and_publickey($key['secret'],$public);
    if (!hash_equals($message,(string)sodium_crypto_box_seal_open($cipher,$pair)))
        throw new RuntimeException('backup recipient encryption roundtrip failed');
    try {
        backup_recipient_generate($temp);
        throw new RuntimeException('second key generation was unexpectedly allowed');
    } catch (RuntimeException $e) {
        if (!str_contains($e->getMessage(),'禁止自动覆盖'))
            throw $e;
    }
    if (file_get_contents($temp.'/backup-recipient.pub')!==$public)
        throw new RuntimeException('second request changed pinned backup public key');
    sodium_memzero($key['secret']);
    echo "PASS: recipient generated once, public-only persisted, offline private key decrypts and existing key cannot be replaced\n";
} finally {
    if (is_file($temp.'/backup-recipient.pub')) unlink($temp.'/backup-recipient.pub');
    rmdir($temp);
}
