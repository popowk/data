<?php
declare(strict_types=1);
require_once __DIR__.'/mobile.php';

/**
 * Sensitive device identifiers are encrypted at rest, never recorded in logs.
 * The existing deployment HMAC key is used only as key material; a
 * purpose-separated secretbox key is derived by keyed BLAKE2b.
 * Back up storage/mobile-identity.key: loss prevents decryption and matching.
 */
function device_sensitive_key(): string {
    if (!extension_loaded('sodium')) throw new RuntimeException('设备原文加密需要 PHP sodium 扩展');
    return sodium_crypto_generichash('phonehub-identifier-encryption-v1',mobile_identity_key(),SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
}
function device_encrypt(?string $value): ?string {
    if ($value===null || $value==='') return null;
    $nonce=random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    return base64_encode($nonce.sodium_crypto_secretbox($value,$nonce,device_sensitive_key()));
}
function device_decrypt(?string $encoded): ?string {
    if ($encoded===null || $encoded==='') return null;
    $raw=base64_decode($encoded,true);
    if ($raw===false || strlen($raw)<SODIUM_CRYPTO_SECRETBOX_NONCEBYTES+SODIUM_CRYPTO_SECRETBOX_MACBYTES)
        throw new RuntimeException('设备身份密文无效');
    $nonce=substr($raw,0,SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $plain=sodium_crypto_secretbox_open(substr($raw,SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),$nonce,device_sensitive_key());
    if ($plain===false) throw new RuntimeException('设备身份密钥不匹配或密文已损坏');
    return $plain;
}
function device_phone_normalize(?string $number): ?string {
    if ($number===null || trim($number)==='') return null;
    $number=preg_replace('/[\s()-]+/','',trim($number));
    if (!is_string($number)) throw new RuntimeException('手机号格式不正确');
    if (preg_match('/^1[3-9][0-9]{9}$/D',$number)) $number='+86'.$number;
    if (!preg_match('/^\+[1-9][0-9]{7,14}$/D',$number))
        throw new RuntimeException('手机号应为有效的国际格式，例如 +8613800000000');
    return $number;
}
function device_phone_hash(?string $phone): ?string {
    if (!$phone) return null;
    return hash_hmac('sha256','phone-number:'.$phone,mobile_identity_key());
}
function device_mask(?string $value,int $first=3,int $last=4): string {
    if (!$value) return '未获取';
    return substr($value,0,$first).'••••'.substr($value,-$last);
}
function device_blacklisted_computer(PDO $connection,string $computerId): bool {
    $stmt=$connection->prepare("SELECT 1 FROM phonehub_mobile_blacklist WHERE enabled=1 AND identifier_type='computer_id' AND identifier_hash=? LIMIT 1");
    $stmt->execute([$computerId]);return (bool)$stmt->fetchColumn();
}
function device_insert_blacklist(PDO $connection,string $kind,string $value,string $reason,int $admin): void {
    if (!in_array($kind,['computer_id','phone_id','imei_hash','phone_hash'],true) ||
        !preg_match('/^[a-f0-9]{64}$/D',$value))
        throw new RuntimeException('拉黑类型或标识无效');
    $st=$connection->prepare("INSERT INTO phonehub_mobile_blacklist(identifier_type,identifier_hash,reason,enabled,created_by,created_at)
      VALUES(?,?,?,1,?,UTC_TIMESTAMP()) ON DUPLICATE KEY UPDATE reason=VALUES(reason),enabled=1,created_by=VALUES(created_by),created_at=UTC_TIMESTAMP()");
    $st->execute([$kind,$value,$reason,$admin]);
}
