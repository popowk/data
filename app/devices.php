<?php
declare(strict_types=1);
require_once __DIR__.'/mobile.php';

function device_blacklisted_computer(PDO $connection,string $computerId): bool {
    $stmt=$connection->prepare("SELECT 1 FROM phonehub_mobile_blacklist WHERE enabled=1 AND identifier_type='computer_id' AND identifier_hash=? LIMIT 1");
    $stmt->execute([$computerId]);return (bool)$stmt->fetchColumn();
}
function device_insert_blacklist(PDO $connection,string $kind,string $value,string $reason,int $admin): void {
    if (!in_array($kind,['computer_id','phone_id'],true) ||
        !preg_match('/^[a-f0-9]{64}$/D',$value))
        throw new RuntimeException('拉黑类型或标识无效');
    $st=$connection->prepare("INSERT INTO phonehub_mobile_blacklist(identifier_type,identifier_hash,reason,enabled,created_by,created_at)
      VALUES(?,?,?,1,?,UTC_TIMESTAMP()) ON DUPLICATE KEY UPDATE reason=VALUES(reason),enabled=1,created_by=VALUES(created_by),created_at=UTC_TIMESTAMP()");
    $st->execute([$kind,$value,$reason,$admin]);
}
