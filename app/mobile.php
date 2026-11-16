<?php
declare(strict_types=1);

/**
 * Mobile identity helpers.
 * Callers must submit raw IMEI only over HTTPS; it is normalized and immediately converted to
 * a deployment-keyed HMAC. It is never stored or returned.
 */
function mobile_identity_db_sql(string $statement,array $params=[]): PDOStatement {
    $connection=$GLOBALS['pdo']??null;
    if ($connection instanceof PDO) {
        $stmt=$connection->prepare($statement);
        $stmt->execute($params);
        return $stmt;
    }
    if (function_exists('client_sql')) return client_sql($statement,$params);
    if (function_exists('sql')) return sql($statement,$params);
    throw new RuntimeException('无法访问手机身份密钥元数据数据库');
}

function mobile_identity_store_fingerprint(string $fingerprint): void {
    mobile_identity_db_sql(
        "INSERT INTO phonehub_mobile_identity_meta(meta_key,meta_value) VALUES('hmac_key_fingerprint',?)
         ON DUPLICATE KEY UPDATE meta_value=VALUES(meta_value)",
        [$fingerprint]
    );
}

function mobile_identity_has_imei_records(): bool {
    $count=mobile_identity_db_sql("SELECT
        (SELECT COUNT(*) FROM phonehub_mobile_devices WHERE imei_hash IS NOT NULL) +
        (SELECT COUNT(*) FROM phonehub_mobile_blacklist WHERE identifier_type='imei_hash')")->fetchColumn();
    return (int)$count>0;
}

function mobile_identity_key(): string {
    $path=APP_STORE.'/mobile-identity.key';
    if (is_link($path)) throw new RuntimeException('手机身份密钥不能是符号链接');

    $marker=mobile_identity_db_sql("SELECT meta_value FROM phonehub_mobile_identity_meta WHERE meta_key='hmac_key_fingerprint'")->fetchColumn();
    if ($marker===false) throw new RuntimeException('手机身份密钥元数据缺失，请先完成后台数据库迁移');
    $marker=(string)$marker;

    if (is_file($path)) {
        $key=file_get_contents($path);
        if (!is_string($key) || strlen($key)!==32) throw new RuntimeException('手机身份密钥文件损坏');
        if (PHP_OS_FAMILY!=='Windows') {
            $mode=fileperms($path);
            if ($mode===false || (($mode & 0077)!==0 && !chmod($path,0600)))
                throw new RuntimeException('手机身份密钥权限不安全');
        }
        $fingerprint=hash('sha256',$key);
        if ($marker!=='' && !hash_equals($marker,$fingerprint))
            throw new RuntimeException('手机身份密钥与数据库指纹不匹配，请恢复正确的密钥备份');
        if ($marker==='') mobile_identity_store_fingerprint($fingerprint);
        return $key;
    }

    // Never silently rotate the HMAC key: doing so would make existing IMEI
    // blacklist entries ineffective. Restore the original key backup instead.
    if ($marker!=='' || mobile_identity_has_imei_records())
        throw new RuntimeException('手机身份密钥丢失；为防止黑名单失效，已拒绝生成新密钥，请恢复 storage/mobile-identity.key 备份');

    $key=random_bytes(32);
    $fp=@fopen($path,'x+b');
    if (!$fp) {
        if (is_file($path)) return mobile_identity_key();
        throw new RuntimeException('无法创建手机身份密钥文件');
    }
    try {
        if (fwrite($fp,$key)!==32 || !fflush($fp)) {
            @unlink($path);
            throw new RuntimeException('无法写入手机身份密钥文件');
        }
        if (PHP_OS_FAMILY!=='Windows' && !chmod($path,0600)) {
            @unlink($path);
            throw new RuntimeException('无法限制手机身份密钥文件权限');
        }
    } finally {fclose($fp);}
    try {
        mobile_identity_store_fingerprint(hash('sha256',$key));
    } catch(Throwable $e) {
        @unlink($path);
        throw new RuntimeException('无法登记手机身份密钥指纹，已撤销新密钥文件');
    }
    return $key;
}

function mobile_imei_hash(string $imei): ?string {
    $imei=trim($imei);
    if ($imei==='') return null;
    if (!preg_match('/^[0-9]{14,16}$/D',$imei))
        throw new RuntimeException('IMEI 格式不正确，应为 14–16 位数字');
    return hash_hmac('sha256',$imei,mobile_identity_key());
}

function mobile_blacklist_match(PDO $connection,string $phoneId,?string $imeiHash): ?array {
    $sql="SELECT id,identifier_type,reason FROM phonehub_mobile_blacklist
          WHERE enabled=1 AND ((identifier_type='phone_id' AND identifier_hash=?)";
    $params=[$phoneId];
    if ($imeiHash!==null) {
        $sql.=" OR (identifier_type='imei_hash' AND identifier_hash=?)";
        $params[]=$imeiHash;
    }
    $sql.=") ORDER BY id DESC LIMIT 1";
    $stmt=$connection->prepare($sql);
    $stmt->execute($params);
    $row=$stmt->fetch(PDO::FETCH_ASSOC);
    return $row?:null;
}
