<?php
declare(strict_types=1);

/**
 * Mobile identity helpers.
 * Raw IMEI is accepted only over HTTPS, normalized and immediately converted to
 * a deployment-keyed HMAC. It is never stored or returned.
 */
function mobile_identity_key(): string {
    $path=APP_STORE.'/mobile-identity.key';
    if (is_link($path)) throw new RuntimeException('手机身份密钥不能是符号链接');
    if (is_file($path)) {
        $key=file_get_contents($path);
        if (!is_string($key) || strlen($key)!==32) throw new RuntimeException('手机身份密钥文件损坏');
        if (PHP_OS_FAMILY!=='Windows') {
            $mode=fileperms($path);
            if ($mode===false || (($mode & 0077)!==0 && !chmod($path,0600)))
                throw new RuntimeException('手机身份密钥权限不安全');
        }
        return $key;
    }
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
