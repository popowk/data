<?php
declare(strict_types=1);

/**
 * PhoneHub encrypted backup format v1.
 * CLI-only library. Streaming libsodium secretstream (authenticated AEAD)
 * with an independently provisioned offline recipient Curve25519 public key.
 * The server NEVER needs or stores the backup recipient private key.
 */
const PH_BACKUP_MAGIC="PHUBAK1\n";
const PH_BACKUP_CHUNK=65536;
const PH_BACKUP_FRAME_MAX=262144;

function ph_backup_exact($handle,int $length): string {
    $data='';
    while (strlen($data)<$length) {
        $part=fread($handle,$length-strlen($data));
        if (!is_string($part) || $part==='') throw new RuntimeException('加密备份内容不完整或被截断');
        $data.=$part;
    }
    return $data;
}
function ph_backup_write($handle,string $bytes): void {
    $offset=0;
    while ($offset<strlen($bytes)) {
        $n=fwrite($handle,substr($bytes,$offset));
        if (!is_int($n) || $n<1) throw new RuntimeException('加密备份写入失败');
        $offset+=$n;
    }
}
function ph_backup_path_allowed(string $name): bool {
    return preg_match('~^(?:database\.sql|storage/(?:config\.php|ai-master\.key|mobile-identity\.key|self-update-trust\.pub|backup-recipient\.pub|updates/(?:signing\.(?:key|pub)|[a-f0-9]{40}\.zip)))$~D',$name)===1;
}
function ph_backup_encrypt_begin($out,string $recipientPub): string {
    if (!extension_loaded('sodium') || strlen($recipientPub)!==SODIUM_CRYPTO_BOX_PUBLICKEYBYTES)
        throw new RuntimeException('备份接收者公钥必须为 32 字节 Curve25519 公钥');
    $key=random_bytes(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);
    $sealed=sodium_crypto_box_seal($key,$recipientPub);
    [$state,$header]=sodium_crypto_secretstream_xchacha20poly1305_init_push($key);
    ph_backup_write($out,PH_BACKUP_MAGIC.$sealed.$header);
    sodium_memzero($key);
    return $state;
}
function ph_backup_encrypt_frame($out,string &$state,string $type,string $payload='',bool $last=false): void {
    if (strlen($type)!==1 || strlen($payload)>PH_BACKUP_CHUNK)
        throw new RuntimeException('备份分块长度或类型不合法');
    $tag=$last?SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL:
        SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
    $cipher=sodium_crypto_secretstream_xchacha20poly1305_push($state,$type.$payload,'',$tag);
    ph_backup_write($out,pack('N',strlen($cipher)).$cipher);
}
function ph_backup_encrypt_file($out,string &$state,string $name,$source): array {
    if (!ph_backup_path_allowed($name) || !is_resource($source))
        throw new RuntimeException('备份来源路径或输入无效');
    ph_backup_encrypt_frame($out,$state,'S',json_encode(['path'=>$name],JSON_THROW_ON_ERROR));
    $hash=hash_init('sha256');$size=0;
    while (!feof($source)) {
        $chunk=fread($source,PH_BACKUP_CHUNK-1);
        if ($chunk===false) throw new RuntimeException('备份读取失败：'.$name);
        if ($chunk==='') {
            if (!feof($source)) throw new RuntimeException('备份输入流无数据：'.$name);
            break;
        }
        $size+=strlen($chunk);
        hash_update($hash,$chunk);
        ph_backup_encrypt_frame($out,$state,'D',$chunk);
    }
    $digest=hash_final($hash);
    ph_backup_encrypt_frame($out,$state,'E',json_encode(['size'=>$size,'sha256'=>$digest],JSON_THROW_ON_ERROR));
    return ['name'=>$name,'size'=>$size,'sha256'=>$digest];
}
function ph_backup_encrypt_finish($out,string &$state,int $fileCount): void {
    ph_backup_encrypt_frame($out,$state,'Z',json_encode(['count'=>$fileCount],JSON_THROW_ON_ERROR),true);
}
function ph_backup_decrypt(string $archive,string $secretKey,?string $destination=null): array {
    if (!extension_loaded('sodium') || strlen($secretKey)!==SODIUM_CRYPTO_BOX_SECRETKEYBYTES)
        throw new RuntimeException('验证需要离线保存的 32 字节 Curve25519 私钥');
    $pub=sodium_crypto_box_publickey_from_secretkey($secretKey);
    $pair=sodium_crypto_box_keypair_from_secretkey_and_publickey($secretKey,$pub);
    $in=fopen($archive,'rb');
    if (!$in) throw new RuntimeException('无法打开备份文件');
    $current=null;$output=null;$ctx=null;$size=0;$seen=[];$files=[];$final=false;$metaSeen=false;
    try {
        if (ph_backup_exact($in,strlen(PH_BACKUP_MAGIC))!==PH_BACKUP_MAGIC)
            throw new RuntimeException('备份格式标识错误');
        $sealed=ph_backup_exact($in,SODIUM_CRYPTO_BOX_SEALBYTES+SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);
        $key=sodium_crypto_box_seal_open($sealed,$pair);
        if (!is_string($key)) throw new RuntimeException('备份接收者私钥错误或密钥封装损坏');
        $header=ph_backup_exact($in,SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);
        $state=sodium_crypto_secretstream_xchacha20poly1305_init_pull($header,$key);
        sodium_memzero($key);
        while (!$final) {
            $lengthBytes=ph_backup_exact($in,4);
            $length=unpack('N',$lengthBytes)[1];
            if ($length<18 || $length>PH_BACKUP_FRAME_MAX) throw new RuntimeException('加密备份帧长度错误');
            $result=sodium_crypto_secretstream_xchacha20poly1305_pull($state,ph_backup_exact($in,$length));
            if (!is_array($result)) throw new RuntimeException('备份认证失败：内容被修改或已损坏');
            [$data,$tag]=$result;
            if (!is_string($data) || $data==='') throw new RuntimeException('备份帧内容无效');
            $type=$data[0];$body=substr($data,1);
            if (!$metaSeen) {
                if ($type!=='M' || $tag===SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL)
                    throw new RuntimeException('备份缺少元信息');
                $meta=json_decode($body,true);
                if (!is_array($meta) || ($meta['format']??null)!==1)
                    throw new RuntimeException('备份元信息版本不兼容');
                $metaSeen=true;
                continue;
            }
            if ($type==='S') {
                if ($current!==null || $tag===SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL)
                    throw new RuntimeException('备份文件序列错误');
                $info=json_decode($body,true);
                $name=$info['path']??null;
                if (!is_string($name) || !ph_backup_path_allowed($name) || isset($seen[$name]))
                    throw new RuntimeException('备份包含重复或不安全的文件路径');
                $seen[$name]=true;$current=$name;$ctx=hash_init('sha256');$size=0;
                if ($destination!==null) {
                    $path=rtrim($destination,'/').'/'.$name;
                    if (!is_dir(dirname($path)) && !mkdir(dirname($path),0700,true))
                        throw new RuntimeException('无法创建隔离恢复目录');
                    $output=fopen($path,'x+b');
                    if (!$output) throw new RuntimeException('恢复目标已存在或不可写：'.$name);
                    @chmod($path,0600);
                }
            } elseif ($type==='D') {
                if ($current===null || $tag===SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL)
                    throw new RuntimeException('备份数据帧顺序错误');
                $size+=strlen($body);
                if ($size>10737418240) throw new RuntimeException('单个备份文件超过 10GiB 安全上限');
                hash_update($ctx,$body);
                if ($output) ph_backup_write($output,$body);
            } elseif ($type==='E') {
                if ($current===null || $tag===SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL)
                    throw new RuntimeException('备份结束帧顺序错误');
                $info=json_decode($body,true);
                $digest=hash_final($ctx);
                if (!is_array($info) || !is_int($info['size']??null) ||
                    $info['size']!==$size || !hash_equals($digest,(string)($info['sha256']??'')))
                    throw new RuntimeException('备份文件摘要不匹配：'.$current);
                if ($output) {fclose($output);$output=null;}
                $files[]=['path'=>$current,'size'=>$size,'sha256'=>$digest];
                $current=null;$ctx=null;$size=0;
            } elseif ($type==='Z') {
                $info=json_decode($body,true);
                if ($current!==null || $tag!==SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL ||
                    !is_array($info) || ($info['count']??null)!==count($files) ||
                    !isset($seen['database.sql']) || !isset($seen['storage/config.php']))
                    throw new RuntimeException('备份最终完整性检查失败');
                $final=true;
            } else throw new RuntimeException('未知的备份帧类型');
        }
        if (fread($in,1)!=='') throw new RuntimeException('备份结束后存在多余数据');
        return $files;
    } finally {
        if ($output) fclose($output);
        fclose($in);
    }
}
