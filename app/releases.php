<?php
declare(strict_types=1);
// Client core release publishing, kept separate from admin panel software self-updates.
const CLIENT_RELEASE_LIMIT=52428800; // 50 MiB compressed
const SCRCPY_DEFAULT_DOWNLOAD_URL='https://down.tmd.pet/scrcpy/scrcpy-win64-v5.0.1.zip';
// Temporary placeholder only: replace with the official program download when available.
const MAIN_PROGRAM_DEFAULT_DOWNLOAD_URL='https://down.tmd.pet/scrcpy/scrcpy-win64-v5.0.1.zip';
const DOWNLOAD_URL_CACHE_SECONDS=300;

/**
 * Legacy encrypted packages retain exact IDs and independent versions while
 * sharing the parent Douyin product entitlement. Never grant a wildcard:
 * only the explicit notification sub-package maps to douyin.
 */
function phonehub_operation_package_scope(string $packageId): string {
    return $packageId==='douyin-notification'?'douyin':$packageId;
}
function phonehub_operation_package_allowed(string $packageId,array $entitlements): bool {
    return in_array($packageId,$entitlements,true)
        || in_array(phonehub_operation_package_scope($packageId),$entitlements,true);
}
function phonehub_operation_package_category(string $packageId): string {
    return match(phonehub_operation_package_scope($packageId)) {
        'douyin'=>'抖音',
        'xiaohongshu'=>'小红书',
        'mcp'=>'MCP',
        'mcp-codex'=>'Codex MCP',
        'mcp-harness'=>'DeepSeek Harness MCP',
        'skill'=>'Skill',
        default=>'其他操作包'
    };
}

/** Validate a public download target; the server never fetches or redirects to it. */
function phonehub_validate_download_url(string $url,string $resource): string {
    if (!in_array($resource,['scrcpy','main_program'],true))
        throw new RuntimeException('未知下载资源');
    $label=$resource==='scrcpy'?'scrcpy':'官网主程序';
    $url=trim($url);
    if ($url==='' || strlen($url)>512 || preg_match('/[\\x00-\\x20\\x7f]/',$url))
        throw new RuntimeException($label.'下载地址不能为空、包含空格或超过 512 字节');
    if (filter_var($url,FILTER_VALIDATE_URL)===false)
        throw new RuntimeException($label.'下载地址必须是完整 URL');
    $parts=parse_url($url);
    if (!is_array($parts) || strtolower((string)($parts['scheme']??''))!=='https'
        || !is_string($parts['host']??null)
        || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])
        || (isset($parts['port']) && $parts['port']!==443))
        throw new RuntimeException($label.'下载地址仅允许无凭据的 HTTPS 链接（标准 443 端口）');
    $host=$parts['host'];
    if (filter_var($host,FILTER_VALIDATE_IP)!==false ||
        filter_var($host,FILTER_VALIDATE_DOMAIN,FILTER_FLAG_HOSTNAME)===false ||
        !str_contains($host,'.'))
        throw new RuntimeException($label.'下载地址需要有效的公开域名，不接受 IP 或本地域名');
    $pattern=$resource==='scrcpy'?'~^/.+\\.zip$~iD':'~^/.+\\.(?:zip|exe|msi)$~iD';
    if (!preg_match($pattern,(string)($parts['path']??'')))
        throw new RuntimeException($label.'下载地址必须指向 '.($resource==='scrcpy'?'ZIP':'ZIP、EXE 或 MSI').' 文件');
    return $url;
}
function scrcpy_validate_download_url(string $url): string {
    return phonehub_validate_download_url($url,'scrcpy');
}
function main_program_validate_download_url(string $url): string {
    return phonehub_validate_download_url($url,'main_program');
}
function release_store(): string {
    $root=realpath(APP_STORE);
    if (!$root || is_link(APP_STORE)) throw new RuntimeException('服务器存储目录不可用');
    $path=$root.'/updates';
    if (is_link($path)) throw new RuntimeException('更新文件目录不能是符号链接');
    if (!is_dir($path) && !mkdir($path,0700,true)) throw new RuntimeException('更新文件目录不可写');
    $real=realpath($path);
    if (!$real || dirname($real)!==$root) throw new RuntimeException('更新文件目录路径校验失败');
    return $real;
}
function release_keypair(): array {
    if (!extension_loaded('sodium')) throw new RuntimeException('客户端签名发布需要 PHP sodium 扩展');
    $dir=release_store();
    $fp=fopen($dir.'/signing.lock','c+');
    if (!$fp || !flock($fp,LOCK_EX)) throw new RuntimeException('签名锁不可用');
    try {
        $private=$dir.'/signing.key';
        $public=$dir.'/signing.pub';
        if (is_file($private) && is_file($public)) {
            $secret=file_get_contents($private);
            $pub=file_get_contents($public);
            if (!is_string($secret) || strlen($secret)!==SODIUM_CRYPTO_SIGN_SECRETKEYBYTES ||
                !is_string($pub) || strlen($pub)!==SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES)
                throw new RuntimeException('签名密钥损坏，已停止发布');
            if (!hash_equals($pub,sodium_crypto_sign_publickey_from_secretkey($secret)))
                throw new RuntimeException('签名密钥不匹配，已停止发布');
            return [$secret,$pub];
        }
        if (is_file($private) || is_file($public)) throw new RuntimeException('只发现部分签名密钥，需管理员修复，禁止重新生成');
        $pair=sodium_crypto_sign_keypair();
        $secret=sodium_crypto_sign_secretkey($pair);
        $pub=sodium_crypto_sign_publickey($pair);
        $tmp=$private.'.'.bin2hex(random_bytes(8)).'.tmp';
        if (file_put_contents($tmp,$secret,LOCK_EX)!==strlen($secret)) throw new RuntimeException('无法保存签名私钥');
        @chmod($tmp,0600);
        if (!rename($tmp,$private)) { @unlink($tmp); throw new RuntimeException('签名私钥安装失败'); }
        if (file_put_contents($public,$pub,LOCK_EX)!==strlen($pub)) throw new RuntimeException('签名公钥安装失败');
        @chmod($public,0600);
        return [$secret,$pub];
    } finally {
        flock($fp,LOCK_UN); fclose($fp);
    }
}
function release_public_key(): string {
    $path=release_store().'/signing.pub';
    if (!is_file($path)) return '';
    $pub=file_get_contents($path);
    return is_string($pub) && strlen($pub)===SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES ? base64_encode($pub) : '';
}
function valid_version(string $str): bool {
    return preg_match('/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/D',$str)===1 && strlen($str)<=48;
}
function release_platform(string $name): string {
    if (!in_array($name,['core','douyin','xiaohongshu','mcp','skill','mcp-codex','mcp-harness'],true)) throw new RuntimeException('发布目标仅支持 core、douyin、xiaohongshu、mcp、skill、mcp-codex、mcp-harness');
    return $name;
}
function release_channel(string $channel): string {
    if (!in_array($channel,['stable','beta'],true)) throw new RuntimeException('发布渠道仅支持 stable 或 beta');
    return $channel;
}
function inspect_release_zip(string $path): void {
    if (!extension_loaded('zip')) throw new RuntimeException('PHP ZipArchive 扩展未启用');
    $zip=new ZipArchive();
    if ($zip->open($path)!==true) throw new RuntimeException('更新包不是有效 ZIP');
    try {
        if ($zip->numFiles<1 || $zip->numFiles>2000) throw new RuntimeException('更新包文件数量异常');
        $sum=0;
        for ($i=0;$i<$zip->numFiles;$i++) {
            $name=$zip->getNameIndex($i);
            $stat=$zip->statIndex($i);
            if (!is_string($name) || strlen($name)>512 || str_contains($name,"\0") ||
                str_contains($name,'\\') || str_starts_with($name,'/') || preg_match('~(^|/)\.\.?(/|$)~',$name) ||
                preg_match('/^[A-Za-z]:/',$name)) throw new RuntimeException('ZIP 包存在不安全的文件路径');
            if (!is_array($stat)) throw new RuntimeException('ZIP 条目无法读取');
            $sum+=(int)($stat['size']??0);
            if ($sum>262144000) throw new RuntimeException('ZIP 解压后体积超过 250MB');
            if ($zip->getExternalAttributesIndex($i,$os,$attr) && $os===ZipArchive::OPSYS_UNIX) {
                $type=(($attr>>16)&0170000);
                if ($type!==0 && $type!==0100000 && $type!==0040000) throw new RuntimeException('ZIP 不允许符号链接或设备节点');
            }
        }
    } finally {$zip->close();}
}
function release_publish(array $file,array $post): array {
    require_global_admin();
    if (!isset($file['error']) || (int)$file['error']!==UPLOAD_ERR_OK || !is_uploaded_file((string)($file['tmp_name']??'')))
        throw new RuntimeException('上传失败；请检查 PHP upload_max_filesize/post_max_size 与网站限制');
    $tmp=(string)($file['tmp_name']??'');
    $actualSize=is_file($tmp)?(int)filesize($tmp):0;
    $size=(int)($file['size']??0);
    if ($size<=0 || $size>CLIENT_RELEASE_LIMIT || $actualSize!==$size)
        throw new RuntimeException('更新 ZIP 大小不正确或超过 50MB 限制');
    $original=basename((string)($file['name']??''));
    if (!preg_match('/^[a-zA-Z0-9_.-]{1,160}\.zip$/iD',$original)) throw new RuntimeException('文件名称须为英文字母、数字或下划线，且后缀为 ZIP');
    $platform=release_platform((string)($post['platform']??'core'));
    $channel=release_channel((string)($post['channel']??'stable'));
    $version=trim((string)($post['version']??''));
    $min=trim((string)($post['min_client']??'0.7.1'));
    if (!valid_version($version) || !valid_version($min)) throw new RuntimeException('版本号必须为 1.2.3 格式');
    $notes=trim((string)($post['notes']??''));
    if (strlen($notes)>1000 || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F]/',$notes)) throw new RuntimeException('版本说明无效');
    inspect_release_zip((string)$file['tmp_name']);
    $store=release_store();
    $random=bin2hex(random_bytes(20)).'.zip';
    $path=$store.'/'.$random;
    if (!move_uploaded_file((string)$file['tmp_name'],$path)) throw new RuntimeException('保存更新 ZIP 失败');
    @chmod($path,0600);
    try {
        $hash=hash_file('sha256',$path);
        if (!is_string($hash)) throw new RuntimeException('更新文件校验失败');
        [$secret,$pub]=release_keypair();
        $manifest=[
            'format'=>1,'platform'=>$platform,'channel'=>$channel,'version'=>$version,
            'min_client'=>$min,'filename'=>$original,'size_bytes'=>filesize($path),
            'sha256'=>$hash,'notes'=>$notes,'released_at'=>gmdate('Y-m-d\TH:i:s\Z')
        ];
        $raw=json_encode($manifest,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
        $signature=base64_encode(sodium_crypto_sign_detached($raw,$secret));
        sql('INSERT INTO phonehub_releases(platform,channel,version,min_client,notes,filename,storage_name,size_bytes,sha256,manifest,signature) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
            [$platform,$channel,$version,$min,$notes,$original,$random,filesize($path),$hash,$raw,$signature]);
        $id=(int)db()->lastInsertId();
        audit('release_publish',$platform.'/'.$channel.' v'.$version);
        return ['id'=>$id,'version'=>$version,'platform'=>$platform,'channel'=>$channel,'sha256'=>$hash,'public_key'=>base64_encode($pub)];
    } catch(Throwable $e) { @unlink($path);throw $e; }
}
function release_toggle(int $id): array {
    require_global_admin();
    $row=sql('SELECT id,platform,version,enabled FROM phonehub_releases WHERE id=?',[$id])->fetch();
    if (!$row) throw new RuntimeException('更新版本不存在');
    $next=!(int)$row['enabled']?1:0;
    sql('UPDATE phonehub_releases SET enabled=? WHERE id=?',[$next,$id]);
    audit('release_toggle',$row['platform'].' v'.$row['version'].' enabled='.$next);
    return ['message'=>$next?'版本已启用':'版本已停用','enabled'=>$next];
}
/**
 * Permanently remove an obsolete, disabled *client* core ZIP and its release
 * metadata. Never touches self-updater files, signatures, or active releases.
 * Only the protected owner may delete, with newer enabled core in the same
 * channel as a mandatory rollback-safe replacement.
 */
function release_delete_obsolete_core(int $id): array {
    require_owner();
    if ($id<1) throw new RuntimeException('旧版本 ID 不正确');
    $pdo=db();
    $pdo->beginTransaction();
    $quarantine=null;$original=null;
    try {
        $record=sql('SELECT id,platform,channel,version,enabled,storage_name
            FROM phonehub_releases WHERE id=? FOR UPDATE',[$id])->fetch();
        if (!$record) throw new RuntimeException('该更新版本不存在，请刷新页面');
        if ($record['platform']!=='core')
            throw new RuntimeException('仅允许删除旧版 core 客户端更新包');
        if ((int)$record['enabled']!==0)
            throw new RuntimeException('请先停用旧版 core，再进行永久删除');
        $others=sql("SELECT version,enabled FROM phonehub_releases
            WHERE platform='core' AND channel=? FOR UPDATE",[$record['channel']])->fetchAll();
        $hasNewerEnabled=false;
        foreach ($others as $candidate) {
            if ((int)$candidate['enabled']===1 &&
                version_compare((string)$candidate['version'],(string)$record['version'],'>')) {
                $hasNewerEnabled=true;break;
            }
        }
        if (!$hasNewerEnabled)
            throw new RuntimeException('同一渠道没有仍启用的更新版 core；禁止删除唯一可用或最新版本');
        $file=(string)$record['storage_name'];
        if (!preg_match('/^[0-9a-f]{40}\\.zip$/D',$file))
            throw new RuntimeException('旧版 core 的更新文件路径异常，禁止删除');
        if ((int)sql('SELECT COUNT(*) FROM phonehub_releases
            WHERE storage_name=? AND id<>?',[$file,$id])->fetchColumn()>0)
            throw new RuntimeException('该 ZIP 仍被其他版本引用，不允许删除');
        $original=release_store().'/'.$file;
        if (is_link($original) || (file_exists($original) && !is_file($original)))
            throw new RuntimeException('旧版更新文件不是普通 ZIP 文件，禁止删除');
        if (is_file($original)) {
            // Move out of the published path *before* committing the database
            // mutation. Restore the original if SQL or audit fails.
            $quarantine=$original.'.retired-'.bin2hex(random_bytes(12));
            if (!@rename($original,$quarantine))
                throw new RuntimeException('更新文件无法移入临时回收位置，未删除数据库记录');
        }
        $deleted=sql('DELETE FROM phonehub_releases WHERE id=?',[$id])->rowCount();
        if ($deleted!==1) throw new RuntimeException('旧版本数据库删除失败');
        audit('release_delete','core/'.$record['channel'].' v'.$record['version'].' #'.$id);
        $pdo->commit();
    } catch (Throwable $e) {
        if ($pdo->inTransaction())$pdo->rollBack();
        if ($quarantine!==null && is_file($quarantine) && $original!==null)
            @rename($quarantine,$original);
        throw $e;
    }
    $cleanupPending=$quarantine!==null && !@unlink($quarantine);
    if ($cleanupPending)
        error_log('PhoneHub retired core ZIP cleanup pending: '.basename((string)$quarantine));
    return ['deleted'=>true,'file_cleanup_pending'=>$cleanupPending,
        'message'=>$cleanupPending
            ? '旧版 core 已从发布列表移除；回收文件尚未能删除，请检查服务器更新目录'
            : '旧版 core 已永久删除（版本记录及其 ZIP）'];
}
/**
 * Streaming semantic release ordering. Keeping only the highest N rows in
 * memory avoids interpreting most-recent database IDs as version precedence.
 * Tie-breaks prefer the newest ID, while semver always decides first.
 */
function release_top_version_rows(PDOStatement $cursor,int $limit): array {
    if($limit<1 || $limit>100) throw new RuntimeException('版本查询条数无效');
    $top=[];
    while($row=$cursor->fetch(PDO::FETCH_ASSOC)) {
        $top[]=$row;
        usort($top,static function(array $a,array $b): int {
            $compare=version_compare((string)$b['version'],(string)$a['version']);
            return $compare!==0?$compare:((int)$b['id']<=>(int)$a['id']);
        });
        if(count($top)>$limit)array_pop($top);
    }
    return $top;
}
function public_release(array $row): array {
    return [
        'id'=>(int)$row['id'],'platform'=>$row['platform'],'channel'=>$row['channel'],
        'version'=>$row['version'],'min_client'=>$row['min_client'],
        'manifest'=>base64_encode((string)$row['manifest']),'signature'=>$row['signature'],
        'public_key'=>release_public_key(),'sha256'=>$row['sha256'],
        'size_bytes'=>(int)$row['size_bytes'],'filename'=>$row['filename'],
        'notes'=>$row['notes']
    ];
}
