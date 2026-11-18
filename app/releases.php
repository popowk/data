<?php
declare(strict_types=1);
// Client core release publishing, kept separate from admin panel software self-updates.
const CLIENT_RELEASE_LIMIT=52428800; // 50 MiB compressed
const SCRCPY_DEFAULT_DOWNLOAD_URL='https://down.tmd.pet/scrcpy/scrcpy-win64-v5.0.1.zip';
const SCRCPY_DOWNLOAD_CACHE_SECONDS=300;

/** Validate a public client download target; the server never fetches it. */
function scrcpy_validate_download_url(string $url): string {
    $url=trim($url);
    if ($url==='' || strlen($url)>512 || preg_match('/[\\x00-\\x20\\x7f]/',$url))
        throw new RuntimeException('scrcpy 下载地址不能为空、包含空格或超过 512 字节');
    if (filter_var($url,FILTER_VALIDATE_URL)===false)
        throw new RuntimeException('scrcpy 下载地址必须是完整 URL');
    $parts=parse_url($url);
    if (!is_array($parts) || strtolower((string)($parts['scheme']??''))!=='https'
        || !is_string($parts['host']??null)
        || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])
        || (isset($parts['port']) && $parts['port']!==443))
        throw new RuntimeException('scrcpy 下载地址仅允许无凭据的 HTTPS 链接（标准 443 端口）');
    $host=$parts['host'];
    if (filter_var($host,FILTER_VALIDATE_IP)!==false ||
        filter_var($host,FILTER_VALIDATE_DOMAIN,FILTER_FLAG_HOSTNAME)===false ||
        !str_contains($host,'.'))
        throw new RuntimeException('scrcpy 下载地址需要有效的公开域名，不接受 IP 或本地域名');
    if (!preg_match('~^/.+\\.zip$~iD',(string)($parts['path']??'')))
        throw new RuntimeException('scrcpy 下载地址必须以 .zip 文件结尾');
    return $url;
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
function latest_release(string $platform,string $channel): ?array {
    // Version strings are semantic rather than lexical. Filter in PHP after DB access.
    $rows=sql('SELECT * FROM phonehub_releases WHERE platform=? AND channel=? AND enabled=1 ORDER BY id DESC LIMIT 500',
        [$platform,$channel])->fetchAll();
    usort($rows,static fn($a,$b)=>version_compare($b['version'],$a['version']));
    return $rows[0]??null;
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
