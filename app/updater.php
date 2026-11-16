<?php
declare(strict_types=1);
// GitHub 镜像更新器。仅由已登录管理员通过 index.php 调用。
const UPDATE_ARCHIVE = 'https://git.wksite.cn/popowk/data/archive/refs/heads/main.zip';
const UPDATE_MAX_BYTES = 16777216;
const UPDATE_FILES = [
    'index.php','install.php','version.json','.htaccess',
    'app/core.php','app/accounts.php','app/updater.php','app/features.php','app/gateway.php',
    'app/releases.php','app/release_admin.php','app/ai.php','app/mobile.php',
    'api/phonehub.php','api/extensions.php','docs/客户端接入API-v0.3.md','docs/客户端接入API-v0.4.md','docs/客户端接入API-v0.5.md','docs/运维备份与升级.md','tools/backup-crypto.php','tools/backup-server.php','tools/sign-self-update.php','assets/app.css','assets/app.js'
];

/**
 * Fail before touching live files. The update catalog is an exact runtime
 * manifest: optional files must be removed from UPDATE_FILES intentionally.
 * TOKEN_PARSE checks PHP syntax without executing downloaded code.
 */
function update_validate_files(array $files): void {
    foreach (UPDATE_FILES as $path) {
        if (!array_key_exists($path,$files) || !is_string($files[$path]) || $files[$path]==='')
            throw new RuntimeException('更新包缺少必要文件：'.$path);
        if (strlen($files[$path])>2097152)
            throw new RuntimeException('更新文件过大：'.$path);
        if (str_ends_with($path,'.php')) {
            if (!str_starts_with(ltrim($files[$path]),'<?php'))
                throw new RuntimeException('PHP 更新文件不包含有效的 PHP 文件头：'.$path);
            try { token_get_all($files[$path], TOKEN_PARSE); }
            catch (ParseError $e) {
                throw new RuntimeException('PHP 更新文件存在语法错误：'.$path.'（'.$e->getMessage().'）');
            }
        }
    }
    $manifest=json_decode($files['version.json'],true);
    if (!is_array($manifest) || !is_string($manifest['version']??null))
        throw new RuntimeException('更新包 version.json 格式错误');
}
/**
 * Owner-provisioned pinned trust root for signed server updates.
 * Private signing key must remain OFF the web server and out of GitHub.
 * Legacy installations may update without a pin; once installed, signatures
 * are mandatory. This is not trust-on-first-use.
 */
function update_trust_public_key(string $store): ?string {
    $path=rtrim($store,'/').'/self-update-trust.pub';
    if (is_link($path)) throw new RuntimeException('更新信任公钥不能是符号链接');
    if (!is_file($path)) return null;
    if (!extension_loaded('sodium')) throw new RuntimeException('独立签名更新需要 PHP sodium 扩展');
    $key=file_get_contents($path);
    if (!is_string($key) || strlen($key)!==SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES)
        throw new RuntimeException('更新签名信任公钥格式错误，已拒绝安装');
    return $key;
}
function update_signed_manifest(array $files,string $version): string {
    $hashes=[];
    foreach(UPDATE_FILES as $path) {
        if (!isset($files[$path]) || !is_string($files[$path]))
            throw new RuntimeException('签名清单缺少程序文件：'.$path);
        $hashes[$path]=hash('sha256',$files[$path]);
    }
    ksort($hashes,SORT_STRING);
    return json_encode(['format'=>1,'version'=>$version,'files'=>$hashes],
        JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
}
function update_verify_signed_archive(array $files,string $version,?string $manifest,?string $signature,string $publicKey): void {
    if (!extension_loaded('sodium')) throw new RuntimeException('独立签名更新需要 PHP sodium 扩展');
    if (!is_string($manifest) || !is_string($signature) || $manifest==='' || $signature==='')
        throw new RuntimeException('更新源缺少独立签名清单，已拒绝安装');
    $sig=base64_decode(trim($signature),true);
    if (!is_string($sig) || strlen($sig)!==SODIUM_CRYPTO_SIGN_BYTES ||
        !sodium_crypto_sign_verify_detached($sig,$manifest,$publicKey))
        throw new RuntimeException('更新包独立 Ed25519 签名不可信，已拒绝安装');
    $decoded=json_decode($manifest,true);
    if (!is_array($decoded) || ($decoded['format']??null)!==1 ||
        ($decoded['version']??null)!==$version || !is_array($decoded['files']??null))
        throw new RuntimeException('已签名更新清单版本或格式错误');
    $expected=json_decode(update_signed_manifest($files,$version),true,512,JSON_THROW_ON_ERROR);
    if ($decoded['files']!==$expected['files'])
        throw new RuntimeException('更新内容与已签名文件摘要不一致，已拒绝安装');
}
function update_download(string $destination): void {
    if (!extension_loaded('curl') || !extension_loaded('zip')) throw new RuntimeException('请在 PHP 中启用 curl 与 zip 扩展');
    $url=UPDATE_ARCHIVE;
    for ($redirect=0; $redirect<3; $redirect++) {
        if (parse_url($url,PHP_URL_SCHEME)!=='https' || parse_url($url,PHP_URL_HOST)!=='git.wksite.cn')
            throw new RuntimeException('更新地址被重定向至未授权的站点，已拒绝下载');
        $fp=fopen($destination,'wb');if (!$fp) throw new RuntimeException('更新缓存目录不可写');
        $size=0;$location='';
        $ch=curl_init($url);
        curl_setopt_array($ch,[
            CURLOPT_FOLLOWLOCATION=>false,CURLOPT_CONNECTTIMEOUT=>12,CURLOPT_TIMEOUT=>90,
            CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,
            CURLOPT_USERAGENT=>'PhoneHub-Updater/'.app_version(),
            CURLOPT_HTTPHEADER=>['Accept: application/zip,application/octet-stream'],
            CURLOPT_HEADERFUNCTION=>static function($curl,$line) use (&$location) {
                if (stripos($line,'Location:')===0) $location=trim(substr($line,9));
                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION=>static function($curl,$chunk) use ($fp,&$size) {
                $size+=strlen($chunk);
                return $size<=UPDATE_MAX_BYTES ? fwrite($fp,$chunk) : 0;
            }
        ]);
        $ok=curl_exec($ch);$status=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE);
        curl_close($ch);fclose($fp);
        if ($ok===false || $size>UPDATE_MAX_BYTES) throw new RuntimeException('更新下载失败或 ZIP 文件超过 16MB');
        if ($status>=300 && $status<400 && $location!=='') {
            if (str_starts_with($location,'/')) $location='https://git.wksite.cn'.$location;
            $url=$location;continue;
        }
        if ($status!==200 || $size<100) throw new RuntimeException('镜像站未返回有效 ZIP 文件（HTTP '.$status.'），请检查镜像下载接口');
        return;
    }
    throw new RuntimeException('更新下载重定向次数过多');
}

function update_archive(): array {
    if (!is_dir(APP_STORE) && !mkdir(APP_STORE,0700,true)) throw new RuntimeException('storage 目录不可写');
    $file=tempnam(APP_STORE,'update-');
    if ($file===false) throw new RuntimeException('无法创建更新缓存文件');
    try {
        update_download($file);
        $zip=new ZipArchive();
        if ($zip->open($file)!==true) throw new RuntimeException('镜像下载内容并非有效 ZIP 文件');
        try {
            if ($zip->numFiles>500) throw new RuntimeException('ZIP 文件条目过多');
            $prefix=null;
            for ($i=0;$i<$zip->numFiles;$i++) {
                $name=$zip->getNameIndex($i);
                if (is_string($name) && preg_match('~^[A-Za-z0-9_.-]+/version\.json$~D',$name)) { $prefix=substr($name,0,-strlen('version.json')); break; }
            }
            if ($prefix===null) throw new RuntimeException('更新包缺少 version.json');
            $files=[];
            foreach (UPDATE_FILES as $path) {
                $index=$zip->locateName($prefix.$path);
                if ($index===false) throw new RuntimeException('更新包缺少清单文件：'.$path);
                $stat=$zip->statIndex($index);
                if (($stat['size']??0)>2097152) throw new RuntimeException('更新文件大小异常');
                if ($zip->getExternalAttributesIndex($index,$opsys,$attrs) && $opsys===ZipArchive::OPSYS_UNIX) {
                    $type=(($attrs >> 16) & 0170000);
                    if ($type!==0 && $type!==0100000) throw new RuntimeException('更新包含非常规文件，已拒绝');
                }
                $bytes=$zip->getFromIndex($index);
                if ($bytes===false) throw new RuntimeException('ZIP 文件读取失败');
                $files[$path]=$bytes;
            }
            update_validate_files($files);
            $version=json_decode($files['version.json'],true);
            $number=(string)($version['version']??'');
            if (!preg_match('/^\d+\.\d+\.\d+(?:[-.][A-Za-z0-9.]+)?$/D',$number)) throw new RuntimeException('远端版本号格式不正确');
            $trusted=update_trust_public_key(APP_STORE);
            $verified=false;
            if ($trusted!==null) {
                $manifest=$zip->getFromName($prefix.'deploy/self-update-manifest.json');
                $signature=$zip->getFromName($prefix.'deploy/self-update-manifest.sig');
                update_verify_signed_archive($files,$number,
                    is_string($manifest)?$manifest:null,is_string($signature)?$signature:null,$trusted);
                $verified=true;
            }
            return ['version'=>$number,'files'=>$files,'signed'=>$verified,'signature_required'=>$trusted!==null];
        } finally {$zip->close();}
    } finally {@unlink($file);}
}
function missing_runtime_modules(): array {
    $required=['app/accounts.php','app/features.php','app/gateway.php','app/releases.php','app/release_admin.php','app/ai.php',
        'api/phonehub.php','api/extensions.php','tools/backup-crypto.php','tools/backup-server.php','tools/sign-self-update.php'];
    return array_values(array_filter($required,static fn($name)=>!is_file(APP_ROOT.'/'.$name)));
}
function check_update(): array {
    $archive=update_archive();
    $current=app_version();
    $missing=missing_runtime_modules();
    $newer=version_compare($archive['version'],$current,'>');
    return [
        'current'=>$current, 'latest'=>$archive['version'],
        'available'=>$newer || count($missing)>0,
        'repair'=>!$newer && count($missing)>0,
        'missing_modules'=>$missing,
        'signature_verified'=>$archive['signed'],
        'signature_required'=>$archive['signature_required'],
        'source'=>UPDATE_ARCHIVE
    ];
}
/**
 * Owner-only runtime preflight. Intentionally returns no credentials, absolute
 * filesystem paths, key contents, or publicly callable unauthenticated URL.
 */
function update_diagnostics(): array {
    $checks=[];
    $checks[]=['name'=>'PHP 运行版本','status'=>version_compare(PHP_VERSION,'8.2.0','>=')?'ok':'error',
        'detail'=>'PHP '.PHP_VERSION.'（要求 8.2+）'];
    foreach (['pdo_mysql','curl','zip','sodium'] as $extension) {
        $checks[]=['name'=>'PHP 扩展 '.$extension,'status'=>extension_loaded($extension)?'ok':'error',
            'detail'=>extension_loaded($extension)?'已启用':'未启用'];
    }
    $missing=missing_runtime_modules();
    $checks[]=['name'=>'核心程序模块','status'=>$missing?'error':'ok',
        'detail'=>$missing?'缺失：'.implode('、',$missing):'全部存在'];
    $checks[]=['name'=>'数据目录可写','status'=>is_dir(APP_STORE)&&is_writable(APP_STORE)?'ok':'error',
        'detail'=>is_dir(APP_STORE)&&is_writable(APP_STORE)?'读写检查通过':'storage 目录不存在或不可写'];
    $backups=APP_STORE.'/backups';
    $canBackup=is_dir($backups)?is_writable($backups):(is_dir(APP_STORE)&&is_writable(APP_STORE));
    $checks[]=['name'=>'程序回滚备份目录','status'=>$canBackup?'ok':'error',
        'detail'=>$canBackup?'具备写入备份的条件':'备份目录不可写'];
    try {
        $migrations=(int)db()->query('SELECT COALESCE(MAX(version),0) FROM phonehub_admin_migrations')->fetchColumn();
        $checks[]=['name'=>'MySQL 数据库','status'=>$migrations>=6?'ok':'warning',
            'detail'=>'连接正常；数据结构版本 '.$migrations];
    } catch(Throwable $e) {
        error_log('PhoneHub runtime diagnostics database failure: '.get_class($e));
        $checks[]=['name'=>'MySQL 数据库','status'=>'error','detail'=>'数据库连接或迁移状态异常，请检查 PHP 错误日志'];
    }
    $signatureReady=false;
    try { $signatureReady=update_trust_public_key(APP_STORE)!==null; }
    catch (Throwable $e) {
        error_log('PhoneHub update trust key invalid: '.get_class($e));
        $checks[]=['name'=>'服务端更新签名','status'=>'error','detail'=>'固定信任公钥不正确，更新将被拒绝'];
    }
    if (!array_filter($checks,static fn($x)=>$x['name']==='服务端更新签名')) {
        $checks[]=['name'=>'服务端更新签名','status'=>$signatureReady?'ok':'warning',
            'detail'=>$signatureReady?'已配置固定 Ed25519 公钥，更新必须验签':'尚未配置独立信任公钥，仍为兼容模式的 HTTPS 镜像更新'];
    }
    $checks[]=['name'=>'Nginx 存储目录访问限制','status'=>'warning',
        'detail'=>'需在宝塔确认 /license/storage/ 被拒绝访问；本地文件检查无法证明公网访问控制'];
    $recipient=APP_STORE.'/backup-recipient.pub';
    $backupKeyOk=is_file($recipient) && !is_link($recipient) &&
        extension_loaded('sodium') && filesize($recipient)===SODIUM_CRYPTO_BOX_PUBLICKEYBYTES;
    $checks[]=['name'=>'加密备份接收公钥','status'=>$backupKeyOk?'ok':'warning',
        'detail'=>$backupKeyOk?'已配置 Curve25519 备份公钥；可由 CLI 工具生成加密备份':'未配置 32 字节备份公钥，或格式不正确；CLI 加密备份暂不可用'];
    $checks[]=['name'=>'异地备份与恢复验证','status'=>'warning',
        'detail'=>'无法通过网站判断宝塔任务或离线恢复是否成功；请检查定时任务、异地副本和恢复演练'];
    return ['checks'=>$checks,'summary'=>[
        'errors'=>count(array_filter($checks,static fn($x)=>$x['status']==='error')),
        'warnings'=>count(array_filter($checks,static fn($x)=>$x['status']==='warning'))
    ]];
}
function update_reset_opcache(): ?bool {
    if (!function_exists('opcache_reset')) return null;
    $enabled=filter_var((string)ini_get('opcache.enable'),FILTER_VALIDATE_BOOLEAN);
    if (!$enabled) return null;
    return @opcache_reset();
}
/**
 * Build every replacement in protected storage and back up every existing
 * destination before changing any live PHP file. Every destination is renamed
 * individually (atomic per file), so full zero-downtime multi-file atomics
 * still require a release-directory/symlink deployment outside this updater.
 *
 * The optional callback is a test-only failure injection point.
 */
function update_install_files(array $files,string $root,string $store,?callable $beforeReplace=null): array {
    update_validate_files($files);
    $root=rtrim($root,'/');
    $store=rtrim($store,'/');
    $nonce=bin2hex(random_bytes(6));
    $stage=$store.'/update-stage-'.$nonce;
    $backup=$store.'/backups/'.gmdate('Ymd-His').'-'.$nonce;
    if (!is_dir($store) || !mkdir($stage,0700))
        throw new RuntimeException('更新暂存目录不可写');
    $installed=[];$changed=[];
    try {
        // Pre-stage and verify the full archive before any live replacement.
        foreach ($files as $path=>$bytes) {
            if (!in_array($path,UPDATE_FILES,true)) throw new RuntimeException('更新文件不在白名单内');
            $dest=$root.'/'.$path;
            if (is_link($dest) || is_link(dirname($dest)))
                throw new RuntimeException('更新路径包含符号链接：'.$path);
            if (file_exists($dest) && !is_file($dest))
                throw new RuntimeException('更新目标不是普通文件：'.$path);
            $parent=dirname($dest);
            if (!is_dir($parent) && !is_dir(dirname($parent)))
                throw new RuntimeException('更新目标父目录不存在：'.$path);
            if (!is_writable(is_dir($parent)?$parent:dirname($parent)))
                throw new RuntimeException('更新目标目录不可写：'.$path);
            $source=$stage.'/'.$path;
            if (!is_dir(dirname($source)) && !mkdir(dirname($source),0700,true))
                throw new RuntimeException('创建更新暂存目录失败：'.$path);
            if (file_put_contents($source,$bytes,LOCK_EX)!==strlen($bytes) ||
                !hash_equals(hash('sha256',$bytes),(string)hash_file('sha256',$source)))
                throw new RuntimeException('更新文件暂存校验失败：'.$path);
        }

        if (!mkdir($backup,0700,true))
            throw new RuntimeException('无法创建更新备份目录');
        foreach ($files as $path=>$bytes) {
            $dest=$root.'/'.$path;
            if (!is_file($dest)) { $changed[$path]=false;continue; }
            $backupFile=$backup.'/'.$path;
            if (!is_dir(dirname($backupFile)) && !mkdir(dirname($backupFile),0700,true))
                throw new RuntimeException('创建更新备份目录失败：'.$path);
            if (!copy($dest,$backupFile) ||
                !hash_equals((string)hash_file('sha256',$dest),(string)hash_file('sha256',$backupFile)))
                throw new RuntimeException('更新备份校验失败：'.$path);
            $changed[$path]=$backupFile;
        }

        // Install the version manifest last so an interrupted installation
        // cannot appear fully upgraded based on version.json alone.
        $ordered=$files;
        $version=$ordered['version.json'];unset($ordered['version.json']);
        $ordered['version.json']=$version;
        foreach ($ordered as $path=>$bytes) {
            if ($beforeReplace!==null) $beforeReplace($path,count($installed));
            $dest=$root.'/'.$path;
            $dir=dirname($dest);
            if (!is_dir($dir) && !mkdir($dir,0755,true))
                throw new RuntimeException('无法创建更新目标目录：'.$path);
            $tmp=tempnam($dir,'.phup-');
            if ($tmp===false) throw new RuntimeException('创建更新目标临时文件失败：'.$path);
            try {
                if (!copy($stage.'/'.$path,$tmp) ||
                    !hash_equals(hash('sha256',$bytes),(string)hash_file('sha256',$tmp)))
                    throw new RuntimeException('更新目标写入校验失败：'.$path);
                @chmod($tmp,0644);
                if (!rename($tmp,$dest)) throw new RuntimeException('更新文件替换失败：'.$path);
                $installed[]=$path;
            } finally {
                if (is_file($tmp)) @unlink($tmp);
            }
        }
        foreach ($ordered as $path=>$bytes) {
            if (!is_file($root.'/'.$path) ||
                !hash_equals(hash('sha256',$bytes),(string)hash_file('sha256',$root.'/'.$path)))
                throw new RuntimeException('更新安装后校验失败：'.$path);
        }
        return ['backup'=>basename($backup),'installed_count'=>count($installed)];
    } catch(Throwable $e) {
        $restored=true;
        foreach (array_reverse($installed) as $path) {
            $dest=$root.'/'.$path;
            if (($changed[$path]??false)===false) {
                if (is_file($dest) && !@unlink($dest)) $restored=false;
                continue;
            }
            $tmp=@tempnam(dirname($dest),'.phrb-');
            if ($tmp===false) { $restored=false;continue; }
            try {
                if (!@copy($changed[$path],$tmp) ||
                    !@rename($tmp,$dest) ||
                    !hash_equals((string)hash_file('sha256',$changed[$path]),(string)hash_file('sha256',$dest)))
                    $restored=false;
            } finally {
                if (is_file($tmp)) @unlink($tmp);
            }
        }
        throw new RuntimeException($e->getMessage().($restored?'；已恢复升级前程序文件':'；自动恢复未完成，请检查备份目录'),0,$e);
    } finally {
        if (is_dir($stage)) {
            $iter=new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($stage,FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($iter as $item) {
                if ($item->isDir() && !$item->isLink()) @rmdir($item->getPathname());
                else @unlink($item->getPathname());
            }
            @rmdir($stage);
        }
    }
}
function apply_update(): array {
    if (!is_dir(APP_STORE)) throw new RuntimeException('storage 目录不存在');
    $lock=fopen(APP_STORE.'/update.lock','c+');
    if (!$lock || !flock($lock,LOCK_EX|LOCK_NB))
        throw new RuntimeException('另一个更新任务正在执行');
    try {
        $archive=update_archive();
        $latest=$archive['version'];$current=app_version();
        $missing=missing_runtime_modules();
        if (!version_compare($latest,$current,'>') && !$missing)
            return ['message'=>'当前已经是最新版本','version'=>$current];
        if (version_compare($latest,$current,'<'))
            throw new RuntimeException('远端更新版本低于当前版本，已拒绝降级');
        $result=update_install_files($archive['files'],APP_ROOT,APP_STORE);
        $cacheReset=update_reset_opcache();
        $message=$cacheReset===false
            ? '更新文件安装成功，但 PHP OPcache 未确认刷新；请重启 PHP-FPM 或 Web 服务'
            : '更新成功，已验证安装文件并保留备份';
        return ['message'=>$message,'version'=>$latest,'backup'=>$result['backup'],
            'installed_count'=>$result['installed_count'],'cache_reset'=>$cacheReset,
            'signature_verified'=>$archive['signed']];
    } finally {
        flock($lock,LOCK_UN);fclose($lock);
    }
}
