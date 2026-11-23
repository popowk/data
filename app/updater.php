<?php
declare(strict_types=1);
// GitHub 镜像更新器。仅由已登录管理员通过 index.php 调用。
const UPDATE_ARCHIVE = 'https://git.wksite.cn/popowk/data/archive/refs/heads/main.zip';
const UPDATE_MAX_BYTES = 16777216;
const UPDATE_FILES = [
    'index.php','install.php','version.json','.htaccess',
    'app/core.php','app/accounts.php','app/updater.php','app/features.php',
    'app/devices.php','app/device_admin.php','app/signing_admin.php',
    'app/releases.php','app/release_admin.php','app/automation.php','app/ai.php','app/mobile.php',
    'api/phonehub.php','api/extensions.php','automation/v1/index.php','docs/自动化核心更新API-v0.5.12.md','deploy/nginx-automation.conf','docs/客户端接入API-v0.5.md','docs/运维备份与升级.md','docs/设备管理与签名-v0.5.2.md','tools/backup-crypto.php','tools/backup-server.php','tools/sign-self-update.php','tools/bootstrap-self-update.php','assets/app.css','assets/app.js'
];

/**
 * V3-only signed inventory since v0.5.20. Its signed tombstone permits
 * deleting only the retired gateway stub; never arbitrary paths, storage
 * configuration, private keys or other business files.
 */
const UPDATE_V3_REMOVABLE_FILES = ['app/gateway.php'];

/**
 * Fail before touching live files. The update catalog is an exact runtime
 * manifest: optional files must be removed from UPDATE_FILES intentionally.
 * TOKEN_PARSE checks PHP syntax without executing downloaded code.
 */
function update_validate_files(array $files,?array $requiredPaths=null): void {
    $requiredPaths=$requiredPaths??UPDATE_FILES;
    foreach ($requiredPaths as $path) {
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
    if (count($files)!==count($requiredPaths) ||
        array_diff(array_keys($files),$requiredPaths))
        throw new RuntimeException('更新包包含未经授权的额外文件');
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
/**
 * V3 signed manifest format 2:
 * {"format":2,"version":"x.y.z","files":{"path":"sha256",...},"remove":[]}
 * Path set and permitted removals are constrained by installed policy.
 * The signature is verified BEFORE trusting even the filename list.
 */
function update_v3_catalog_paths(array $remove): array {
    if (array_filter($remove,static fn($p)=>!is_string($p)) ||
        $remove!==array_values(array_unique($remove)) ||
        array_diff($remove,UPDATE_V3_REMOVABLE_FILES))
        throw new RuntimeException('签名更新清单包含未经批准的删除目标');
    $list=array_values(array_diff(UPDATE_FILES,$remove));
    if (!in_array('app/updater.php',$list,true) ||
        !in_array('version.json',$list,true) || !in_array('index.php',$list,true))
        throw new RuntimeException('更新清单缺少不可删除的核心模块');
    return $list;
}
function update_v3_manifest(array $files,string $version,array $remove=[]): string {
    $paths=update_v3_catalog_paths($remove);
    if (array_diff(array_keys($files),$paths) || array_diff($paths,array_keys($files)))
        throw new RuntimeException('V3 清单文件集与安全策略不一致');
    update_validate_files($files,$paths);
    $hashes=[];
    foreach($paths as $path) $hashes[$path]=hash('sha256',$files[$path]);
    ksort($hashes,SORT_STRING);
    return json_encode(['format'=>2,'version'=>$version,'files'=>$hashes,'remove'=>$remove],
        JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
}
function update_v3_verify_catalog(string $version,?string $manifest,?string $signature,string $publicKey): array {
    if (!extension_loaded('sodium')) throw new RuntimeException('Ed25519 验签必须启用 sodium');
    $sig=is_string($signature)?base64_decode(trim($signature),true):false;
    if (!is_string($manifest) || !is_string($sig) ||
        strlen($sig)!==SODIUM_CRYPTO_SIGN_BYTES ||
        !sodium_crypto_sign_verify_detached($sig,$manifest,$publicKey))
        throw new RuntimeException('V3 更新签名缺失或不可信，拒绝安装');
    $data=json_decode($manifest,true);
    if (!is_array($data) || array_keys($data)!==['format','version','files','remove'] ||
        $data['format']!==2 || $data['version']!==$version ||
        !is_array($data['files']) || !is_array($data['remove']))
        throw new RuntimeException('V3 签名清单格式或版本错误');
    $paths=update_v3_catalog_paths($data['remove']);
    $actual=array_keys($data['files']);
    if (array_diff($paths,$actual) || array_diff($actual,$paths) ||
        count($actual)!==count($paths))
        throw new RuntimeException('V3 清单包含未知文件或缺少必要文件');
    foreach ($data['files'] as $path=>$hash) {
        if (!is_string($hash) || !preg_match('/^[a-f0-9]{64}$/D',$hash))
            throw new RuntimeException('V3 更新文件摘要格式错误');
    }
    return $data;
}
function update_v3_verify_files(array $files,array $catalog): void {
    $paths=update_v3_catalog_paths($catalog['remove']);
    update_validate_files($files,$paths);
    foreach ($paths as $path) {
        if (!hash_equals($catalog['files'][$path],hash('sha256',$files[$path])))
            throw new RuntimeException('V3 更新文件签名摘要不一致：'.$path);
    }
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
            // Read a small, untrusted version string only to match it against
            // the V3 signature. File paths and removals are trusted only after
            // independent Ed25519 verification with the pinned public key.
            $versionBytes=$zip->getFromName($prefix.'version.json');
            if (!is_string($versionBytes) || strlen($versionBytes)>4096)
                throw new RuntimeException('更新版本文件不可读取或过大');
            $version=json_decode($versionBytes,true);
            $number=is_array($version)?($version['version']??null):null;
            if (!is_string($number) ||
                !preg_match('/^\d+\.\d+\.\d+(?:[-.][A-Za-z0-9.]+)?$/D',$number))
                throw new RuntimeException('远端版本号格式不正确');
            $trusted=update_trust_public_key(APP_STORE);
            if ($trusted===null)
                throw new RuntimeException('V3 更新要求固定 Ed25519 公钥；请先安全配置 storage/self-update-trust.pub');
            $manifest=$zip->getFromName($prefix.'deploy/self-update-manifest-v3.json');
            $signature=$zip->getFromName($prefix.'deploy/self-update-manifest-v3.sig');
            $catalog=update_v3_verify_catalog($number,
                is_string($manifest)?$manifest:null,
                is_string($signature)?$signature:null,$trusted);
            $paths=array_keys($catalog['files']);
            $files=[];
            foreach ($paths as $path) {
                $index=$zip->locateName($prefix.$path);
                if ($index===false) throw new RuntimeException('V3 清单文件缺失：'.$path);
                $stat=$zip->statIndex($index);
                if (($stat['size']??0)>2097152) throw new RuntimeException('更新文件大小异常');
                if ($zip->getExternalAttributesIndex($index,$opsys,$attrs) && $opsys===ZipArchive::OPSYS_UNIX) {
                    $type=(($attrs >> 16) & 0170000);
                    if ($type!==0 && $type!==0100000)
                        throw new RuntimeException('更新包含非常规文件，已拒绝');
                }
                $bytes=$zip->getFromIndex($index);
                if (!is_string($bytes)) throw new RuntimeException('ZIP 文件读取失败');
                $files[$path]=$bytes;
            }
            update_v3_verify_files($files,$catalog);
            return ['version'=>$number,'files'=>$files,'remove'=>$catalog['remove'],
                'signed'=>true,'signature_required'=>true,'signature_format'=>3];
        } finally {$zip->close();}
    } finally {@unlink($file);}
}
function missing_runtime_modules(): array {
    $required=['app/accounts.php','app/features.php','app/releases.php','app/release_admin.php','app/automation.php','automation/v1/index.php','app/ai.php',
        'app/devices.php','app/device_admin.php','app/signing_admin.php',
        'api/phonehub.php','api/extensions.php','tools/backup-crypto.php','tools/backup-server.php','tools/sign-self-update.php','tools/bootstrap-self-update.php'];
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
        'signature_format'=>$archive['signature_format']??null,
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
        $checks[]=['name'=>'MySQL 数据库','status'=>$migrations>=17?'ok':'warning',
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
    $checks[]=['name'=>'更新清单迁移准备','status'=>'ok',
        'detail'=>'仅支持 V3 固定公钥签名更新；允许签名清理历史 app/gateway.php 占位文件'];
    $checks[]=['name'=>'Nginx 存储目录访问限制','status'=>'warning',
        'detail'=>'需在宝塔确认 /license/storage/ 被拒绝访问；本地文件检查无法证明公网访问控制'];
    $recipient=APP_STORE.'/backup-recipient.pub';
    $backupKeyOk=is_file($recipient) && !is_link($recipient) &&
        extension_loaded('sodium') && filesize($recipient)===SODIUM_CRYPTO_BOX_PUBLICKEYBYTES;
    $checks[]=['name'=>'加密备份接收公钥','status'=>$backupKeyOk?'ok':'warning',
        'detail'=>$backupKeyOk?'已配置 Curve25519 备份公钥；可由 CLI 工具生成加密备份':'未配置 32 字节备份公钥，或格式不正确；CLI 加密备份暂不可用'];
    $checks[]=['name'=>'备份加密工具','status'=>is_file(APP_ROOT.'/tools/backup-server.php') &&
        is_file(APP_ROOT.'/tools/backup-crypto.php')?'ok':'error',
        'detail'=>is_file(APP_ROOT.'/tools/backup-server.php') &&
        is_file(APP_ROOT.'/tools/backup-crypto.php')?'命令行加密备份工具文件存在（未执行数据库导出）':'加密备份工具文件不完整'];
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
/**
 * Check each path component under the trusted installation root. If $create
 * is false, the nearest existing ancestor must be writable; missing nested
 * directories are valid for new runtime modules.
 *
 * Never follow symlinks or overwrite a non-directory. The installer creates
 * missing directories only AFTER all files have been staged and backed up,
 * and records each one so rollback can remove empty directories it created.
 */
function update_target_parent(string $root,string $path,bool $create,array &$createdDirs): void {
    $relative=dirname($path);
    $dir=$root;
    if (is_link($dir) || !is_dir($dir))
        throw new RuntimeException('更新网站根目录不可用');
    if ($relative==='.') {
        if (!is_writable($dir)) throw new RuntimeException('更新目标目录不可写：'.$path);
        return;
    }
    foreach (explode('/',$relative) as $part) {
        if (!preg_match('/^[A-Za-z0-9_.-]+$/D',$part) || $part==='.' || $part==='..')
            throw new RuntimeException('更新目标目录路径无效：'.$path);
        $next=$dir.'/'.$part;
        if (is_link($next))
            throw new RuntimeException('更新路径包含符号链接：'.$path);
        if (is_dir($next)) {
            $dir=$next;
            continue;
        }
        if (file_exists($next))
            throw new RuntimeException('更新目标父目录不是目录：'.$path);
        if (!is_writable($dir))
            throw new RuntimeException('更新目标目录不可写：'.$path);
        if (!$create) return; // Remaining descendants cannot yet exist.
        if (!@mkdir($next,0755) || is_link($next) || !is_dir($next))
            throw new RuntimeException('无法安全创建更新目标目录：'.$path);
        $createdDirs[]=$next;
        $dir=$next;
    }
    if (!is_writable($dir)) throw new RuntimeException('更新目标目录不可写：'.$path);
}
function update_install_files(array $files,string $root,string $store,?callable $beforeReplace=null,array $remove=[]): array {
    $allowed=update_v3_catalog_paths($remove);
    update_validate_files($files,$allowed);
    $root=rtrim($root,'/');
    $store=rtrim($store,'/');
    $nonce=bin2hex(random_bytes(6));
    $stage=$store.'/update-stage-'.$nonce;
    $backup=$store.'/backups/'.gmdate('Ymd-His').'-'.$nonce;
    if (!is_dir($store) || !mkdir($stage,0700))
        throw new RuntimeException('更新暂存目录不可写');
    $installed=[];$changed=[];$createdDirs=[];
    try {
        // Pre-stage and verify the full archive before any live replacement.
        foreach ($files as $path=>$bytes) {
            if (!in_array($path,UPDATE_FILES,true)) throw new RuntimeException('更新文件不在白名单内');
            $dest=$root.'/'.$path;
            if (is_link($dest))
                throw new RuntimeException('更新路径包含符号链接：'.$path);
            if (file_exists($dest) && !is_file($dest))
                throw new RuntimeException('更新目标不是普通文件：'.$path);
            update_target_parent($root,$path,false,$createdDirs);
            $source=$stage.'/'.$path;
            if (!is_dir(dirname($source)) && !mkdir(dirname($source),0700,true))
                throw new RuntimeException('创建更新暂存目录失败：'.$path);
            if (file_put_contents($source,$bytes,LOCK_EX)!==strlen($bytes) ||
                !hash_equals(hash('sha256',$bytes),(string)hash_file('sha256',$source)))
                throw new RuntimeException('更新文件暂存校验失败：'.$path);
        }

        // Check signed, allowlisted removals BEFORE touching any live file.
        // A symlinked target must never be followed or removed as an update.
        foreach ($remove as $path) {
            $dest=$root.'/'.$path;
            if (is_link($dest)) throw new RuntimeException('删除路径包含符号链接：'.$path);
            if (file_exists($dest) && !is_file($dest))
                throw new RuntimeException('删除目标不是普通文件：'.$path);
            update_target_parent($root,$path,false,$createdDirs);
        }
        if (!mkdir($backup,0700,true))
            throw new RuntimeException('无法创建更新备份目录');
        foreach (array_values(array_unique(array_merge(array_keys($files),$remove))) as $path) {
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
            if ($path==='version.json') {
                // Delete retired files only AFTER current modules have been
                // staged and backed up, but BEFORE publishing version.json.
                foreach ($remove as $retired) {
                    if ($beforeReplace!==null) $beforeReplace($retired,count($installed));
                    $retiredPath=$root.'/'.$retired;
                    if (is_link($retiredPath) ||
                        (file_exists($retiredPath) && !is_file($retiredPath)))
                        throw new RuntimeException('更新删除目标异常：'.$retired);
                    if (is_file($retiredPath)) {
                        if (!unlink($retiredPath)) throw new RuntimeException('旧文件删除失败：'.$retired);
                        $installed[]=$retired;
                    }
                }
            }
            if ($beforeReplace!==null) $beforeReplace($path,count($installed));
            $dest=$root.'/'.$path;
            update_target_parent($root,$path,true,$createdDirs);
            $dir=dirname($dest);
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
        foreach ($remove as $retired) {
            if (file_exists($root.'/'.$retired) || is_link($root.'/'.$retired))
                throw new RuntimeException('旧文件删除后仍存在：'.$retired);
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
        // Roll back new nested directories in reverse order, but do not remove
        // pre-existing folders or delete any non-empty directories.
        foreach (array_reverse($createdDirs) as $dir) {
            if (is_dir($dir) && !is_link($dir) && !@rmdir($dir))
                $restored=false;
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
        $result=update_install_files($archive['files'],APP_ROOT,APP_STORE,null,$archive['remove']??[]);
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
