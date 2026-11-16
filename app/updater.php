<?php
declare(strict_types=1);
// GitHub 镜像更新器。仅由已登录管理员通过 index.php 调用。
const UPDATE_ARCHIVE = 'https://git.wksite.cn/popowk/data/archive/refs/heads/main.zip';
const UPDATE_MAX_BYTES = 16777216;
const UPDATE_FILES = [
    'index.php','install.php','version.json','README.md','.htaccess',
    'app/core.php','app/updater.php','app/features.php','app/gateway.php',
    'app/releases.php','app/release_admin.php',
    'api/phonehub.php','api/extensions.php','assets/app.css','assets/app.js'
];

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
                if ($index===false) continue;
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
            foreach (['index.php','install.php','app/core.php','app/updater.php','version.json'] as $must) {
                if (!isset($files[$must])) throw new RuntimeException('更新包缺少必要文件：'.$must);
            }
            $version=json_decode($files['version.json'],true);
            $number=(string)($version['version']??'');
            if (!preg_match('/^\d+\.\d+\.\d+(?:[-.][A-Za-z0-9.]+)?$/D',$number)) throw new RuntimeException('远端版本号格式不正确');
            return ['version'=>$number,'files'=>$files];
        } finally {$zip->close();}
    } finally {@unlink($file);}
}
function missing_runtime_modules(): array {
    $required=['app/features.php','app/gateway.php','app/releases.php','app/release_admin.php',
        'api/phonehub.php','api/extensions.php'];
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
        'source'=>UPDATE_ARCHIVE
    ];
}
function apply_update(): array {
    $lock=fopen(APP_STORE.'/update.lock','c+');
    if (!$lock || !flock($lock,LOCK_EX|LOCK_NB)) throw new RuntimeException('另一个更新任务正在执行');
    try {
        $archive=update_archive();$latest=$archive['version'];$current=app_version();
        $missing=missing_runtime_modules();
        if (!version_compare($latest,$current,'>') && !$missing)
            return ['message'=>'当前已经是最新版本','version'=>$current];
        $backup=APP_STORE.'/backups/'.gmdate('Ymd-His').'-'.bin2hex(random_bytes(4));
        if (!mkdir($backup,0700,true)) throw new RuntimeException('无法创建更新备份目录');
        $changed=[];$installed=[];
        try {
            foreach (array_keys($archive['files']) as $path) {
                $target=APP_ROOT.'/'.$path;
                if (is_link($target)) throw new RuntimeException('更新目标包含符号链接，已拒绝');
                if (!is_file($target)) { $changed[$path]=false; continue; }
                $dst=$backup.'/'.$path;
                if (!is_dir(dirname($dst)) && !mkdir(dirname($dst),0700,true)) throw new RuntimeException('备份目录不可写');
                if (!copy($target,$dst)) throw new RuntimeException('备份失败：'.$path);
                $changed[$path]=$dst;
            }
            // version.json 最后写入，尽可能避免半更新版本误判。
            $files=$archive['files'];$version=$files['version.json'];unset($files['version.json']);$files['version.json']=$version;
            foreach ($files as $path=>$bytes) {
                $dest=APP_ROOT.'/'.$path;$dir=dirname($dest);
                if (!is_dir($dir) && !mkdir($dir,0755,true)) throw new RuntimeException('无法创建目录：'.$path);
                $temp=tempnam($dir,'.phup-');
                if ($temp===false) throw new RuntimeException('无法写入更新临时文件：'.$path);
                if (file_put_contents($temp,$bytes,LOCK_EX)===false) { @unlink($temp);throw new RuntimeException('写入文件失败：'.$path); }
                @chmod($temp,0644);
                if (!rename($temp,$dest)) { @unlink($temp);throw new RuntimeException('替换文件失败：'.$path); }
                $installed[]=$path;
                if (function_exists('opcache_invalidate')) @opcache_invalidate($dest,true);
            }
            return ['message'=>'更新成功，原文件已备份','version'=>$latest,'backup'=>basename($backup)];
        } catch (Throwable $e) {
            $restored=true;
            foreach (array_reverse($installed) as $path) {
                $dest=APP_ROOT.'/'.$path;
                if ($changed[$path]===false) { if (!@unlink($dest)) $restored=false; }
                elseif (!@copy($changed[$path],$dest)) $restored=false;
                if (function_exists('opcache_invalidate')) @opcache_invalidate($dest,true);
            }
            throw new RuntimeException($e->getMessage().($restored?'；已尝试恢复原文件':'；回滚未完成，请使用备份目录手工恢复'));
        }
    } finally {flock($lock,LOCK_UN);fclose($lock);}
}
