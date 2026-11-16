<?php
declare(strict_types=1);
// CLI only. Never expose backup creation or private-key-based restore over HTTP.
if (PHP_SAPI!=='cli') {http_response_code(404);exit;}
require dirname(__DIR__).'/app/core.php';
require __DIR__.'/backup-crypto.php';

function ph_backup_key_file(string $path,int $length,bool $mustBeOffline): string {
    $real=realpath($path);
    $root=realpath(APP_ROOT);
    if (!$real || !is_file($real) || is_link($path) || ($mustBeOffline && $root &&
        ($real===$root || str_starts_with($real,$root.DIRECTORY_SEPARATOR))))
        throw new RuntimeException('密钥不存在或不在允许的位置');
    $bytes=file_get_contents($real);
    if (!is_string($bytes) || strlen($bytes)!==$length)
        throw new RuntimeException('密钥长度无效');
    return $bytes;
}
function ph_backup_safe_outdir(string $path,bool $mustExist): string {
    if (!str_starts_with($path,'/')) throw new RuntimeException('必须使用站点目录之外的绝对路径');
    $root=realpath(APP_ROOT);
    $existing=$mustExist?realpath($path):realpath(dirname($path));
    if (!$existing || is_link($path) || ($root &&
        ($existing===$root || str_starts_with($existing,$root.DIRECTORY_SEPARATOR))))
        throw new RuntimeException('备份和恢复目标必须位于网站目录之外');
    if ($mustExist && (!is_dir($existing) || !is_writable($existing)))
        throw new RuntimeException('备份目录不存在或不可写');
    if (!$mustExist && file_exists($path)) throw new RuntimeException('恢复目标必须是不存在的新目录');
    return $mustExist?$existing:$path;
}
function ph_backup_config_escape(string $value): string {
    if (str_contains($value,"\r") || str_contains($value,"\n") || str_contains($value,"\0"))
        throw new RuntimeException('数据库凭据包含不允许的换行或控制字符');
    return '"'.str_replace(['\\','"'],['\\\\','\\"'],$value).'"';
}
function ph_backup_dump($output,string &$state): array {
    $configPath=APP_STORE.'/config.php';
    if (!is_file($configPath) || is_link($configPath)) throw new RuntimeException('数据库配置文件不存在或不是普通文件');
    $cfg=require $configPath;
    foreach(['db_host','db_port','db_name','db_user','db_pass'] as $key) {
        if (!is_array($cfg) || !isset($cfg[$key])) throw new RuntimeException('数据库配置字段缺失：'.$key);
    }
    $db=(string)$cfg['db_name'];
    if (!preg_match('/^[A-Za-z0-9_-]{1,64}$/D',$db))
        throw new RuntimeException('数据库名称不安全');
    $defaults=tempnam(APP_STORE,'phmysqldump-');
    $stderr=tempnam(APP_STORE,'phmysqldump-err-');
    if ($defaults===false || $stderr===false) throw new RuntimeException('无法创建临时连接配置');
    @chmod($defaults,0600);@chmod($stderr,0600);
    $process=null;$pipes=[];
    try {
        $ini="[client]\n".
            "host=".ph_backup_config_escape((string)$cfg['db_host'])."\n".
            "port=".ph_backup_config_escape((string)$cfg['db_port'])."\n".
            "user=".ph_backup_config_escape((string)$cfg['db_user'])."\n".
            "password=".ph_backup_config_escape((string)$cfg['db_pass'])."\n".
            "default-character-set=utf8mb4\n";
        if (file_put_contents($defaults,$ini,LOCK_EX)!==strlen($ini))
            throw new RuntimeException('无法写入 MySQL 临时凭据文件');
        $binary=getenv('PHONEHUB_MYSQLDUMP')?:'mysqldump';
        if (str_contains($binary,"\0") || str_contains($binary,"\n"))
            throw new RuntimeException('mysqldump 命令路径无效');
        $cmd=[$binary,'--defaults-extra-file='.$defaults,'--single-transaction','--quick',
            '--routines','--triggers','--events','--hex-blob','--skip-lock-tables',
            '--default-character-set=utf8mb4','--set-gtid-purged=OFF','--databases',$db];
        $process=proc_open($cmd,[0=>['pipe','r'],1=>['pipe','w'],2=>['file',$stderr,'w']],$pipes);
        if (!is_resource($process)) throw new RuntimeException('无法启动 mysqldump（请配置 MySQL 5.7 命令行工具）');
        fclose($pipes[0]);unset($pipes[0]);
        $row=ph_backup_encrypt_file($output,$state,'database.sql',$pipes[1]);
        fclose($pipes[1]);unset($pipes[1]);
        $exit=proc_close($process);$process=null;
        if ($exit!==0) throw new RuntimeException('mysqldump 导出失败（退出码 '.$exit.'）；请检查数据库权限与 PHP 错误日志');
        return $row;
    } finally {
        foreach($pipes as $pipe) if (is_resource($pipe)) fclose($pipe);
        if (is_resource($process)) proc_terminate($process);
        if (is_file($defaults)) unlink($defaults);
        if (is_file($stderr)) unlink($stderr);
    }
}
function ph_backup_storage_list(): array {
    $items=['storage/config.php','storage/ai-master.key','storage/mobile-identity.key',
        'storage/self-update-trust.pub','storage/backup-recipient.pub',
        'storage/updates/signing.key','storage/updates/signing.pub'];
    $dir=APP_STORE.'/updates';
    if (is_dir($dir) && !is_link($dir)) {
        $entries=scandir($dir);
        if (!is_array($entries)) throw new RuntimeException('无法枚举发布包目录');
        foreach($entries as $filename) {
            if (preg_match('/^[0-9a-f]{40}\.zip$/D',$filename))
                $items[]='storage/updates/'.$filename;
        }
    }
    sort($items,SORT_STRING);
    return $items;
}
function ph_backup_create(string $destinationDir): array {
    if (!extension_loaded('sodium')) throw new RuntimeException('加密备份需要 PHP sodium 扩展');
    $destinationDir=ph_backup_safe_outdir($destinationDir,true);
    $public=ph_backup_key_file(APP_STORE.'/backup-recipient.pub',SODIUM_CRYPTO_BOX_PUBLICKEYBYTES,false);
    $name='phonehub-'.gmdate('Ymd-His').'-'.bin2hex(random_bytes(5)).'.phbk';
    $tmp=$destinationDir.'/'.$name.'.part';
    $output=fopen($tmp,'x+b');
    if (!$output) throw new RuntimeException('无法创建加密备份临时文件');
    @chmod($tmp,0600);
    $done=false;$summary=[];
    try {
        $state=ph_backup_encrypt_begin($output,$public);
        ph_backup_encrypt_frame($output,$state,'M',json_encode(['format'=>1,'created_at'=>gmdate('c'),'source'=>'PhoneHub server'],JSON_THROW_ON_ERROR));
        $summary[]=ph_backup_dump($output,$state);
        foreach(ph_backup_storage_list() as $nameInArchive) {
            $path=APP_ROOT.'/'.$nameInArchive;
            if (!is_file($path)) {
                if ($nameInArchive==='storage/config.php') throw new RuntimeException('必须包含数据库配置文件');
                continue;
            }
            if (is_link($path)) throw new RuntimeException('备份不能读取符号链接：'.$nameInArchive);
            $src=fopen($path,'rb');
            if (!$src) throw new RuntimeException('无法读取关键存储文件：'.$nameInArchive);
            try {$summary[]=ph_backup_encrypt_file($output,$state,$nameInArchive,$src);}
            finally {fclose($src);}
        }
        ph_backup_encrypt_finish($output,$state,count($summary));
        if (!fflush($output)) throw new RuntimeException('加密备份刷盘失败');
        fclose($output);$output=null;
        if (!rename($tmp,$destinationDir.'/'.$name))
            throw new RuntimeException('无法将完整备份安装到目标目录');
        $done=true;
        return ['filename'=>$destinationDir.'/'.$name,'files'=>count($summary),'size'=>(int)filesize($destinationDir.'/'.$name)];
    } finally {
        if (is_resource($output)) fclose($output);
        if (!$done && is_file($tmp)) @unlink($tmp);
    }
}
/**
 * Opt-in local retention. Never deletes unrecognized file names, symlinks,
 * newest 3 completed backups, or backups before a successful new creation.
 * Keep an independent off-server copy: pruning is NOT disaster recovery.
 */
function ph_backup_prune(string $directory,int $days): int {
    if ($days<7 || $days>365) throw new RuntimeException('自动保留天数必须为 7–365');
    $directory=ph_backup_safe_outdir($directory,true);
    $entries=scandir($directory);
    if (!is_array($entries)) throw new RuntimeException('无法读取备份目录');
    $matches=[];
    foreach($entries as $filename) {
        if (!preg_match('/^phonehub-[0-9]{8}-[0-9]{6}-[a-f0-9]{10}\.phbk$/D',$filename)) continue;
        $full=$directory.'/'.$filename;
        if (is_link($full) || !is_file($full)) continue;
        $matches[]=['path'=>$full,'mtime'=>(int)filemtime($full)];
    }
    usort($matches,static fn($a,$b)=>$b['mtime']<=>$a['mtime']);
    $deleted=0;
    foreach(array_slice($matches,3) as $item) {
        if ($item['mtime']>=time()-$days*86400) continue;
        if (!unlink($item['path'])) throw new RuntimeException('无法清理历史备份，请检查目录权限');
        $deleted++;
    }
    return $deleted;
}
function ph_backup_restore(string $archive,string $privateFile,string $target): array {
    $target=ph_backup_safe_outdir($target,false);
    $private=ph_backup_key_file($privateFile,SODIUM_CRYPTO_BOX_SECRETKEYBYTES,true);
    if (!mkdir($target,0700)) throw new RuntimeException('无法创建隔离恢复目录');
    try {return ph_backup_decrypt($archive,$private,$target);}
    catch(Throwable $e) {
        $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($target,FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST);
        foreach($it as $entry) $entry->isDir()?@rmdir($entry->getPathname()):@unlink($entry->getPathname());
        @rmdir($target);
        throw $e;
    }
}
try {
    $mode=(string)($argv[1]??'');
    if ($mode==='create' && count($argv)===3) {
        $result=ph_backup_create($argv[2]);
        echo "Encrypted backup created: ".$result['filename']." (".$result['files']." files)\n";
        $retention=getenv('PHONEHUB_BACKUP_RETENTION_DAYS');
        if ($retention!==false && $retention!=='') {
            if (!ctype_digit($retention)) throw new RuntimeException('备份保留天数设置无效');
            $deleted=ph_backup_prune($argv[2],(int)$retention);
            echo "Retention policy: ".$retention." days; removed ".$deleted." old backups (newest 3 always kept)\n";
        }
    } elseif ($mode==='verify' && count($argv)===4) {
        $secret=ph_backup_key_file($argv[3],SODIUM_CRYPTO_BOX_SECRETKEYBYTES,true);
        $rows=ph_backup_decrypt($argv[2],$secret);
        echo "Backup authentication and SHA-256 verified: ".count($rows)." records\n";
    } elseif ($mode==='restore' && count($argv)===5) {
        $rows=ph_backup_restore($argv[2],$argv[3],$argv[4]);
        echo "Restore extracted into isolated directory: ".$argv[4]." (".count($rows)." records)\n";
        echo "No SQL has been imported. Inspect the restored files before any database restoration.\n";
    } else {
        fwrite(STDERR,"Usage (CLI only):\n".
            "  php tools/backup-server.php create /absolute/offsite-backup-directory\n".
            "  php tools/backup-server.php verify /path/backup.phbk /offline/recipient-secret.key\n".
            "  php tools/backup-server.php restore /path/backup.phbk /offline/recipient-secret.key /new/isolated/directory\n");
        exit(2);
    }
} catch(Throwable $e) {
    fwrite(STDERR,"PhoneHub backup failed: ".$e->getMessage()."\n");
    exit(1);
}
