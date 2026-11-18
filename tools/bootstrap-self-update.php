<?php
declare(strict_types=1);
/**
 * One-time trusted-workstation bootstrap.
 * Generates Ed25519 keys locally (never in the repository), uploads the
 * private key encrypted to GitHub Actions via gh secret stdin, triggers the
 * signer, independently verifies the signed mirror archive, then SCPs only
 * the public key to an SSH-authenticated PhoneHub server and checks its hash.
 *
 * Requirements: PHP 8.2+ sodium curl zip, gh authenticated with repo rights,
 * SSH key access to the server. Remote directory must already be installed.
 */
if (PHP_SAPI!=='cli') {http_response_code(404);exit;}
require dirname(__DIR__).'/app/core.php';
require __DIR__.'/../app/updater.php';

function bootstrap_exec(array $command,?string $stdin=null): string {
    $pipes=[];
    $process=proc_open($command,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
    if (!is_resource($process)) throw new RuntimeException('无法启动必要的配置工具');
    if ($stdin!==null) {
        $written=0;
        while ($written<strlen($stdin)) {
            $n=fwrite($pipes[0],substr($stdin,$written));
            if (!is_int($n) || $n===0) break;
            $written+=$n;
        }
        if ($written!==strlen($stdin)) {
            fclose($pipes[0]);fclose($pipes[1]);fclose($pipes[2]);
            proc_terminate($process);
            throw new RuntimeException('向 GitHub CLI 传输签名密钥失败');
        }
    }
    fclose($pipes[0]);
    $stdout=stream_get_contents($pipes[1]);fclose($pipes[1]);
    $stderr=stream_get_contents($pipes[2]);fclose($pipes[2]);
    $status=proc_close($process);
    if ($status!==0) throw new RuntimeException('执行外部命令失败（退出码 '.$status.'）：'.implode(' ',array_slice($command,0,2))
        .'；请确认 GitHub CLI 登录和服务器 SSH 密钥授权。');
    return is_string($stdout)?$stdout:'';
}
function bootstrap_storage(string $path): array {
    $root=realpath(APP_ROOT);
    if (!is_dir($path) && !mkdir($path,0700,true))
        throw new RuntimeException('无法创建本地密钥目录');
    $dir=realpath($path);
    if (!$dir || is_link($path) || ($root && ($dir===$root || str_starts_with($dir,$root.DIRECTORY_SEPARATOR))))
        throw new RuntimeException('密钥不得保存在仓库或网站目录之内');
    @chmod($dir,0700);
    $private=$dir.'/server-signing.secret';
    $public=$dir.'/server-signing.pub';
    if (is_link($private) || is_link($public)) throw new RuntimeException('签名密钥不能是符号链接');
    if (file_exists($private) !== file_exists($public))
        throw new RuntimeException('发现不完整密钥对，请从安全备份恢复，不可静默重新生成');
    if (!file_exists($private)) {
        $pair=sodium_crypto_sign_keypair();
        $secret=sodium_crypto_sign_secretkey($pair);
        $pub=sodium_crypto_sign_publickey($pair);
        $handle=fopen($private,'x+b');
        if (!$handle) throw new RuntimeException('无法安全创建签名私钥');
        @chmod($private,0600);
        try {
            if (fwrite($handle,$secret)!==strlen($secret) || !fflush($handle))
                throw new RuntimeException('无法保存签名私钥');
        } finally {fclose($handle);}
        $handle=fopen($public,'x+b');
        if (!$handle) throw new RuntimeException('无法创建签名公钥');
        try {
            if (fwrite($handle,$pub)!==strlen($pub) || !fflush($handle))
                throw new RuntimeException('无法保存签名公钥');
        } finally {fclose($handle);}
        @chmod($public,0600);
        sodium_memzero($secret);
    }
    $secret=file_get_contents($private);
    $pub=file_get_contents($public);
    if (!is_string($secret) || strlen($secret)!==SODIUM_CRYPTO_SIGN_SECRETKEYBYTES ||
        !is_string($pub) || strlen($pub)!==SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES ||
        !hash_equals($pub,sodium_crypto_sign_publickey_from_secretkey($secret)))
        throw new RuntimeException('现有签名密钥不匹配，已拒绝操作');
    return [$private,$public,$secret,$pub];
}
function bootstrap_verify_mirror(string $publicKey): string {
    $temp=tempnam(sys_get_temp_dir(),'phub-signed-');
    if ($temp===false) throw new RuntimeException('无法建立更新包验证缓存');
    try {
        update_download($temp);
        $zip=new ZipArchive();
        if ($zip->open($temp)!==true) throw new RuntimeException('国内镜像没有返回有效 ZIP');
        try {
            $prefix=null;
            for($i=0;$i<$zip->numFiles;$i++) {
                $name=$zip->getNameIndex($i);
                if (is_string($name) && preg_match('~^[A-Za-z0-9_.-]+/version\.json$~D',$name)) {
                    $prefix=substr($name,0,-strlen('version.json'));break;
                }
            }
            if($prefix===null) throw new RuntimeException('国内镜像更新包缺少版本文件');
            $versionBytes=$zip->getFromName($prefix.'version.json');
            $number=is_string($versionBytes)?json_decode($versionBytes,true,512,JSON_THROW_ON_ERROR)['version']??null:null;
            if (!is_string($number)) throw new RuntimeException('镜像版本格式错误');
            $v3=update_v3_verify_catalog($number,
                $zip->getFromName($prefix.'deploy/self-update-manifest-v3.json')?:null,
                $zip->getFromName($prefix.'deploy/self-update-manifest-v3.sig')?:null,$publicKey);
            $files=[];
            foreach (array_keys($v3['files']) as $path) {
                $data=$zip->getFromName($prefix.$path);
                if (!is_string($data)) throw new RuntimeException('镜像发布包缺少必需文件：'.$path);
                $files[$path]=$data;
            }
            update_v3_verify_files($files,$v3);
            return $number;
        } finally {$zip->close();}
    } finally {@unlink($temp);}
}
try {
    if (!extension_loaded('sodium')) throw new RuntimeException('需要 PHP sodium 扩展');
    $args=getopt('',['server::','site::','key-dir::','repo::','prepare-only']);
    $home=getenv('HOME')?:getenv('USERPROFILE');
    if (!$home) throw new RuntimeException('无法定位安全的本地用户目录');
    $keyDir=(string)($args['key-dir']??($home.'/.phonehub/self-update'));
    [$privatePath,$pubPath,$private,$public]=bootstrap_storage($keyDir);
    $fp=hash('sha256',$public);
    echo "Ed25519 identity ready. Public SHA-256 fingerprint: ".$fp."\n";
    if (isset($args['prepare-only'])) {
        echo "Prepared locally; GitHub and server were NOT changed.\n";exit(0);
    }
    $repoName=(string)($args['repo']??'popowk/data');
    $server=(string)($args['server']??'');
    $site=(string)($args['site']??'');
    if (!preg_match('~^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$~D',$repoName) ||
        !preg_match('~^(?:[a-zA-Z_][a-zA-Z0-9_.-]*@)?[a-zA-Z0-9_.-]+$~D',$server) ||
        !preg_match('~^/[A-Za-z0-9_./-]+$~D',$site) || str_contains($site,'..'))
        throw new RuntimeException('请提供有效的 --server=user@host --site=/网站目录/license 参数');
    $pubRemote=$site.'/storage/self-update-trust.pub';
    $nonce=bin2hex(random_bytes(6));
    $remoteTemp=$site.'/storage/.self-update-trust-'.$nonce;
    // Require pre-existing site and authenticated, noninteractive SSH. Never
    // generate a fresh server trust key from the untrusted update archive.
    bootstrap_exec(['ssh','-o','BatchMode=yes',$server,
        'test -d '.escapeshellarg($site.'/storage').' && test ! -L '.escapeshellarg($pubRemote)]);
    bootstrap_exec(['gh','auth','status']);
    bootstrap_exec(['gh','secret','set','PHONEHUB_SERVER_SIGNING_KEY_B64','--repo',$repoName],
        base64_encode($private));
    sodium_memzero($private);
    echo "GitHub Actions signing secret provisioned; triggering publisher.\n";
    bootstrap_exec(['gh','workflow','run','sign-server-update.yml','--repo',$repoName,'--ref','main']);
    $version=null;
    for($attempt=0;$attempt<15;$attempt++){
        try {$version=bootstrap_verify_mirror($public);break;}
        catch(Throwable $e) {
            if ($attempt===14) throw new RuntimeException(
                '已配置 Actions 密钥，但镜像签名尚未通过验证；未向服务器安装信任公钥。请检查 GitHub Actions 签名任务。');
            sleep(4);
        }
    }
    echo "Mirror Ed25519 signature verified: v".$version."\n";
    bootstrap_exec(['scp','-q','-o','BatchMode=yes',$pubPath,$server.':'.$remoteTemp]);
    $remoteCommand='umask 077; if [ -e '.escapeshellarg($pubRemote).' ]; then '.
        'cmp -s '.escapeshellarg($remoteTemp).' '.escapeshellarg($pubRemote).
        ' || { rm -f '.escapeshellarg($remoteTemp).'; exit 8; }; rm -f '.escapeshellarg($remoteTemp).
        '; else mv '.escapeshellarg($remoteTemp).' '.escapeshellarg($pubRemote).'; fi; '.
        'chmod 600 '.escapeshellarg($pubRemote).'; sha256sum '.escapeshellarg($pubRemote);
    $remoteHash=bootstrap_exec(['ssh','-o','BatchMode=yes',$server,$remoteCommand]);
    if (!hash_equals($fp,strtok(trim($remoteHash)," \t\n")))
        throw new RuntimeException('服务器上固定公钥指纹校验失败，请检查远程文件');
    echo "Server pinned public key installed and fingerprint verified.\n";
    echo "Future GitHub main updates are automatically signed, mirror-fetched and independently verified before installation.\n";
} catch(Throwable $e) {
    fwrite(STDERR,"PhoneHub self-update bootstrap: ".$e->getMessage()."\n");
    exit(1);
}
