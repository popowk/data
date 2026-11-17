<?php
declare(strict_types=1);
require_once __DIR__.'/updater.php';

/**
 * One-time owner-only bootstrap: generate Ed25519 on the server, transfer the
 * signing secret to GitHub Actions as a libsodium sealed-box secret via HTTPS,
 * then discard the local secret. Keep only a pending public key until the
 * independently signed mirror archive has been verified.
 *
 * Server must NEVER sign downloaded source. The trust key is pinned only
 * after publisher output has been verified with this freshly generated key.
 */
function signing_status(): array {
    $active=APP_STORE.'/self-update-trust.pub';
    $pending=APP_STORE.'/self-update-pending.pub';
    if (is_link($active) || is_link($pending))
        throw new RuntimeException('签名信任文件不能是符号链接');
    if (is_file($active)) {
        $pub=file_get_contents($active);
        if (!is_string($pub) || strlen($pub)!==32) throw new RuntimeException('签名信任公钥损坏');
        return ['state'=>'active','fingerprint'=>hash('sha256',$pub)];
    }
    if (is_file($pending)) {
        $pub=file_get_contents($pending);
        if (!is_string($pub) || strlen($pub)!==32) throw new RuntimeException('待启用公钥损坏');
        return ['state'=>'pending','fingerprint'=>hash('sha256',$pub)];
    }
    return ['state'=>'unconfigured'];
}
function signing_github_call(string $method,string $path,string $pat,?array $payload=null): array {
    if (!preg_match('~^/repos/popowk/data/actions/(?:secrets/public-key|secrets/PHONEHUB_SERVER_SIGNING_KEY_B64|workflows/sign-server-update.yml/dispatches)$~D',$path))
        throw new RuntimeException('不允许调用此 GitHub 操作');
    $ch=curl_init('https://api.github.com'.$path);
    if ($ch===false) throw new RuntimeException('无法连接 GitHub API');
    $result='';$json=$payload===null?'':json_encode($payload,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
    curl_setopt_array($ch,[
        CURLOPT_CUSTOMREQUEST=>$method,
        CURLOPT_FOLLOWLOCATION=>false,
        CURLOPT_CONNECTTIMEOUT=>8,CURLOPT_TIMEOUT=>20,
        CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,
        CURLOPT_RETURNTRANSFER=>false,
        CURLOPT_HTTPHEADER=>[
            'Accept: application/vnd.github+json',
            'X-GitHub-Api-Version: 2022-11-28',
            'Authorization: Bearer '.$pat,
            'Content-Type: application/json',
            'User-Agent: PhoneHub-Admin'
        ],
        CURLOPT_WRITEFUNCTION=>static function($ch,string $chunk) use (&$result): int {
            if (strlen($result)+strlen($chunk)>32768) return 0;
            $result.=$chunk;return strlen($chunk);
        }
    ]);
    if ($payload!==null) curl_setopt($ch,CURLOPT_POSTFIELDS,$json);
    try {
        $ok=curl_exec($ch);$status=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE);
        if ($ok===false || !in_array($status,[200,201,204],true))
            throw new RuntimeException('GitHub 配置失败（HTTP '.$status.'）。请检查一次性 Token 的仓库 Secrets/Actions 权限');
        return $status===204?[]:(json_decode($result,true)?:[]);
    } finally {curl_close($ch);}
}
function signing_generate_and_publish(string $githubToken): array {
    require_owner();
    if (!extension_loaded('sodium') || !extension_loaded('curl'))
        throw new RuntimeException('需要 PHP sodium 和 curl 扩展');
    if (signing_status()['state']!=='unconfigured')
        throw new RuntimeException('已生成签名身份，禁止重复生成；请激活待启用公钥');
    if (strlen($githubToken)<16 || strlen($githubToken)>255 || preg_match('/\s/',$githubToken))
        throw new RuntimeException('请提供有本仓库 Actions Secrets 写入权限的临时 GitHub Token');
    $lock=fopen(APP_STORE.'/signing-init.lock','c+');
    if (!$lock || !flock($lock,LOCK_EX|LOCK_NB))
        throw new RuntimeException('已有签名初始化任务正在执行');
    try {
        if (signing_status()['state']!=='unconfigured')
            throw new RuntimeException('签名身份已被其他管理员初始化');
        $keypair=sodium_crypto_sign_keypair();
        $private=sodium_crypto_sign_secretkey($keypair);
        $public=sodium_crypto_sign_publickey($keypair);
        try {
            $repo='/repos/popowk/data/actions/';
            $keyInfo=signing_github_call('GET',$repo.'secrets/public-key',$githubToken);
            $ghKey=base64_decode((string)($keyInfo['key']??''),true);
            $keyId=(string)($keyInfo['key_id']??'');
            if (!is_string($ghKey) || strlen($ghKey)!==SODIUM_CRYPTO_BOX_PUBLICKEYBYTES || $keyId==='')
                throw new RuntimeException('GitHub 返回的 Secrets 加密公钥格式无效');
            $encrypted=base64_encode(sodium_crypto_box_seal(base64_encode($private),$ghKey));
            signing_github_call('PUT',$repo.'secrets/PHONEHUB_SERVER_SIGNING_KEY_B64',$githubToken,
                ['encrypted_value'=>$encrypted,'key_id'=>$keyId]);
            $pending=APP_STORE.'/self-update-pending.pub';
            $fp=fopen($pending,'x+b');
            if (!$fp) throw new RuntimeException('无法写入待启用签名公钥');
            @chmod($pending,0600);
            try {
                if (fwrite($fp,$public)!==32 || !fflush($fp))
                    throw new RuntimeException('签名公钥持久化失败');
            } finally {fclose($fp);}
            try {
                signing_github_call('POST',$repo.'workflows/sign-server-update.yml/dispatches',$githubToken,['ref'=>'main']);
            } catch(Throwable $e) {
                // Keep the pending identity so administrators can retry via GitHub
                // rather than silently rotating to a different signing key.
                throw new RuntimeException('密钥已配置并保存待启用公钥，但自动触发失败；请检查 GitHub Actions，稍后点击验证启用',0,$e);
            }
            audit('self_update_signing_prepare',substr(hash('sha256',$public),0,16));
            return ['message'=>'签名密钥已自动生成并安全提交 GitHub Actions；等待镜像同步签名后点击验证启用',
                'state'=>'pending','fingerprint'=>hash('sha256',$public)];
        } finally {
            sodium_memzero($private);
            sodium_memzero($keypair);
        }
    } finally {flock($lock,LOCK_UN);fclose($lock);}
}
function signing_activate_trust(): array {
    require_owner();
    $status=signing_status();
    if ($status['state']==='active') return ['message'=>'签名信任已启用','state'=>'active']+$status;
    if ($status['state']!=='pending') throw new RuntimeException('请先初始化签名身份');
    $pub=file_get_contents(APP_STORE.'/self-update-pending.pub');
    if (!is_string($pub) || strlen($pub)!==32) throw new RuntimeException('待启用公钥格式错误');
    // Validate a freshly downloaded archive, not server source or cached data.
    $temp=tempnam(APP_STORE,'verify-signed-');
    if ($temp===false) throw new RuntimeException('无法建立签名验证缓存');
    try {
        update_download($temp);
        $zip=new ZipArchive();
        if ($zip->open($temp)!==true) throw new RuntimeException('国内镜像返回无效 ZIP');
        try {
            $prefix=null;
            for($i=0;$i<$zip->numFiles;$i++) {
                $name=$zip->getNameIndex($i);
                if (is_string($name) && preg_match('~^[A-Za-z0-9_.-]+/version\.json$~D',$name)){
                    $prefix=substr($name,0,-strlen('version.json'));break;
                }
            }
            if ($prefix===null) throw new RuntimeException('镜像缺少版本文件');
            // The second archive must match the first untrusted preflight.
            $files=[];foreach(UPDATE_FILES as $path){
                $bytes=$zip->getFromName($prefix.$path);
                if (!is_string($bytes)) throw new RuntimeException('镜像缺少程序文件：'.$path);
                $files[$path]=$bytes;
            }
            $number=(string)(json_decode($files['version.json'],true)['version']??'');
            update_validate_files($files);
            update_verify_signed_archive($files,$number,
                $zip->getFromName($prefix.'deploy/self-update-manifest.json')?:null,
                $zip->getFromName($prefix.'deploy/self-update-manifest.sig')?:null,$pub);
        } finally {$zip->close();}
    } finally {@unlink($temp);}
    if (is_file(APP_STORE.'/self-update-trust.pub'))
        throw new RuntimeException('信任公钥已由其他管理员安装，请刷新页面');
    if (!rename(APP_STORE.'/self-update-pending.pub',APP_STORE.'/self-update-trust.pub'))
        throw new RuntimeException('无法启用固定签名公钥');
    audit('self_update_signing_activate',substr(hash('sha256',$pub),0,16));
    return ['message'=>'国内镜像签名和所有程序文件摘要验证成功，Ed25519 固定公钥已启用',
        'state'=>'active','fingerprint'=>hash('sha256',$pub)];
}
