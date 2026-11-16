<?php
declare(strict_types=1);
// OFFLINE signer: run on a trusted administrator workstation, NOT on the production web server.
// Usage: php tools/sign-self-update.php /absolute/path/to/offline-ed25519-secret.key
if (PHP_SAPI!=='cli') {http_response_code(404);exit;}
require dirname(__DIR__).'/app/core.php';
require dirname(__DIR__).'/app/updater.php';
if (!extension_loaded('sodium')) throw new RuntimeException('PHP sodium extension required');
$secretFile=(string)($argv[1]??'');
$secretPath=realpath($secretFile);
$root=realpath(APP_ROOT);
if (!$secretPath || !$root || !is_file($secretPath) ||
    $secretPath===$root || str_starts_with($secretPath,$root.DIRECTORY_SEPARATOR))
    throw new RuntimeException('密钥必须是仓库和网站目录外的现有离线私钥文件');
$key=file_get_contents($secretPath);
if (!is_string($key) || strlen($key)!==SODIUM_CRYPTO_SIGN_SECRETKEYBYTES)
    throw new RuntimeException('离线 Ed25519 私钥长度错误（需 64 字节）');
$files=[];
foreach(UPDATE_FILES as $path) {
    $source=APP_ROOT.'/'.$path;
    if (!is_file($source) || is_link($source)) throw new RuntimeException('程序文件不可用：'.$path);
    $data=file_get_contents($source);
    if (!is_string($data) || $data==='') throw new RuntimeException('无法读取程序文件：'.$path);
    $files[$path]=$data;
}
update_validate_files($files);
$version=json_decode($files['version.json'],true,512,JSON_THROW_ON_ERROR)['version']??null;
if (!is_string($version) || !preg_match('/^\d+\.\d+\.\d+$/D',$version))
    throw new RuntimeException('发布版本号无效');
$manifest=update_signed_manifest($files,$version);
$signature=base64_encode(sodium_crypto_sign_detached($manifest,$key));
$pub=sodium_crypto_sign_publickey_from_secretkey($key);
update_verify_signed_archive($files,$version,$manifest,$signature,$pub);
$dir=APP_ROOT.'/deploy';
if (!is_dir($dir) && !mkdir($dir,0755,true)) throw new RuntimeException('无法创建 deploy 目录');
$manifestPath=$dir.'/self-update-manifest.json';
$sigPath=$dir.'/self-update-manifest.sig';
if (file_put_contents($manifestPath,$manifest,LOCK_EX)!==strlen($manifest) ||
    file_put_contents($sigPath,$signature."\n",LOCK_EX)!==strlen($signature)+1)
    throw new RuntimeException('签名清单写入失败');
echo "Server update manifest signed: v".$version."\n";
echo "Public key fingerprint (SHA-256): ".hash('sha256',$pub)."\n";
echo "Commit both deploy/self-update-manifest.json and deploy/self-update-manifest.sig with the exact runtime files.\n";
echo "Never commit the private key or put it on the website.\n";
