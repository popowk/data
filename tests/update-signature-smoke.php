<?php
declare(strict_types=1);
require dirname(__DIR__).'/app/core.php';
require dirname(__DIR__).'/app/updater.php';
if (!extension_loaded('sodium')) throw new RuntimeException('sodium unavailable');
$files=[];
foreach(UPDATE_FILES as $path) {
    $bytes=file_get_contents(APP_ROOT.'/'.$path);
    if (!is_string($bytes)) throw new RuntimeException('Missing test file '.$path);
    $files[$path]=$bytes;
}
$version=json_decode($files['version.json'],true,512,JSON_THROW_ON_ERROR)['version'];
$pair=sodium_crypto_sign_keypair();
$secret=sodium_crypto_sign_secretkey($pair);
$pub=sodium_crypto_sign_publickey($pair);
$manifest=update_signed_manifest($files,$version);
$sig=base64_encode(sodium_crypto_sign_detached($manifest,$secret));
update_verify_signed_archive($files,$version,$manifest,$sig,$pub);
function must_deny(callable $f,string $which): void {
    try {$f();}
    catch(RuntimeException $e) {return;}
    throw new RuntimeException($which.' unexpectedly accepted');
}
must_deny(static fn()=>update_verify_signed_archive($files,$version,null,$sig,$pub),'missing manifest');
must_deny(static fn()=>update_verify_signed_archive($files,$version,$manifest,null,$pub),'missing signature');
must_deny(static fn()=>update_verify_signed_archive($files,$version,$manifest,$sig,random_bytes(32)),'wrong public key');
must_deny(static fn()=>update_verify_signed_archive($files,'99.99.99',$manifest,$sig,$pub),'replayed old version');
$changed=$files;
$changed['index.php'].="\n//tampered\n";
must_deny(static fn()=>update_verify_signed_archive($changed,$version,$manifest,$sig,$pub),'modified PHP file');
$dir=sys_get_temp_dir().'/phonehub-pub-'.bin2hex(random_bytes(8));
mkdir($dir,0700);
try {
    if(update_trust_public_key($dir)!==null)throw new RuntimeException('trust unexpectedly enabled');
    file_put_contents($dir.'/self-update-trust.pub',$pub);
    if(!hash_equals($pub,(string)update_trust_public_key($dir)))throw new RuntimeException('trust key mismatch');
    file_put_contents($dir.'/self-update-trust.pub','INVALID');
    must_deny(static fn()=>update_trust_public_key($dir),'invalid trust key');
} finally {unlink($dir.'/self-update-trust.pub');rmdir($dir);}
echo "PASS: Ed25519 self-update verified; missing/invalid signature, wrong key, replay and tampering rejected\n";
