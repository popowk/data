<?php
declare(strict_types=1);
require dirname(__DIR__).'/app/core.php';
require dirname(__DIR__).'/app/updater.php';
if (!extension_loaded('sodium')) throw new RuntimeException('sodium unavailable');
function must_deny(callable $f,string $which): void {
    try {$f();}
    catch(RuntimeException $e) {return;}
    throw new RuntimeException($which.' unexpectedly accepted');
}
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
// Only V3 is accepted. Its signed tombstone is mandatory for this release.
$v3=update_v3_manifest($files,$version,['app/gateway.php']);
$v3Sig=base64_encode(sodium_crypto_sign_detached($v3,$secret));
$catalog=update_v3_verify_catalog($version,$v3,$v3Sig,$pub);
update_v3_verify_files($files,$catalog);
if ($catalog['remove']!==['app/gateway.php'] ||
    isset($catalog['files']['app/gateway.php']) ||
    count($catalog['files'])!==count(UPDATE_FILES))
    throw new RuntimeException('V3-only signed retirement catalog has incorrect inventory');
must_deny(static fn()=>update_v3_verify_catalog($version,null,$v3Sig,$pub),'missing V3 manifest');
must_deny(static fn()=>update_v3_verify_catalog($version,$v3,null,$pub),'missing V3 signature');
must_deny(static fn()=>update_v3_verify_catalog($version,$v3,$v3Sig,random_bytes(32)),'wrong V3 public key');
must_deny(static fn()=>update_v3_verify_catalog('99.99.99',$v3,$v3Sig,$pub),'V3 replay');
$changed=$files;
$changed['index.php'].="\n// tampered\n";
must_deny(static fn()=>update_v3_verify_files($changed,$catalog),'tampered V3 file');
$withRetired=$files;
$withRetired['app/gateway.php']="<?php // old retired gateway";
must_deny(static fn()=>update_v3_verify_files($withRetired,$catalog),'unexpected retired gateway in signed file inventory');
$withRemoved=$files;
must_deny(static fn()=>update_v3_manifest($withRemoved,$version,['app/core.php']),'removing core PHP');
must_deny(static fn()=>update_v3_manifest($withRemoved,$version,['storage/config.php']),'removing storage');
must_deny(static fn()=>update_v3_manifest($withRemoved,$version,['../.env']),'path traversal deletion');
must_deny(static fn()=>update_v3_manifest($withRemoved,$version,['app/gateway.php','app/gateway.php']),'duplicate deletion');
$modified=json_decode($v3,true,512,JSON_THROW_ON_ERROR);
$modified['files']['storage/config.php']=str_repeat('a',64);
$modifiedManifest=json_encode($modified,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
$modifiedSig=base64_encode(sodium_crypto_sign_detached($modifiedManifest,$secret));
must_deny(static fn()=>update_v3_verify_catalog($version,$modifiedManifest,$modifiedSig,$pub),'signed unauthorized file');
$modified=json_decode($v3,true,512,JSON_THROW_ON_ERROR);
$modified['remove']=['app/gateway.php','app/gateway.php'];
$modifiedManifest=json_encode($modified,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
$modifiedSig=base64_encode(sodium_crypto_sign_detached($modifiedManifest,$secret));
must_deny(static fn()=>update_v3_verify_catalog($version,$modifiedManifest,$modifiedSig,$pub),'duplicate signed retirement tombstone');
$dir=sys_get_temp_dir().'/phonehub-pub-'.bin2hex(random_bytes(8));
mkdir($dir,0700);
try {
    if (update_trust_public_key($dir)!==null) throw new RuntimeException('trust unexpectedly enabled');
    file_put_contents($dir.'/self-update-trust.pub',$pub);
    if (!hash_equals($pub,(string)update_trust_public_key($dir)))
        throw new RuntimeException('trust key mismatch');
    file_put_contents($dir.'/self-update-trust.pub','INVALID');
    must_deny(static fn()=>update_trust_public_key($dir),'invalid trust key');
} finally {unlink($dir.'/self-update-trust.pub');rmdir($dir);}
echo "PASS: V3-only Ed25519 signed gateway removal; missing signature, wrong key, tampering, path traversal and unsafe deletion rejected\n";
