<?php
declare(strict_types=1);
require dirname(__DIR__).'/app/core.php';
require dirname(__DIR__).'/app/releases.php';
if (!extension_loaded('sodium') || !extension_loaded('zip')) throw new RuntimeException('extensions missing');
[$secret,$public]=release_keypair();
$data=json_encode(['platform'=>'core','version'=>'0.8.0','sha256'=>str_repeat('a',64)],JSON_THROW_ON_ERROR);
$sig=sodium_crypto_sign_detached($data,$secret);
if (!sodium_crypto_sign_verify_detached($sig,$data,$public)) throw new RuntimeException('Ed25519 verification failure');
$file=tempnam(sys_get_temp_dir(),'phonehub-release-');
$zip=new ZipArchive();
if ($zip->open($file,ZipArchive::CREATE|ZipArchive::OVERWRITE)!==true) throw new RuntimeException('Cannot create zip');
$zip->addFromString('core/version.txt','0.8.0');
$zip->close();
inspect_release_zip($file);
unlink($file);
echo "PASS: Ed25519 signed manifest and safe ZIP validation\n";
