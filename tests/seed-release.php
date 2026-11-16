<?php
declare(strict_types=1);
require dirname(__DIR__).'/app/core.php';
require dirname(__DIR__).'/app/releases.php';
$dir=release_store();
$name=bin2hex(random_bytes(20)).'.zip';
$file=$dir.'/'.$name;
$zip=new ZipArchive();
if ($zip->open($file,ZipArchive::CREATE|ZipArchive::OVERWRITE)!==true) throw new RuntimeException('Cannot open test ZIP');
$zip->addFromString('core/version.txt','0.8.0');
$zip->close();
$hash=hash_file('sha256',$file);
[$secret,$public]=release_keypair();
$manifest=json_encode([
  'format'=>1,'platform'=>'core','channel'=>'stable','version'=>'0.8.0',
  'min_client'=>'0.7.1','filename'=>'phonehub-core-0.8.0.zip',
  'size_bytes'=>filesize($file),'sha256'=>$hash,'notes'=>'CI',
  'released_at'=>gmdate('Y-m-d\TH:i:s\Z')
],JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
$signature=base64_encode(sodium_crypto_sign_detached($manifest,$secret));
sql('INSERT INTO phonehub_releases(platform,channel,version,min_client,filename,storage_name,size_bytes,sha256,manifest,signature) VALUES(?,?,?,?,?,?,?,?,?,?)',
  ['core','stable','0.8.0','0.7.1','phonehub-core-0.8.0.zip',$name,filesize($file),$hash,$manifest,$signature]);
echo db()->lastInsertId().'|'.$hash."\n";
