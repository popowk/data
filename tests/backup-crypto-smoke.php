<?php
declare(strict_types=1);
require dirname(__DIR__).'/tools/backup-crypto.php';
if (!extension_loaded('sodium')) throw new RuntimeException('sodium unavailable');
$root=sys_get_temp_dir().'/phbackup-ci-'.bin2hex(random_bytes(6));
mkdir($root,0700);
function cleanup_backup_fixture(string $dir): void {
    if (!is_dir($dir)) return;
    $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir,FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST);
    foreach($it as $item) $item->isDir()?rmdir($item->getPathname()):unlink($item->getPathname());
    rmdir($dir);
}
function verify_backup(bool $check,string $message): void {
    if (!$check) throw new RuntimeException($message);
}
function rejected_backup(callable $fn,string $name): void {
    try{$fn();}catch(RuntimeException $e){return;}
    throw new RuntimeException($name.' accepted unexpectedly');
}
try {
    $pair=sodium_crypto_box_keypair();
    $pub=sodium_crypto_box_publickey($pair);
    $secret=sodium_crypto_box_secretkey($pair);
    $archive=$root.'/fixture.phbk';
    $out=fopen($archive,'x+b');
    $state=ph_backup_encrypt_begin($out,$pub);
    ph_backup_encrypt_frame($out,$state,'M',json_encode(['format'=>1,'created_at'=>gmdate('c')],JSON_THROW_ON_ERROR));
    $fixture=[
      'database.sql'=>"CREATE DATABASE ci;\n".str_repeat("INSERT INTO t VALUES ('test');\n",3000),
      'storage/config.php'=>"<?php return ['db_pass'=>'not-a-real-secret'];\n",
      'storage/ai-master.key'=>random_bytes(32),
      'storage/updates/'.str_repeat('a',40).'.zip'=>random_bytes(50000)
    ];
    foreach($fixture as $name=>$bytes) {
        $stream=fopen('php://temp','w+b');
        fwrite($stream,$bytes);rewind($stream);
        ph_backup_encrypt_file($out,$state,$name,$stream);
        fclose($stream);
    }
    ph_backup_encrypt_finish($out,$state,count($fixture));
    fclose($out);
    $verified=ph_backup_decrypt($archive,$secret);
    verify_backup(count($verified)===count($fixture),'valid archive file count mismatch');
    $restore=$root.'/isolation';
    mkdir($restore,0700);
    $restored=ph_backup_decrypt($archive,$secret,$restore);
    verify_backup(count($restored)===count($fixture),'isolated restore count mismatch');
    foreach($fixture as $path=>$bytes)
        verify_backup(file_get_contents($restore.'/'.$path)===$bytes,'restored file mismatch '.$path);
    rejected_backup(static fn()=>ph_backup_decrypt($archive,sodium_crypto_box_secretkey(sodium_crypto_box_keypair())),'wrong recipient key');
    $tampered=file_get_contents($archive);
    $offset=strlen(PH_BACKUP_MAGIC)+SODIUM_CRYPTO_BOX_SEALBYTES+
        SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES+
        SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES+10;
    $tampered[$offset]=chr(ord($tampered[$offset])^1);
    file_put_contents($root.'/tampered.phbk',$tampered);
    rejected_backup(static fn()=>ph_backup_decrypt($root.'/tampered.phbk',$secret),'tampered ciphertext');
    file_put_contents($root.'/truncated.phbk',substr(file_get_contents($archive),0,-12));
    rejected_backup(static fn()=>ph_backup_decrypt($root.'/truncated.phbk',$secret),'truncated archive');
    verify_backup(!ph_backup_path_allowed('../storage/config.php'),'path traversal accepted');
    echo "PASS: sealed recipient key, authenticated streaming backup, isolated restore, wrong-key/tamper/truncation rejection\n";
} finally { cleanup_backup_fixture($root); }
