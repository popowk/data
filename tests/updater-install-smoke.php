<?php
declare(strict_types=1);

require dirname(__DIR__).'/app/core.php';
require dirname(__DIR__).'/app/updater.php';

function verify(bool $condition,string $message): void {
    if (!$condition) throw new RuntimeException($message);
}
function delete_fixture(string $directory): void {
    if (!is_dir($directory)) return;
    $it=new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory,FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($it as $f) $f->isDir()&&!$f->isLink()?rmdir($f->getPathname()):unlink($f->getPathname());
    rmdir($directory);
}
$root=sys_get_temp_dir().'/phonehub-updater-ci-'.bin2hex(random_bytes(5));
$store=$root.'/storage';
mkdir($store,0700,true);
try {
    $files=[];
    foreach(UPDATE_FILES as $path) {
        $bytes=file_get_contents(APP_ROOT.'/'.$path);
        verify(is_string($bytes),'missing repository file: '.$path);
        $files[$path]=$bytes;
        $dest=$root.'/'.$path;
        if (!is_dir(dirname($dest))) mkdir(dirname($dest),0700,true);
        verify(file_put_contents($dest,$bytes)!==false,'failed preparing fixture: '.$path);
    }
    // A legacy two-pass upgrade reaches this point WITHOUT automation/v1.
    // Verify the installer may create both missing levels, not just one.
    $nested='automation/v1/index.php';
    verify(isset($files[$nested]),'nested automation entry point is missing from runtime catalog');
    verify(unlink($root.'/'.$nested),'cannot remove nested test fixture');
    verify(rmdir($root.'/automation/v1'),'cannot remove nested v1 fixture directory');
    verify(rmdir($root.'/automation'),'cannot remove nested automation fixture directory');
    verify(!file_exists($root.'/automation'),'nested fixture must start absent');

    file_put_contents($root.'/README.md',"This README is user-owned. Do not overwrite.\n");
    file_put_contents($store.'/config.php',"secret fixture - never replace\n");

    update_validate_files($files);
    $missing=$files;
    unset($missing['app/accounts.php']);
    try {
        update_validate_files($missing);
        throw new RuntimeException('missing accounts.php was accepted');
    } catch (RuntimeException $e) {
        verify(str_contains($e->getMessage(),'accounts.php'),'wrong missing file error');
    }
    $broken=$files;
    $broken['app/accounts.php']="<?php function broken( {";
    try {
        update_validate_files($broken);
        throw new RuntimeException('invalid PHP syntax was accepted');
    } catch (RuntimeException $e) {
        verify(str_contains($e->getMessage(),'PHP 更新文件存在语法错误'),'wrong parse error');
    }

    $changed=$files;
    $changed['app/accounts.php'].="\n// test upgraded accounts.php\n";
    $changed['assets/app.js'].="\n// test upgraded client asset\n";
    $version=json_decode($changed['version.json'],true,512,JSON_THROW_ON_ERROR);
    $version['version']='9.9.9';
    $changed['version.json']=json_encode($version,JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT)."\n";

    // Do not traverse a symlinked ancestor or treat an existing regular
    // file as a directory, even when the downstream file is allowlisted.
    $outside=$store.'/outside';
    verify(mkdir($outside,0700),'failed creating symlink target');
    verify(symlink($outside,$root.'/automation'),'failed creating symlink fixture');
    try {
        update_install_files($changed,$root,$store);
        throw new RuntimeException('symlinked parent was accepted');
    } catch (RuntimeException $e) {
        verify(str_contains($e->getMessage(),'符号链接'),'symlink rejection missing');
    }
    verify(unlink($root.'/automation'),'failed removing symlink fixture');
    file_put_contents($root.'/automation','blocking file');
    try {
        update_install_files($changed,$root,$store);
        throw new RuntimeException('non-directory parent was accepted');
    } catch (RuntimeException $e) {
        verify(str_contains($e->getMessage(),'不是目录'),'non-directory rejection missing');
    }
    verify(unlink($root.'/automation'),'failed removing blocking parent file');

    // Inject failure only after the new two-level file has been installed.
    // Rollback must restore every old file AND remove the new entry and dirs.
    try {
        update_install_files($changed,$root,$store,static function(string $path,int $installed) use ($changed): void {
            if ($installed>=count($changed)-1)
                throw new RuntimeException('CI simulated failure');
        });
        throw new RuntimeException('simulated failure unexpectedly installed');
    } catch (RuntimeException $e) {
        verify(str_contains($e->getMessage(),'CI simulated failure'),'unexpected rollback failure');
    }
    foreach($files as $path=>$bytes) {
        if ($path===$nested) {
            verify(!file_exists($root.'/'.$nested),'rollback left new nested file');
            continue;
        }
        verify(hash_equals(hash('sha256',$bytes),(string)hash_file('sha256',$root.'/'.$path)),
            'rollback content mismatch: '.$path);
    }
    verify(!file_exists($root.'/automation'),'rollback left new automation directory');
    $result=update_install_files($changed,$root,$store);
    verify(is_file($root.'/'.$nested),'fresh install failed to create nested API entry point');
    verify($result['installed_count']===count(UPDATE_FILES),'installed file count mismatch');
    foreach($changed as $path=>$bytes) {
        verify(hash_equals(hash('sha256',$bytes),(string)hash_file('sha256',$root.'/'.$path)),
            'installed file mismatch: '.$path);
    }
    verify(file_get_contents($root.'/README.md')==="This README is user-owned. Do not overwrite.\n",
        'user-owned README was overwritten');
    verify(file_get_contents($store.'/config.php')==="secret fixture - never replace\n",
        'storage/config.php was overwritten');
    verify(is_file($store.'/backups/'.$result['backup'].'/app/accounts.php'),
        'rollback backup missing app/accounts.php');
    // An upgraded v0.5.19 server still contains the old gateway stub.
    // This V3-only release must delete it using the signed remove tombstone.
    $gateway=$root.'/app/gateway.php';
    verify(file_put_contents($gateway,"<?php\n// retired v0.5.19 gateway stub\n")!==false,
        'cannot seed retired v0.5.19 gateway');
    $future=$changed;
    $removals=['app/gateway.php'];
    update_validate_files($future,update_v3_catalog_paths($removals));
    try {
        update_install_files($future,$root,$store,null,['storage/config.php']);
        throw new RuntimeException('unsigned storage deletion unexpectedly accepted');
    } catch (RuntimeException $e) {
        verify(str_contains($e->getMessage(),'未经批准'),'storage deletion policy was not enforced');
    }
    $gateway=$root.'/app/gateway.php';
    $gatewayBytes=file_get_contents($gateway);
    verify(is_string($gatewayBytes),'gateway fixture missing');
    $outsideProtected=$store.'/protected-gateway-test';
    file_put_contents($outsideProtected,"leave this protected\n");
    verify(rename($gateway,$gateway.'.backup-test'),'cannot prepare gateway symlink test');
    verify(symlink($outsideProtected,$gateway),'cannot create gateway symlink');
    try {
        update_install_files($future,$root,$store,null,$removals);
        throw new RuntimeException('symlinked signed deletion unexpectedly accepted');
    } catch (RuntimeException $e) {
        verify(str_contains($e->getMessage(),'符号链接'),'gateway deletion symlink rejection missing');
    }
    verify(unlink($gateway),'cannot remove test gateway symlink');
    verify(rename($gateway.'.backup-test',$gateway),'cannot restore gateway test fixture');
    verify(file_get_contents($outsideProtected)==="leave this protected\n",
        'signed deletion modified a symlink target');

    try {
        update_install_files($future,$root,$store,
            static function(string $path,int $installed): void {
                if ($path==='version.json')
                    throw new RuntimeException('CI failure after signed gateway removal');
            },$removals);
        throw new RuntimeException('signed deletion rollback unexpectedly succeeded');
    } catch (RuntimeException $e) {
        verify(str_contains($e->getMessage(),'CI failure after signed gateway removal'),
            'signed deletion failure injection missing');
    }
    verify(is_file($gateway) && file_get_contents($gateway)===$gatewayBytes,
        'rollback failed to restore deleted gateway');
    verify(file_get_contents($store.'/config.php')==="secret fixture - never replace\n",
        'signed migration touched protected storage');

    $migration=update_install_files($future,$root,$store,null,$removals);
    verify(!file_exists($gateway) && !is_link($gateway),
        'signed migration left retired gateway in place');
    verify($migration['installed_count']===count($future)+1,
        'signed migration installed+removed count mismatch');
    verify(is_file($store.'/backups/'.$migration['backup'].'/app/gateway.php'),
        'removed file was not saved in rollback backup');
    verify(file_get_contents($root.'/README.md')==="This README is user-owned. Do not overwrite.\n",
        'migration touched README');
    $repeat=update_install_files($future,$root,$store,null,$removals);
    verify($repeat['installed_count']===count($future) && !file_exists($gateway),
        'repeat signed migration was not idempotent');
    echo "PASS: staged updater, nested directory creation, parent symlink/blocker rejection, rollback cleanup, hashes, signed gateway removal/rollback and README/storage preservation\n";
} finally {
    delete_fixture($root);
}
