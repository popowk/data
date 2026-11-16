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

    try {
        update_install_files($changed,$root,$store,static function(string $path,int $installed): void {
            if ($installed>=3) throw new RuntimeException('CI simulated failure');
        });
        throw new RuntimeException('simulated failure unexpectedly installed');
    } catch (RuntimeException $e) {
        verify(str_contains($e->getMessage(),'CI simulated failure'),'unexpected rollback failure');
    }
    foreach($files as $path=>$bytes) {
        verify(hash_equals(hash('sha256',$bytes),(string)hash_file('sha256',$root.'/'.$path)),
            'rollback content mismatch: '.$path);
    }
    $result=update_install_files($changed,$root,$store);
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
    echo "PASS: staged updater, required modules, PHP syntax validation, failure rollback, install checks and README/storage preservation\n";
} finally {
    delete_fixture($root);
}
