<?php
declare(strict_types=1);
// Deterministic local package validation. Signed mirror freshness is checked
// separately by the informational China mirror CI probe; it must not race the
// GitHub Actions job which generates and commits the signed manifest.
require dirname(__DIR__).'/app/core.php';
require dirname(__DIR__).'/app/updater.php';

$files=[];
foreach (UPDATE_FILES as $path) {
    $file=APP_ROOT.'/'.$path;
    if (!is_file($file) || is_link($file))
        throw new RuntimeException('Modern release is missing its required file: '.$path);
    $bytes=file_get_contents($file);
    if (!is_string($bytes) || $bytes==='')
        throw new RuntimeException('Modern release has an unreadable file: '.$path);
    $files[$path]=$bytes;
}
update_validate_files($files);
$manifest=json_decode($files['version.json'],true,512,JSON_THROW_ON_ERROR);
if ((string)($manifest['version']??'')!==app_version())
    throw new RuntimeException('Current program version does not match the runtime file manifest');
foreach (['index.php','install.php','app/core.php','app/accounts.php','app/updater.php',
    'app/automation.php','automation/v1/index.php','version.json','assets/app.js','assets/app.css'] as $required) {
    if (!isset($files[$required]))
        throw new RuntimeException('Modern update catalog lacks required module: '.$required);
}
if (in_array('docs/客户端接入API-v0.3.md',UPDATE_FILES,true) ||
    in_array('docs/客户端接入API-v0.4.md',UPDATE_FILES,true))
    throw new RuntimeException('Deprecated legacy documentation must not be installed by modern updater');
// Historical pinned updater catalogs still carry an inert gateway.php PATH.
// No bridge implementation can be installed by either signed manifest.
$gatewayStub=(string)file_get_contents(APP_ROOT.'/app/gateway.php');
if (preg_match('/function\s+gateway_[a-z_]+\s*\(/i',$gatewayStub) ||
    str_contains($gatewayStub,'require dirname(__DIR__)'))
    throw new RuntimeException('obsolete client gateway implementation must remain absent');

foreach (UPDATE_LEGACY_FILES as $required) {
    if (!is_file(APP_ROOT.'/'.$required))
        throw new RuntimeException('The pinned v0.5.10 bridge archive lacks: '.$required);
}
if (strpos($files['index.php'],"require_once __DIR__.'/app/accounts.php';")===false)
    throw new RuntimeException('The admin entry point is missing its account module dependency');
if (strpos($files['index.php'],'assets/app.js?v=')===false ||
    strpos($files['index.php'],'assets/app.css?v=')===false)
    throw new RuntimeException('Admin versioned asset URLs are missing');
echo 'Modern runtime update catalog and legacy bootstrap assets validated: v'.$manifest['version'].
    ' ('.count(UPDATE_FILES).' modern files, '.count(UPDATE_LEGACY_FILES)." pinned bridge files)\n";
