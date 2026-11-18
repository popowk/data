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
// The runtime no longer carries the V1/V2 bridge or retired gateway file.
// V3 is the only accepted signed inventory; deletion is a signed tombstone.
if (defined('UPDATE_LEGACY_FILES') ||
    function_exists('update_verify_signed_archive') ||
    function_exists('update_signed_manifest'))
    throw new RuntimeException('retired self-update signature protocol is still active');
if (in_array('app/gateway.php',UPDATE_FILES,true) ||
    is_file(APP_ROOT.'/app/gateway.php'))
    throw new RuntimeException('retired gateway stub remains in repository or installed catalog');
if (count(UPDATE_FILES)!==30)
    throw new RuntimeException('unexpected V3-only signed runtime inventory size');
$v3=update_v3_manifest($files,$manifest['version'],['app/gateway.php']);
$decoded=json_decode($v3,true,512,JSON_THROW_ON_ERROR);
if ($decoded['format']!==2 ||
    $decoded['remove']!==['app/gateway.php'] ||
    count($decoded['files'])!==count(UPDATE_FILES) ||
    isset($decoded['files']['app/gateway.php']))
    throw new RuntimeException('V3-only retirement manifest is invalid');
if (strpos($files['index.php'],"require_once __DIR__.'/app/accounts.php';")===false)
    throw new RuntimeException('The admin entry point is missing its account module dependency');
if (strpos($files['index.php'],'assets/app.js?v=')===false ||
    strpos($files['index.php'],'assets/app.css?v=')===false)
    throw new RuntimeException('Admin versioned asset URLs are missing');
echo 'V3-only catalog and signed gateway retirement validated: v'.$manifest['version'].
    ' ('.count(UPDATE_FILES)." signed runtime files)\n";
