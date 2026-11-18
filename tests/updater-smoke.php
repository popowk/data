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
// v0.5.19 transitional release: V2 still names the inert gateway while
// V3 stages a signed deletion migration for the next higher version.
if (defined('UPDATE_LEGACY_FILES'))
    throw new RuntimeException('obsolete V1 catalog is still defined');
if (count(UPDATE_FILES)!==31 || !in_array('app/gateway.php',UPDATE_FILES,true))
    throw new RuntimeException('V2 bridge file inventory unexpectedly changed');
$gatewayStub=(string)file_get_contents(APP_ROOT.'/app/gateway.php');
if (preg_match('/function\s+gateway_[a-z_]+\s*\(/i',$gatewayStub) ||
    str_contains($gatewayStub,'require dirname(__DIR__)'))
    throw new RuntimeException('retired gateway implementation must remain absent');
$v3=update_v3_manifest($files,$manifest['version']);
$decoded=json_decode($v3,true,512,JSON_THROW_ON_ERROR);
if ($decoded['format']!==2 || $decoded['remove']!==[] ||
    count($decoded['files'])!==count(UPDATE_FILES))
    throw new RuntimeException('V3 transitional signed catalog is invalid');
$future=$files;
unset($future['app/gateway.php']);
$deletePlan=json_decode(update_v3_manifest($future,$manifest['version'],
    ['app/gateway.php']),true,512,JSON_THROW_ON_ERROR);
if ($deletePlan['remove']!==['app/gateway.php'] ||
    isset($deletePlan['files']['app/gateway.php']) ||
    !isset($deletePlan['files']['app/updater.php']))
    throw new RuntimeException('future signed gateway cleanup is not possible');

if (strpos($files['index.php'],"require_once __DIR__.'/app/accounts.php';")===false)
    throw new RuntimeException('The admin entry point is missing its account module dependency');
if (strpos($files['index.php'],'assets/app.js?v=')===false ||
    strpos($files['index.php'],'assets/app.css?v=')===false)
    throw new RuntimeException('Admin versioned asset URLs are missing');
echo 'V2 bridge and V3 signed removal migration catalog validated: v'.$manifest['version'].
    ' ('.count(UPDATE_FILES)." signed bridge files)\n";
