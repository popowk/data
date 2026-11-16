<?php
declare(strict_types=1);
require dirname(__DIR__).'/app/core.php';
require dirname(__DIR__).'/app/updater.php';

$archive=update_archive();
foreach (['index.php','install.php','app/core.php','app/accounts.php','app/updater.php','version.json','assets/app.js','assets/app.css'] as $required) {
    if (!array_key_exists($required,$archive['files'])) {
        throw new RuntimeException('update archive missing required file: '.$required);
    }
}
$manifest=json_decode($archive['files']['version.json'],true,512,JSON_THROW_ON_ERROR);
if ((string)($manifest['version']??'')!==$archive['version']) {
    throw new RuntimeException('update archive version does not match manifest');
}
if (strpos($archive['files']['index.php'],"require_once __DIR__.'/app/accounts.php';")===false) {
    throw new RuntimeException('updated index.php requires app/accounts.php but the updater archive does not match');
}
if (strpos($archive['files']['index.php'],'assets/app.js?v=')===false ||
    strpos($archive['files']['index.php'],'assets/app.css?v=')===false) {
    throw new RuntimeException('updated admin page is missing versioned asset URLs');
}
echo 'Update archive integrity OK: v'.$archive['version'].' ('.count($archive['files'])." allowlisted files)\n";
