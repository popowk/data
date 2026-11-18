<?php
declare(strict_types=1);
// Machine-only HTTP entry point. No admin Cookie Session or CSRF bypass.
require_once __DIR__.'/../../app/core.php';
require_once __DIR__.'/../../app/automation.php';
try {
    automation_api();
} catch (AutomationHttpException $e) {
    if (db()->inTransaction()) db()->rollBack();
    automation_fail($e->errorCode,$e->getMessage(),$e->http);
} catch (PDOException $e) {
    try {if (db()->inTransaction()) db()->rollBack();} catch(Throwable $ignored) {}
    error_log('PhoneHub automation database failure: '.get_class($e));
    automation_fail('SERVER_UNAVAILABLE','发布服务暂不可用',503);
} catch (RuntimeException $e) {
    try {if (db()->inTransaction()) db()->rollBack();} catch(Throwable $ignored) {}
    error_log('PhoneHub automation rejected request: '.get_class($e));
    automation_fail('REQUEST_REJECTED','更新文件或发布条件不符合要求，请检查参数和服务器状态',400);
} catch (Throwable $e) {
    try {if (db()->inTransaction()) db()->rollBack();} catch(Throwable $ignored) {}
    error_log('PhoneHub automation internal failure: '.get_class($e));
    automation_fail('SERVER_UNAVAILABLE','发布服务暂不可用',503);
}
