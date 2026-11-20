<?php
declare(strict_types=1);

/**
 * Customer credential operations. Passwords are generated once and returned
 * only in the immediate authenticated admin response.
 */
function account_reset_password(int $userId): array {
    if ($userId<1) throw new RuntimeException('客户账号无效');
    $connection=db();
    if ($connection->inTransaction()) throw new RuntimeException('当前数据库事务正在执行，请稍后重试');
    $connection->beginTransaction();
    try {
        $target=sql('SELECT id,username FROM phonehub_users WHERE id=? FOR UPDATE',[$userId])->fetch();
        if (!$target) throw new RuntimeException('客户账号不存在');
        $password=random_password(24);
        $hash=password_hash_safe($password);
        sql('UPDATE phonehub_users SET password_hash=? WHERE id=?',[$hash,$userId]);
        sql('DELETE FROM phonehub_sessions WHERE user_id=?',[$userId]);
        // Only the reset event is stored, never the new password or hash.
        phonehub_account_history_record($userId,'password_reset',[],[]);
        audit('account_password',(string)$target['username']);
        $connection->commit();
        return ['username'=>(string)$target['username'],'password'=>$password];
    } catch (Throwable $e) {
        if ($connection->inTransaction()) $connection->rollBack();
        throw $e;
    }
}
