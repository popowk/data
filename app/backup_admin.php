<?php
declare(strict_types=1);
/**
 * Backup recipient key setup is separate from the pinned Ed25519 update key.
 * Generate exactly once; persist only Curve25519 public key, return the 32-byte
 * secret key in a one-time authenticated HTTPS download. NEVER log its contents.
 */
function backup_recipient_status(string $storage=APP_STORE): array {
    if (!extension_loaded('sodium')) throw new RuntimeException('备份密钥管理需要 PHP sodium 扩展');
    $path=rtrim($storage,'/').'/backup-recipient.pub';
    if (is_link($path)) throw new RuntimeException('备份接收公钥不能是符号链接');
    if (!file_exists($path)) return ['configured'=>false];
    if (!is_file($path)) throw new RuntimeException('备份公钥文件类型异常');
    $pub=file_get_contents($path);
    if (!is_string($pub) || strlen($pub)!==SODIUM_CRYPTO_BOX_PUBLICKEYBYTES)
        throw new RuntimeException('备份接收公钥无效，请检查原文件；不要随意覆盖');
    return ['configured'=>true,'fingerprint'=>hash('sha256',$pub)];
}
function backup_recipient_generate(string $storage): array {
    if (!extension_loaded('sodium')) throw new RuntimeException('需要 PHP sodium 扩展');
    $storage=rtrim($storage,'/');
    if (!is_dir($storage) || !is_writable($storage) || is_link($storage))
        throw new RuntimeException('备份公钥存储目录不存在或不可写');
    if (backup_recipient_status($storage)['configured'])
        throw new RuntimeException('备份密钥已经建立，禁止自动覆盖；如遗失私钥，请先处理既有加密备份');
    $pair=sodium_crypto_box_keypair();
    $secret=sodium_crypto_box_secretkey($pair);
    $public=sodium_crypto_box_publickey($pair);
    $path=$storage.'/backup-recipient.pub';
    $fp=@fopen($path,'x+b');
    if ($fp===false) {
        sodium_memzero($secret);sodium_memzero($pair);
        throw new RuntimeException('备份公钥已存在或无法安全创建，不会覆盖现有密钥');
    }
    $complete=false;
    try {
        @chmod($path,0600);
        $written=fwrite($fp,$public);
        $complete=$written===strlen($public) && fflush($fp);
    } finally {
        fclose($fp);
        if (!$complete) @unlink($path);
        sodium_memzero($pair);
    }
    if (!$complete) {
        sodium_memzero($secret);
        throw new RuntimeException('备份公钥写入失败');
    }
    return ['secret'=>$secret,'fingerprint'=>hash('sha256',$public)];
}
function backup_admin_download_once(): never {
    require_owner();
    if (!extension_loaded('sodium')) throw new RuntimeException('PHP sodium 不可用');
    audit('backup_recipient_generate_requested','initialization');
    $generated=backup_recipient_generate(APP_STORE);
    $secret=$generated['secret'];
    try {
        try {audit('backup_recipient_generate',substr($generated['fingerprint'],0,16));}
        catch(Throwable $e) {error_log('PhoneHub recipient key audit failed: '.get_class($e));}
        // Raw recipient private key is compatible with the existing offline
        // tools/backup-server.php verify/restore CLI operations.
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="phonehub-backup-recovery.key"');
        header('Content-Length: '.strlen($secret));
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('X-Content-Type-Options: nosniff');
        echo $secret;
    } finally {sodium_memzero($secret);}
    exit;
}
function backup_admin_view(): void {
    require_owner();
    $status=backup_recipient_status();
    ?>
    <div class="page-title"><div><h1>备份密钥管理</h1>
        <p>初始化加密备份接收公钥；解密私钥只下载一次，不修改现有 Ed25519 更新签名</p></div>
        <a class="btn" href="?view=diagnostics">查看故障诊断</a>
    </div>
    <div class="card"><div class="card-head"><h2>Curve25519 备份密钥</h2>
        <span class="pill <?=$status['configured']?'ok':'off'?>"><?=$status['configured']?'已配置公钥':'尚未配置'?></span></div>
        <?php if ($status['configured']): ?>
          <p>备份接收公钥已安装，支持现有 CLI 加密备份工具。</p>
          <p class="muted">公钥 SHA-256 指纹：<code><?=h($status['fingerprint'])?></code></p>
          <p class="footnote">解密私钥在创建时只提供一次，不会保存在服务器，也不能再次下载。如已经遗失，请先确认是否存在需要恢复的旧备份，不能直接重置密钥。</p>
        <?php else: ?>
          <p>点击下方按钮，后台自动创建独立的备份加密密钥对，将公钥保存至受保护的 storage，立即下载私钥文件。这个私钥可以解密之后生成的数据库和关键存储文件备份。</p>
          <form method="post" action="index.php" data-backup-key-download>
            <input type="hidden" name="action" value="backup_key_generate">
            <input type="hidden" name="csrf" value="<?=h(csrf())?>">
            <button class="btn primary" type="submit">生成备份密钥并下载私钥（仅此一次）</button>
          </form>
          <p class="footnote">请将下载的 32 字节 .key 文件放入独立的加密离线存储，并确认保存成功后再创建备份。不要上传 GitHub 或发送到聊天窗口。该私钥与 Ed25519 签名密钥完全不同。</p>
        <?php endif ?>
    </div>
    <div class="card"><div class="card-head"><h2>使用边界</h2></div>
      <p class="muted">密钥初始化不会触发数据库备份，也不提供定时任务、异地同步、密钥轮换或在线恢复。生成公钥后，可通过现有的 PHP CLI 备份工具执行加密导出；恢复操作必须在隔离环境中使用离线私钥。</p>
    </div>
    <?php
}
