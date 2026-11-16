<?php
declare(strict_types=1);
require_once __DIR__.'/releases.php';

function release_admin_action(string $action): never {
    require_owner();
    if ($action==='release_publish') {
        $r=release_publish($_FILES['file']??[],$_POST);
        json_response(['ok'=>true,'message'=>'已发布签名更新包 '+$r['platform'].' v'.$r['version']]+$r);
    }
    if ($action==='release_toggle') {
        $result=release_toggle((int)($_POST['id']??0));
        json_response(['ok'=>true]+$result);
    }
    if ($action==='logs_purge') {
        $days=(int)($_POST['days']??30);
        if ($days<7 || $days>365) throw new RuntimeException('日志保留天数应为 7–365');
        $count=sql('DELETE FROM phonehub_client_logs WHERE created_at<DATE_SUB(UTC_TIMESTAMP(), INTERVAL '.$days.' DAY)')->rowCount();
        audit('logs_purge','older_than='.$days.' days, removed='.$count);
        json_response(['ok'=>true,'message'=>'已删除 '.$count.' 条过期日志']);
    }
    throw new RuntimeException('未知发布管理操作');
}
function release_admin_view(): void {
    require_owner();
    $list=sql('SELECT id,platform,channel,version,min_client,size_bytes,sha256,signature,enabled,created_at FROM phonehub_releases ORDER BY id DESC LIMIT 200')->fetchAll();
    ?>
    <div class="page-title"><div><h1>客户端核心更新</h1><p>向客户软件发布签名 ZIP 包；与管理后台 GitHub 自更新独立</p></div></div>
    <div class="card"><div class="card-head"><h2>上传新版本（50 MB 以内）</h2></div>
      <form data-ajax="release_publish" enctype="multipart/form-data">
       <input type="hidden" name="action" value="release_publish">
       <div class="form-grid">
        <div class="field"><label>更新目标</label><select name="platform"><option value="core">core（客户端核心）</option><option value="douyin">douyin（抖音模块）</option><option value="xiaohongshu">xiaohongshu（小红书模块）</option></select></div>
        <div class="field"><label>发布渠道</label><select name="channel"><option value="stable">正式版 stable</option><option value="beta">测试版 beta</option></select></div>
        <div class="field"><label>版本号</label><input name="version" required placeholder="1.0.1" pattern="[0-9]+\.[0-9]+\.[0-9]+([\-][0-9a-zA-Z.-]+)?"></div>
        <div class="field"><label>最低客户端版本</label><input name="min_client" required value="0.7.1"></div>
        <div class="field span2"><label>更新 ZIP</label><input name="file" type="file" accept=".zip,application/zip" required></div>
        <div class="field span2"><label>版本说明</label><textarea name="notes" maxlength="1000" rows="3" style="padding:12px;border:1px solid #dce3ef;border-radius:8px;width:100%;resize:vertical" placeholder="更新内容与兼容提醒"></textarea></div>
       </div><div class="editor-actions"><button class="btn primary" data-confirm-submit="确认发布此版本并签署更新包？版本号发布后不可重复。">上传并签名发布</button></div>
      </form>
      <p class="muted">需要 PHP sodium、ZipArchive，并调整 PHP upload_max_filesize 至 50M 以上、post_max_size 至 55M 以上。私钥仅存放服务器 storage/updates/signing.key，不在 GitHub。</p>
      <p class="muted">客户端下载后必须验证：信任的公钥 → Ed25519 原始清单签名 → 清单 SHA-256 → ZIP 安全解压。不能只信任更新接口返回的公钥。</p>
    </div>
    <div class="card"><div class="card-head"><h2>签名公钥</h2></div>
      <?php $pub=release_public_key(); ?>
      <?php if ($pub): ?>
        <p class="muted">客户端必须预置此 Ed25519 公钥，并在正式版中固定使用。公钥变更需要单独可信渠道更新。</p>
        <code class="public-key"><?=h($pub)?></code>
      <?php else: ?><p class="muted">首次上传签名版本后将生成长期签名密钥对，公钥显示在这里。</p><?php endif ?>
    </div>
    <div class="card"><div class="card-head"><h2>已发布版本</h2><span class="count">最近 200 条</span></div>
      <div class="table-scroll"><table><thead><tr><th>更新目标</th><th>渠道</th><th>版本</th><th>最低客户端</th><th>大小</th><th>状态</th><th>操作</th></tr></thead><tbody>
        <?php foreach($list as $x): ?><tr><td><?=h($x['platform'])?></td><td><?=h($x['channel'])?></td><td><b><?=h($x['version'])?></b></td><td><?=h($x['min_client'])?></td><td><?=number_format((int)$x['size_bytes']/1024/1024,2)?> MB</td><td><span class="pill <?=(int)$x['enabled']?'ok':'off'?>"><?=(int)$x['enabled']?'已发布':'已停用'?></span></td><td><button class="small-link" data-action="release-toggle" data-id="<?=(int)$x['id']?>"><?=(int)$x['enabled']?'暂停下载':'恢复下载'?></button></td></tr><?php endforeach ?>
      </tbody></table></div>
    </div>
    <?php
}
