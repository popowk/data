<?php
declare(strict_types=1);
require_once __DIR__.'/devices.php';

function device_admin_action(string $action): never {
    require_admin();
    if ($action==='device_blacklist_add') {
        phonehub_require_action($action);
        $kind=(string)($_POST['kind']??'');
        $id=(int)($_POST['id']??0);
        $input=strtolower(trim((string)($_POST['identifier']??'')));
        $reason=trim((string)($_POST['reason']??'管理员禁止访问'));
        if (utf8_length($reason)>255 || $reason==='') throw new RuntimeException('拉黑原因不能为空且最多 255 字');
        if (!in_array($kind,['computer_id','phone_id'],true))
            throw new RuntimeException('不支持此类型的黑名单');
        $hash=null;
        if ($id>0) {
            if ($kind==='computer_id') {
                $row=sql('SELECT device_id FROM phonehub_sessions WHERE id=?',[$id])->fetch();
                $hash=$row['device_id']??null;
            } else {
                $col='phone_id';
                $row=sql("SELECT {$col} AS hash_value FROM phonehub_mobile_devices WHERE id=?",[$id])->fetch();
                $hash=$row['hash_value']??null;
            }
            if (!$hash) throw new RuntimeException('设备未记录对应标识，无法拉黑');
        } else {
            $hash=$input;
        }
        if (!is_string($hash) || !preg_match('/^[a-f0-9]{64}$/D',$hash))
            throw new RuntimeException('黑名单标识格式错误');
        db()->beginTransaction();
        try {
            device_insert_blacklist(db(),$kind,$hash,$reason,admin_id());
            if ($kind==='computer_id') sql('DELETE FROM phonehub_sessions WHERE device_id=?',[$hash]);
            if ($kind==='phone_id') sql('UPDATE phonehub_mobile_devices SET enabled=0 WHERE phone_id=?',[$hash]);
            audit('device_blacklist',$kind.'='.substr($hash,0,12));
            db()->commit();
        } catch(Throwable $e) { if(db()->inTransaction()) db()->rollBack();throw $e; }
        json_response(['ok'=>true,'message'=>'独立黑名单已生效，匹配设备的有效会话或绑定已撤销']);
    }
    throw new RuntimeException('未知设备管理操作');
}

function device_admin_view(): void {
    require_admin();
    $canBlock=phonehub_role_can_action(admin_role(),'device_blacklist_add');
    $computers=sql("SELECT MIN(s.id) AS id,s.user_id,u.username,s.device_id,MAX(s.expires_at) AS expires_at,
      COUNT(*) AS sessions FROM phonehub_sessions s JOIN phonehub_users u ON u.id=s.user_id
      WHERE s.expires_at>UTC_TIMESTAMP() GROUP BY s.user_id,s.device_id,u.username ORDER BY expires_at DESC LIMIT 300")->fetchAll();
    $phones=sql("SELECT d.id,d.user_id,u.username,d.phone_id,d.display_name,d.phone_model,d.enabled,d.last_seen,d.created_at,
      EXISTS(SELECT 1 FROM phonehub_mobile_blacklist b WHERE b.enabled=1 AND
        ((b.identifier_type='phone_id' AND b.identifier_hash=d.phone_id) OR
         (b.identifier_type='imei_hash' AND d.imei_hash IS NOT NULL AND b.identifier_hash=d.imei_hash) OR
         (b.identifier_type='phone_hash' AND d.phone_number_hash IS NOT NULL AND b.identifier_hash=d.phone_number_hash))) AS blacklisted
      FROM phonehub_mobile_devices d JOIN phonehub_users u ON u.id=d.user_id
      ORDER BY d.id DESC LIMIT 300")->fetchAll();
    $blacklist=sql("SELECT id,identifier_type,identifier_hash,reason,created_at FROM phonehub_mobile_blacklist
       WHERE enabled=1 AND identifier_type IN ('computer_id','phone_id') ORDER BY id DESC LIMIT 150")->fetchAll();
    $users=sql("SELECT u.id,u.username,COALESCE(m.mobile_limit,0) AS mobile_limit
      FROM phonehub_users u LEFT JOIN phonehub_user_meta m ON m.user_id=u.id ORDER BY u.username")->fetchAll();
    $computerCount=count($computers);$mobileCount=count($phones);$blacklistCount=count($blacklist);
    ?>
    <div class="page-title"><div><h1>设备管理</h1>
      <p>统一查看电脑授权会话、安卓手机指纹绑定及设备黑名单；不采集 IMEI 或 SIM 手机号</p></div></div>
    <div class="device-summary">
      <div class="device-summary-card"><span>电脑会话设备</span><strong><?=$computerCount?></strong><small>近 300 台登录记录，不等于实时在线</small></div>
      <div class="device-summary-card"><span>安卓手机记录</span><strong><?=$mobileCount?></strong><small>近 300 条绑定记录</small></div>
      <div class="device-summary-card"><span>有效黑名单</span><strong><?=$blacklistCount?></strong><small>近 150 条</small></div>
    </div>
    <div class="device-tabs" role="tablist" aria-label="设备管理分类">
      <button type="button" class="device-tab active" data-device-tab="computers">电脑设备</button>
      <button type="button" class="device-tab" data-device-tab="mobiles">安卓手机</button>
      <button type="button" class="device-tab" data-device-tab="blacklist">禁止访问</button>
    </div>
    <section data-device-panel="computers">
      <div class="card"><div class="card-head"><h2>电脑设备与会话</h2><span class="count">会话到期不等于设备实时离线</span></div>
        <div class="table-scroll"><table><thead><tr><th>客户账号</th><th>电脑 ID（完整值可复制）</th><th>有效会话</th><th>会话到期</th><th>管理操作</th></tr></thead><tbody>
        <?php foreach($computers as $d): ?>
        <tr><td><b><?=h($d['username'])?></b></td>
          <td><code><?=h(substr($d['device_id'],0,20))?>…</code>
            <button class="small-link" type="button" data-device-copy="<?=h($d['device_id'])?>">复制 ID</button></td>
          <td><?=(int)$d['sessions']?></td><td><?=h(utc_to_cn($d['expires_at']))?></td>
          <td><button class="small-link" data-action="revoke-session" data-id="<?=(int)$d['id']?>">撤销会话</button>
          <?php if($canBlock): ?><button class="small-link danger-action" data-action="device-block" data-kind="computer_id" data-id="<?=(int)$d['id']?>">拉黑电脑 ID</button><?php endif ?></td></tr>
        <?php endforeach ?>
        </tbody></table></div></div>
    </section>
    <section data-device-panel="mobiles" hidden>
      <div class="card"><div class="card-head"><h2>安卓手机绑定</h2><span class="count">通过设备指纹绑定手机，不采集 IMEI 或手机号</span></div>
        <div class="table-scroll"><table><thead><tr><th>客户</th><th>型号 / 名称</th><th>设备指纹</th><th>状态</th><th>最近活动</th><th>管理操作</th></tr></thead><tbody>
        <?php foreach($phones as $d): ?>
          <tr><td><b><?=h($d['username'])?></b></td><td><?=h($d['phone_model']?:'型号未上报')?><small class="device-subline"><?=h($d['display_name'])?></small></td>
          <td><code><?=h(substr($d['phone_id'],0,14))?>…</code></td>
          <td><span class="pill <?=((int)$d['blacklisted']||(int)$d['enabled']===0)?'off':'ok'?>"><?=((int)$d['blacklisted'])?'已拉黑':((int)$d['enabled']===1?'已绑定':'已解绑')?></span></td>
          <td><?=h(utc_to_cn($d['last_seen']?:$d['created_at']))?></td>
          <td class="device-commands">
            <?php if((int)$d['enabled']): ?><button class="small-link" data-action="mobile-revoke" data-id="<?=(int)$d['id']?>">解绑</button><?php endif ?>
            <?php if($canBlock): ?>
              <button class="small-link danger-action" data-action="device-block" data-kind="phone_id" data-id="<?=(int)$d['id']?>">拉黑指纹</button>
            <?php endif ?>
          </td></tr>
        <?php endforeach ?></tbody></table></div>
        <p class="footnote">新版只使用手机指纹进行设备授权及操作包下载限制；历史设备的敏感资料不再在此页面显示，也不再从客户端采集。</p>
      </div>
      <div class="card"><div class="card-head"><h2>管理员手动绑定手机</h2></div>
        <form data-ajax="mobile_add"><input type="hidden" name="action" value="mobile_add">
          <div class="form-grid">
            <div class="field"><label>客户账号</label><select required name="user_id"><option value="">选择客户</option><?php foreach($users as $u): ?><option value="<?=(int)$u['id']?>"><?=h($u['username'])?>（<?=(int)$u['mobile_limit']?> 台）</option><?php endforeach ?></select></div>
            <div class="field"><label>手机名称</label><input name="display_name" maxlength="120" placeholder="客户手机"></div>
            <div class="field"><label>手机型号</label><input name="phone_model" maxlength="120" placeholder="例如 Samsung Galaxy S24"></div>
            <div class="field"><label>手机指纹（SHA-256）</label><input name="phone_id" pattern="[a-fA-F0-9]{64}" maxlength="64" required placeholder="64 位设备指纹"></div>
          </div>
          <button class="btn primary" type="submit">绑定手机</button>
        </form>
        <p class="footnote">仅需稳定手机指纹、备注和可选型号。旧版客户端仍可以连接，但上传的 IMEI/手机号字段将被服务器忽略。</p>
      </div>
    </section>
    <section data-device-panel="blacklist" hidden>
      <?php if($canBlock): ?><div class="card"><div class="card-head"><h2>单独禁止指定标识</h2></div>
        <form data-ajax="device_blacklist_add" data-confirm-submit="确认独立拉黑此标识？匹配电脑会话或手机绑定将立即撤销。">
          <input type="hidden" name="action" value="device_blacklist_add">
          <div class="form-grid">
            <div class="field"><label>禁止类型</label><select name="kind" required><option value="computer_id">电脑 ID</option><option value="phone_id">手机指纹</option></select></div>
            <div class="field"><label>标识原值</label><input name="identifier" required placeholder="电脑或手机指纹（64 位十六进制）"></div>
            <div class="field"><label>原因</label><input name="reason" maxlength="255" required value="管理员禁止访问"></div>
          </div>
          <button class="btn primary" type="submit">加入黑名单</button>
        </form>
      </div><?php endif ?>
      <div class="card"><div class="card-head"><h2>有效禁止访问记录</h2><span class="count">最多显示最近 150 条</span></div>
        <div class="table-scroll"><table><thead><tr><th>禁止类型</th><th>标识摘要</th><th>原因</th><th>创建时间</th><th>操作</th></tr></thead><tbody>
        <?php foreach($blacklist as $b): $typeName=['computer_id'=>'电脑 ID','phone_id'=>'手机指纹'][$b['identifier_type']]??'其他'; ?>
          <tr><td><?=h($typeName)?></td><td><code><?=h(substr($b['identifier_hash'],0,16))?>…</code></td>
            <td><?=h($b['reason'])?></td><td><?=h(utc_to_cn($b['created_at']))?></td>
            <td><?php if($canBlock): ?><button class="small-link" data-action="mobile-unblacklist" data-id="<?=(int)$b['id']?>">解除拉黑</button><?php else: ?><span class="muted">设备管理员操作</span><?php endif ?></td>
          </tr>
        <?php endforeach ?></tbody></table></div>
      </div>
    </section>
    <?php
}
