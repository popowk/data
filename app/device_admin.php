<?php
declare(strict_types=1);
require_once __DIR__.'/devices.php';

function device_admin_action(string $action): never {
    require_admin();
    if ($action==='device_reveal') {
        require_owner();
        $id=(int)($_POST['id']??0);
        $kind=(string)($_POST['kind']??'');
        if ($id<1 || !in_array($kind,['imei','phone_number'],true))
            throw new RuntimeException('设备或查看字段不正确');
        $column=$kind==='imei'?'imei_encrypted':'phone_number_encrypted';
        $row=sql("SELECT {$column} AS secret_value FROM phonehub_mobile_devices WHERE id=?",[$id])->fetch();
        if (!$row) throw new RuntimeException('设备记录不存在');
        $plain=device_decrypt($row['secret_value']);
        audit('device_reveal_'.$kind,'mobile_record='.$id);
        json_response(['ok'=>true,'value'=>$plain??'尚未采集']);
    }
    if ($action==='device_blacklist_add') {
        require_owner();
        $kind=(string)($_POST['kind']??'');
        $id=(int)($_POST['id']??0);
        $input=strtolower(trim((string)($_POST['identifier']??'')));
        $reason=trim((string)($_POST['reason']??'管理员禁止访问'));
        if (utf8_length($reason)>255 || $reason==='') throw new RuntimeException('拉黑原因不能为空且最多 255 字');
        if (!in_array($kind,['computer_id','phone_id','imei_hash','phone_hash'],true))
            throw new RuntimeException('不支持此类型的黑名单');
        $hash=null;
        if ($id>0) {
            if ($kind==='computer_id') {
                $row=sql('SELECT device_id FROM phonehub_sessions WHERE id=?',[$id])->fetch();
                $hash=$row['device_id']??null;
            } else {
                $col=['phone_id'=>'phone_id','imei_hash'=>'imei_hash','phone_hash'=>'phone_number_hash'][$kind];
                $row=sql("SELECT {$col} AS hash_value FROM phonehub_mobile_devices WHERE id=?",[$id])->fetch();
                $hash=$row['hash_value']??null;
            }
            if (!$hash) throw new RuntimeException('设备未记录对应标识，无法拉黑');
        } elseif ($kind==='imei_hash') {
            $hash=mobile_imei_hash($input);
        } elseif ($kind==='phone_hash') {
            $hash=device_phone_hash(device_phone_normalize($input));
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
            if ($kind==='imei_hash') sql('UPDATE phonehub_mobile_devices SET enabled=0 WHERE imei_hash=?',[$hash]);
            if ($kind==='phone_hash') sql('UPDATE phonehub_mobile_devices SET enabled=0 WHERE phone_number_hash=?',[$hash]);
            audit('device_blacklist',$kind.'='.substr($hash,0,12));
            db()->commit();
        } catch(Throwable $e) { if(db()->inTransaction()) db()->rollBack();throw $e; }
        json_response(['ok'=>true,'message'=>'独立黑名单已生效，匹配设备的有效会话或绑定已撤销']);
    }
    throw new RuntimeException('未知设备管理操作');
}

function device_admin_masked(?string $cipher,int $first,int $last): string {
    if (!$cipher) return '未获取';
    try {return device_mask(device_decrypt($cipher),$first,$last);}
    catch(Throwable $e) {error_log('PhoneHub device field cannot decrypt: '.get_class($e));return '解密失败';}
}
function device_admin_view(): void {
    require_admin();
    $owner=admin_role()==='owner';
    $computers=sql("SELECT MIN(s.id) AS id,s.user_id,u.username,s.device_id,MAX(s.expires_at) AS expires_at,
      COUNT(*) AS sessions FROM phonehub_sessions s JOIN phonehub_users u ON u.id=s.user_id
      WHERE s.expires_at>UTC_TIMESTAMP() GROUP BY s.user_id,s.device_id,u.username ORDER BY expires_at DESC LIMIT 300")->fetchAll();
    $phones=sql("SELECT d.id,d.user_id,u.username,d.phone_id,d.display_name,d.phone_model,d.imei_hash,
      d.imei_encrypted,d.phone_number_hash,d.phone_number_encrypted,d.enabled,d.last_seen,d.created_at,
      EXISTS(SELECT 1 FROM phonehub_mobile_blacklist b WHERE b.enabled=1 AND
        ((b.identifier_type='phone_id' AND b.identifier_hash=d.phone_id) OR
         (b.identifier_type='imei_hash' AND d.imei_hash IS NOT NULL AND b.identifier_hash=d.imei_hash) OR
         (b.identifier_type='phone_hash' AND d.phone_number_hash IS NOT NULL AND b.identifier_hash=d.phone_number_hash))) AS blacklisted
      FROM phonehub_mobile_devices d JOIN phonehub_users u ON u.id=d.user_id
      ORDER BY d.id DESC LIMIT 300")->fetchAll();
    $blacklist=sql("SELECT id,identifier_type,identifier_hash,reason,created_at FROM phonehub_mobile_blacklist
       WHERE enabled=1 ORDER BY id DESC LIMIT 150")->fetchAll();
    $users=sql("SELECT u.id,u.username,COALESCE(m.mobile_limit,0) AS mobile_limit
      FROM phonehub_users u LEFT JOIN phonehub_user_meta m ON m.user_id=u.id ORDER BY u.username")->fetchAll();
    $computerCount=count($computers);$mobileCount=count($phones);$blacklistCount=count($blacklist);
    ?>
    <div class="page-title"><div><h1>设备管理</h1>
      <p>统一查看电脑授权会话、安卓设备和独立黑名单；IMEI 与手机号加密存储，默认遮盖</p></div></div>
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
          <?php if($owner): ?><button class="small-link danger-action" data-action="device-block" data-kind="computer_id" data-id="<?=(int)$d['id']?>">拉黑电脑 ID</button><?php endif ?></td></tr>
        <?php endforeach ?>
        </tbody></table></div></div>
    </section>
    <section data-device-panel="mobiles" hidden>
      <div class="card"><div class="card-head"><h2>安卓手机绑定</h2><span class="count">手机型号与号码由客户端合法取得或管理员录入，不自动伪造</span></div>
        <div class="table-scroll"><table><thead><tr><th>客户</th><th>型号 / 名称</th><th>设备指纹</th><th>IMEI</th><th>手机号</th><th>状态</th><th>最近活动</th><th>管理操作</th></tr></thead><tbody>
        <?php foreach($phones as $d): ?>
          <tr><td><b><?=h($d['username'])?></b></td><td><?=h($d['phone_model']?:'型号未上报')?><small class="device-subline"><?=h($d['display_name'])?></small></td>
          <td><code><?=h(substr($d['phone_id'],0,14))?>…</code></td>
          <td><span class="device-sensitive"><?=h($owner?device_admin_masked($d['imei_encrypted'],3,3):($d['imei_encrypted']?'已加密':'未获取'))?></span>
            <?php if($owner && $d['imei_encrypted']): ?><button class="small-link" data-action="device-reveal" data-kind="imei" data-id="<?=(int)$d['id']?>">查看</button><?php endif ?></td>
          <td><span class="device-sensitive"><?=h($owner?device_admin_masked($d['phone_number_encrypted'],4,4):($d['phone_number_encrypted']?'已加密':'未获取'))?></span>
            <?php if($owner && $d['phone_number_encrypted']): ?><button class="small-link" data-action="device-reveal" data-kind="phone_number" data-id="<?=(int)$d['id']?>">查看</button><?php endif ?></td>
          <td><span class="pill <?=((int)$d['blacklisted']||(int)$d['enabled']===0)?'off':'ok'?>"><?=((int)$d['blacklisted'])?'已拉黑':((int)$d['enabled']===1?'已绑定':'已解绑')?></span></td>
          <td><?=h(utc_to_cn($d['last_seen']?:$d['created_at']))?></td>
          <td class="device-commands">
            <?php if((int)$d['enabled']): ?><button class="small-link" data-action="mobile-revoke" data-id="<?=(int)$d['id']?>">解绑</button><?php endif ?>
            <?php if($owner): ?>
              <button class="small-link danger-action" data-action="device-block" data-kind="phone_id" data-id="<?=(int)$d['id']?>">拉黑指纹</button>
              <?php if($d['imei_hash']): ?><button class="small-link danger-action" data-action="device-block" data-kind="imei_hash" data-id="<?=(int)$d['id']?>">拉黑 IMEI</button><?php endif ?>
              <?php if($d['phone_number_hash']): ?><button class="small-link danger-action" data-action="device-block" data-kind="phone_hash" data-id="<?=(int)$d['id']?>">拉黑手机号</button><?php endif ?>
            <?php endif ?>
          </td></tr>
        <?php endforeach ?></tbody></table></div>
        <p class="footnote">历史记录仅保存过 IMEI HMAC 的，不能逆推出 IMEI 原文；需要手机重新上报原值后才会出现可查看项。</p>
      </div>
      <div class="card"><div class="card-head"><h2>管理员手动绑定手机</h2></div>
        <form data-ajax="mobile_add"><input type="hidden" name="action" value="mobile_add">
          <div class="form-grid">
            <div class="field"><label>客户账号</label><select required name="user_id"><option value="">选择客户</option><?php foreach($users as $u): ?><option value="<?=(int)$u['id']?>"><?=h($u['username'])?>（<?=(int)$u['mobile_limit']?> 台）</option><?php endforeach ?></select></div>
            <div class="field"><label>手机名称</label><input name="display_name" maxlength="120" placeholder="客户手机"></div>
            <div class="field"><label>手机型号</label><input name="phone_model" maxlength="120" placeholder="例如 Samsung Galaxy S24"></div>
            <div class="field"><label>手机指纹（SHA-256）</label><input name="phone_id" pattern="[a-fA-F0-9]{64}" maxlength="64" required placeholder="64 位设备指纹"></div>
            <div class="field"><label>IMEI（可选）</label><input name="imei" inputmode="numeric" pattern="[0-9]{14,16}" maxlength="16" placeholder="采集后加密保存"></div>
            <div class="field"><label>手机号（可选）</label><input name="phone_number" inputmode="tel" maxlength="20" placeholder="+8613800000000"></div>
          </div>
          <button class="btn primary" type="submit">绑定手机</button>
        </form>
        <p class="footnote">只有在客户知情且具备合法采集依据时填写 IMEI/手机号；普通 Android 10+ 应用通常无法读取 IMEI，本机号码在很多 SIM 卡上也可能无法读取。服务器使用可逆加密存储原值，并以 HMAC 进行查重和拉黑。</p>
      </div>
    </section>
    <section data-device-panel="blacklist" hidden>
      <?php if($owner): ?><div class="card"><div class="card-head"><h2>单独禁止指定标识</h2></div>
        <form data-ajax="device_blacklist_add" data-confirm-submit="确认独立拉黑此标识？匹配电脑会话或手机绑定将立即撤销。">
          <input type="hidden" name="action" value="device_blacklist_add">
          <div class="form-grid">
            <div class="field"><label>禁止类型</label><select name="kind" required><option value="computer_id">电脑 ID</option><option value="phone_id">手机指纹</option><option value="imei_hash">IMEI 原号</option><option value="phone_hash">手机号</option></select></div>
            <div class="field"><label>标识原值</label><input name="identifier" required placeholder="电脑/指纹 64 位；IMEI 数字；手机号 +86..."></div>
            <div class="field"><label>原因</label><input name="reason" maxlength="255" required value="管理员禁止访问"></div>
          </div>
          <button class="btn primary" type="submit">加入黑名单</button>
        </form>
      </div><?php endif ?>
      <div class="card"><div class="card-head"><h2>有效禁止访问记录</h2><span class="count">最多显示最近 150 条</span></div>
        <div class="table-scroll"><table><thead><tr><th>禁止类型</th><th>标识摘要</th><th>原因</th><th>创建时间</th><th>操作</th></tr></thead><tbody>
        <?php foreach($blacklist as $b): $typeName=['computer_id'=>'电脑 ID','phone_id'=>'手机指纹','imei_hash'=>'IMEI','phone_hash'=>'手机号'][$b['identifier_type']]??'其他'; ?>
          <tr><td><?=h($typeName)?></td><td><code><?=h(substr($b['identifier_hash'],0,16))?>…</code></td>
            <td><?=h($b['reason'])?></td><td><?=h(utc_to_cn($b['created_at']))?></td>
            <td><?php if($owner): ?><button class="small-link" data-action="mobile-unblacklist" data-id="<?=(int)$b['id']?>">解除拉黑</button><?php else: ?><span class="muted">主管理员操作</span><?php endif ?></td>
          </tr>
        <?php endforeach ?></tbody></table></div>
      </div>
    </section>
    <?php
}
