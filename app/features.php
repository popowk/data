<?php
declare(strict_types=1);
require_once __DIR__.'/mobile.php';

function feature_action(string $action): never {
    require_admin();
    $id=(int)($_POST['id'] ?? 0);
    if ($action==='admin_create') {
        require_owner();
        $name=trim((string)($_POST['username'] ?? ''));validate_user($name);
        $password=random_password();
        sql("INSERT INTO phonehub_admins(username,password_hash,role,enabled) VALUES(?,?,'admin',1)",[$name,password_hash_safe($password)]);
        audit('admin_create',$name);
        json_response(['ok'=>true,'message'=>'管理员已创建','password'=>$password,'username'=>$name]);
    }
    if (in_array($action,['admin_toggle','admin_reset','admin_delete'],true)) {
        require_owner();
        $target=sql('SELECT id,username,role,enabled FROM phonehub_admins WHERE id=?',[$id])->fetch();
        if (!$target || $target['role']!=='admin' || (int)$target['id']===admin_id())
            throw new RuntimeException('主管理员受到保护，禁止修改、重置或删除');
        if ($action==='admin_toggle') {
            $next=(int)$target['enabled'] ? 0 : 1;
            sql('UPDATE phonehub_admins SET enabled=?,auth_version=auth_version+1 WHERE id=? AND role=?',[$next,$id,'admin']);
            audit('admin_toggle',(string)$target['username']);
            json_response(['ok'=>true,'message'=>$next?'管理员已启用':'管理员已停用']);
        }
        if ($action==='admin_reset') {
            $password=random_password();
            sql('UPDATE phonehub_admins SET password_hash=?,auth_version=auth_version+1 WHERE id=? AND role=?',
                [password_hash_safe($password),$id,'admin']);
            audit('admin_reset',(string)$target['username']);
            json_response(['ok'=>true,'message'=>'管理员密码已重置','username'=>$target['username'],'password'=>$password]);
        }
        sql('DELETE FROM phonehub_admins WHERE id=? AND role=?',[$id,'admin']);
        audit('admin_delete',(string)$target['username']);
        json_response(['ok'=>true,'message'=>'管理员已删除']);
    }
    if ($action==='owner_password') {
        require_owner();
        $old=(string)($_POST['old_password']??'');
        $new=(string)($_POST['new_password']??'');
        $hash=sql('SELECT password_hash FROM phonehub_admins WHERE id=?',[admin_id()])->fetchColumn();
        if (!$hash || !password_verify($old,(string)$hash)) throw new RuntimeException('当前密码错误');
        $newHash=password_hash_safe($new);
        sql('UPDATE phonehub_admins SET password_hash=?,auth_version=auth_version+1 WHERE id=? AND role=?',[$newHash,admin_id(),'owner']);
        $_SESSION['auth_version']=(int)sql('SELECT auth_version FROM phonehub_admins WHERE id=?',[admin_id()])->fetchColumn();
        audit('owner_password','self');
        json_response(['ok'=>true,'message'=>'主管理员密码已修改']);
    }
    if ($action==='group_bulk') {
        $group=(int)($_POST['group_id']??0);
        if ($group<1 || !(int)sql('SELECT COUNT(*) FROM phonehub_groups WHERE id=?',[$group])->fetchColumn())
            throw new RuntimeException('请选择有效分组');
        $fields=[];
        $allowed=['device_limit','mobile_limit','enabled','license_until','entitlements'];
        foreach($allowed as $f) if(isset($_POST['apply_'.$f])) $fields[]=$f;
        if (!$fields) throw new RuntimeException('请至少勾选一项需要批量修改的配置');
        $set=[];$params=[];
        foreach($fields as $f) {
            if ($f==='device_limit' || $f==='mobile_limit') {
                $v=filter_var($_POST[$f]??null,FILTER_VALIDATE_INT);
                if ($v===false || $v<($f==='device_limit'?1:0) || $v>($f==='device_limit'?100:1000))
                    throw new RuntimeException('设备名额无效');
                $set[]=$f==='device_limit'?'u.device_limit=?':'m.mobile_limit=?';
                $params[]=$v;
            } elseif ($f==='enabled') {
                $v=(string)($_POST['enabled']??'');
                if (!in_array($v,['0','1'],true)) throw new RuntimeException('账号状态无效');
                $set[]='u.enabled=?';$params[]=(int)$v;
            } elseif ($f==='license_until') {
                $set[]='u.license_until=?';$params[]=input_to_utc(trim((string)($_POST['license_until']??'')));
            } elseif ($f==='entitlements') {
                $v=(array)($_POST['entitlements']??[]);
                if (array_diff($v,['douyin','xiaohongshu','mcp','skill'])) throw new RuntimeException('未知平台或扩展授权');
                if (array_intersect($v,['mcp','skill'])) require_owner();
                $set[]='u.entitlements=?';$params[]=json_encode(array_values(array_unique($v)),JSON_UNESCAPED_UNICODE);
            }
        }
        $count=(int)sql('SELECT COUNT(*) FROM phonehub_user_meta WHERE group_id=?',[$group])->fetchColumn();
        if (!$count) throw new RuntimeException('该分组没有客户');
        db()->beginTransaction();
        $memberIds=sql('SELECT u.id FROM phonehub_users u JOIN phonehub_user_meta m ON m.user_id=u.id WHERE m.group_id=? FOR UPDATE',[$group])->fetchAll(PDO::FETCH_COLUMN);
        if (!$memberIds) throw new RuntimeException('该分组没有客户');
        $params[]=$group;
        sql('UPDATE phonehub_users u INNER JOIN phonehub_user_meta m ON m.user_id=u.id SET '.implode(',',$set).' WHERE m.group_id=?',$params);
        $revoke=array_intersect($fields,['device_limit','enabled','license_until','entitlements']);
        if ($revoke) {
            $placeholders=implode(',',array_fill(0,count($memberIds),'?'));
            sql('DELETE FROM phonehub_sessions WHERE user_id IN ('.$placeholders.')',$memberIds);
        }
        audit('group_bulk','group='.$group.' members='.count($memberIds).' fields='.implode(',',$fields));
        db()->commit();
        json_response(['ok'=>true,'message'=>'已批量更新 '.count($memberIds).' 个客户；'.($revoke?'相关电脑会话已撤销':'无需退出客户端')]);
    }
    if ($action==='mobile_add') {
        $user=(int)($_POST['user_id']??0);
        $fingerprint=strtolower(trim((string)($_POST['phone_id']??'')));
        $name=trim((string)($_POST['display_name']??''));
        if ($user<1 || !preg_match('/^[a-f0-9]{64}$/D',$fingerprint)) throw new RuntimeException('请选择客户并输入 64 位手机设备指纹');
        if (utf8_length($name)>120) throw new RuntimeException('手机备注过长');
        $imeiHash=mobile_imei_hash((string)($_POST['imei']??''));
        db()->beginTransaction();
        $u=sql('SELECT u.id,u.enabled,COALESCE(m.mobile_limit,0) AS mobile_limit FROM phonehub_users u LEFT JOIN phonehub_user_meta m ON m.user_id=u.id WHERE u.id=? FOR UPDATE',[$user])->fetch();
        if (!$u || !(int)$u['enabled']) throw new RuntimeException('客户不存在或已停用');
        if (mobile_blacklist_match(db(),$fingerprint,$imeiHash)) throw new RuntimeException('该手机指纹或 IMEI 已在设备黑名单中');
        $existing=sql('SELECT id,enabled,imei_hash FROM phonehub_mobile_devices WHERE user_id=? AND phone_id=? FOR UPDATE',[$user,$fingerprint])->fetch();
        $knownImeiHash=$imeiHash??(($existing && !empty($existing['imei_hash']))?(string)$existing['imei_hash']:null);
        if (mobile_blacklist_match(db(),$fingerprint,$knownImeiHash)) throw new RuntimeException('该手机指纹或 IMEI 已在设备黑名单中');
        if ($existing && $imeiHash!==null && !empty($existing['imei_hash']) && !hash_equals((string)$existing['imei_hash'],$imeiHash))
            throw new RuntimeException('该手机指纹已绑定不同 IMEI，请先由主管理员核对设备');
        if ($imeiHash!==null) {
            $other=sql('SELECT id FROM phonehub_mobile_devices WHERE imei_hash=? AND enabled=1 AND NOT(user_id=? AND phone_id=?) LIMIT 1 FOR UPDATE',[$imeiHash,$user,$fingerprint])->fetch();
            if ($other) throw new RuntimeException('该 IMEI 已绑定其他手机记录');
        }
        $active=(int)sql('SELECT COUNT(*) FROM phonehub_mobile_devices WHERE user_id=? AND enabled=1',[$user])->fetchColumn();
        if ((!$existing || !(int)$existing['enabled']) && $active>=(int)$u['mobile_limit']) throw new RuntimeException('已达到客户安卓手机授权上限');
        sql('INSERT INTO phonehub_mobile_devices(user_id,phone_id,display_name,imei_hash,enabled,last_seen) VALUES(?,?,?,?,1,UTC_TIMESTAMP()) ON DUPLICATE KEY UPDATE display_name=VALUES(display_name),imei_hash=COALESCE(VALUES(imei_hash),imei_hash),enabled=1,last_seen=UTC_TIMESTAMP()',[$user,$fingerprint,$name,$imeiHash]);
        audit('mobile_add','user='.$user.' id='.substr($fingerprint,0,10).' imei='.(($imeiHash!==null)?'bound':'unavailable'));
        db()->commit();
        json_response(['ok'=>true,'message'=>'安卓手机已绑定','imei_bound'=>$imeiHash!==null || !empty($existing['imei_hash'])]);
    }
    if ($action==='mobile_blacklist') {
        require_owner();
        if ($id<1) throw new RuntimeException('手机记录无效');
        $reason=trim((string)($_POST['reason']??'管理员手动拉黑'));
        if (utf8_length($reason)>255) throw new RuntimeException('拉黑原因不能超过 255 字');
        db()->beginTransaction();
        $record=sql('SELECT id,phone_id,imei_hash FROM phonehub_mobile_devices WHERE id=? FOR UPDATE',[$id])->fetch();
        if (!$record) throw new RuntimeException('绑定记录不存在');
        $identifiers=[['phone_id',(string)$record['phone_id']]];
        if (!empty($record['imei_hash'])) $identifiers[]=['imei_hash',(string)$record['imei_hash']];
        foreach($identifiers as [$type,$hash]) {
            sql('INSERT INTO phonehub_mobile_blacklist(identifier_type,identifier_hash,reason,enabled,created_by,created_at) VALUES(?,?,?,1,?,UTC_TIMESTAMP()) ON DUPLICATE KEY UPDATE reason=VALUES(reason),enabled=1,created_by=VALUES(created_by),created_at=UTC_TIMESTAMP()',
                [$type,$hash,$reason,admin_id()]);
        }
        $sql='UPDATE phonehub_mobile_devices SET enabled=0 WHERE phone_id=?';
        $params=[(string)$record['phone_id']];
        if (!empty($record['imei_hash'])) {$sql.=' OR imei_hash=?';$params[]=(string)$record['imei_hash'];}
        sql($sql,$params);
        audit('mobile_blacklist','record='.$id.' identifiers='.count($identifiers));
        db()->commit();
        json_response(['ok'=>true,'message'=>'设备已拉黑，匹配的手机绑定已全部停用']);
    }
    if ($action==='mobile_unblacklist') {
        require_owner();
        if ($id<1) throw new RuntimeException('黑名单记录无效');
        $record=sql('SELECT id,identifier_type,identifier_hash FROM phonehub_mobile_blacklist WHERE id=? AND enabled=1',[$id])->fetch();
        if (!$record) throw new RuntimeException('黑名单记录不存在或已解除');
        sql('UPDATE phonehub_mobile_blacklist SET enabled=0 WHERE id=?',[$id]);
        audit('mobile_unblacklist',$record['identifier_type'].'='.substr($record['identifier_hash'],0,12));
        json_response(['ok'=>true,'message'=>'已解除该条黑名单；设备绑定不会自动恢复']);
    }
    if ($action==='cloud_features_save') {
        require_owner();
        $values=['mcp_enabled'=>isset($_POST['mcp_enabled'])?'1':'0','skill_enabled'=>isset($_POST['skill_enabled'])?'1':'0'];
        foreach($values as $key=>$value) sql('INSERT INTO phonehub_feature_settings(setting_key,setting_value) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)',[$key,$value]);
        audit('cloud_features_save','mcp='.$values['mcp_enabled'].', skill='.$values['skill_enabled']);
        json_response(['ok'=>true,'message'=>'客户端扩展总开关已保存']);
    }
    if ($action==='mobile_revoke') {
        if ($id<1) throw new RuntimeException('手机记录无效');
        db()->beginTransaction();
        $record=sql('SELECT user_id FROM phonehub_mobile_devices WHERE id=?',[$id])->fetch();
        if(!$record)throw new RuntimeException('绑定记录不存在');
        sql('SELECT id FROM phonehub_users WHERE id=? FOR UPDATE',[(int)$record['user_id']])->fetch();
        sql('UPDATE phonehub_mobile_devices SET enabled=0 WHERE id=?',[$id]);
        audit('mobile_revoke',(string)$id);
        db()->commit();
        json_response(['ok'=>true,'message'=>'该手机绑定已撤销']);
    }
    if ($action==='gateway_install') {
        require_owner();
        require __DIR__.'/gateway.php';
        json_response(['ok'=>true]+gateway_install());
    }
    throw new RuntimeException('未知管理操作');
}

function feature_view(string $view): void {
    if ($view==='admins') {
        require_owner();
        $admins=sql('SELECT id,username,role,enabled,created_at FROM phonehub_admins ORDER BY CASE WHEN role=\'owner\' THEN 0 ELSE 1 END,id')->fetchAll();
        ?><div class="page-title"><div><h1>管理员管理</h1><p>仅主管理员可以创建、停用、重置或删除其他管理员</p></div></div>
        <div class="card"><div class="card-head"><h2>创建普通管理员</h2></div>
        <form data-ajax="admin_create" class="inline-form"><input name="action" type="hidden" value="admin_create"><input name="username" placeholder="管理员登录名（3–64 位英文字符）" required minlength="3"><button class="btn primary">+ 创建并生成随机密码</button></form></div>
        <div class="card"><div class="card-head"><h2>管理员列表</h2></div><div class="table-scroll"><table><thead><tr><th>管理员</th><th>权限</th><th>状态</th><th>创建时间</th><th>操作</th></tr></thead><tbody>
        <?php foreach($admins as $a): ?><tr><td><b><?=h($a['username'])?></b></td><td><?= $a['role']==='owner'?'主管理员（受保护）':'普通管理员' ?></td><td><span class="pill <?=(int)$a['enabled']?'ok':'off'?>"><?=(int)$a['enabled']?'正常':'已停用'?></span></td><td><?=h(utc_to_cn($a['created_at']))?></td><td>
        <?php if($a['role']==='owner'): ?><span class="muted">不可操作</span><?php else: ?>
        <button class="small-link" data-action="admin-reset" data-id="<?=(int)$a['id']?>">重置密码</button>
        <button class="small-link" data-action="admin-toggle" data-id="<?=(int)$a['id']?>"><?=(int)$a['enabled']?'停用':'启用'?></button>
        <button class="small-link" data-action="admin-delete" data-id="<?=(int)$a['id']?>">删除</button>
        <?php endif ?></td></tr><?php endforeach ?></tbody></table></div></div>
        <div class="card"><div class="card-head"><h2>修改自己的主管理员密码</h2></div>
        <form data-ajax="owner_password" class="inline-form"><input name="action" type="hidden" value="owner_password"><input type="password" name="old_password" required placeholder="当前密码"><input type="password" name="new_password" required minlength="12" placeholder="新密码（至少12字节）"><button class="btn primary">修改密码</button></form></div><?php
    } elseif ($view==='group_bulk') {
        $groups=sql('SELECT id,name,(SELECT COUNT(*) FROM phonehub_user_meta WHERE group_id=g.id) AS cnt FROM phonehub_groups g ORDER BY name')->fetchAll();
        ?>
        <div class="page-title"><div><h1>分组批量配置</h1><p>先选择客户分组，再勾选需要覆盖的配置；未勾选的字段不会改变。</p></div><a class="btn" href="?view=groups">返回客户分组</a></div>
        <div class="bulk-intro"><div class="bulk-intro-icon">≡</div><div><strong>安全批量修改</strong><p>仅影响所选分组中的客户。涉及电脑会话权限的变更会自动撤销旧会话，确保新配置立即生效。</p></div></div>
        <form id="group-bulk-form" data-ajax="group_bulk">
        <input name="action" type="hidden" value="group_bulk">
        <section class="card bulk-target-card">
          <div class="bulk-section-head"><div><span class="bulk-step">01</span><div><h2>选择目标分组</h2><p>选择要统一调整授权的客户群组</p></div></div><span class="bulk-required">必选</span></div>
          <div class="field"><label for="bulk-group">目标客户分组</label><select id="bulk-group" name="group_id" required><option value="">请选择客户分组</option><?php foreach($groups as $g): ?><option value="<?=(int)$g['id']?>" data-members="<?=(int)$g['cnt']?>"><?=h($g['name'])?>（<?=(int)$g['cnt']?> 位客户）</option><?php endforeach ?></select><div class="bulk-group-meta"><span id="bulk-member-count">尚未选择分组</span><span>只会修改该分组内的客户</span></div></div>
        </section>
        <div class="bulk-section-title"><div><span class="bulk-step">02</span><div><h2>选择要修改的授权字段</h2><p>打开对应选项后，才会应用下面的配置</p></div></div><span class="bulk-tip">未勾选 = 保持原值</span></div>
        <div class="bulk-grid">
          <section class="bulk-option">
            <label class="bulk-option-head"><input class="bulk-option-toggle" type="checkbox" name="apply_device_limit"><span class="bulk-option-icon">PC</span><span><strong>电脑数量上限</strong><small>每个客户允许登录的电脑数量</small></span></label>
            <div class="bulk-option-body"><label for="bulk-device">新的电脑名额</label><input id="bulk-device" data-bulk-field type="number" name="device_limit" min="1" max="100" value="3" disabled><small>允许范围：1–100 台</small></div>
          </section>
          <section class="bulk-option">
            <label class="bulk-option-head"><input class="bulk-option-toggle" type="checkbox" name="apply_mobile_limit"><span class="bulk-option-icon">手机</span><span><strong>安卓手机数量上限</strong><small>每个客户允许绑定的手机数量</small></span></label>
            <div class="bulk-option-body"><label for="bulk-mobile">新的手机名额</label><input id="bulk-mobile" data-bulk-field type="number" name="mobile_limit" min="0" max="1000" value="1" disabled><small>设置为 0 将禁止绑定手机</small></div>
          </section>
          <section class="bulk-option">
            <label class="bulk-option-head"><input class="bulk-option-toggle" type="checkbox" name="apply_enabled"><span class="bulk-option-icon">状态</span><span><strong>客户账号状态</strong><small>统一启用或停用该分组客户</small></span></label>
            <div class="bulk-option-body"><label for="bulk-enabled">设置为</label><select id="bulk-enabled" data-bulk-field name="enabled" disabled><option value="1">启用账号</option><option value="0">停用账号</option></select><small>停用后客户无法继续登录</small></div>
          </section>
          <section class="bulk-option">
            <label class="bulk-option-head"><input class="bulk-option-toggle" type="checkbox" name="apply_license_until"><span class="bulk-option-icon">期限</span><span><strong>授权有效期</strong><small>统一修改客户授权截止时间</small></span></label>
            <div class="bulk-option-body"><label for="bulk-expiry">新的授权截止时间（北京时间）</label><input id="bulk-expiry" data-bulk-field type="datetime-local" name="license_until" step="1" disabled><small>勾选后留空代表永久授权</small></div>
          </section>
          <section class="bulk-option bulk-option-wide">
            <label class="bulk-option-head"><input class="bulk-option-toggle" type="checkbox" name="apply_entitlements"><span class="bulk-option-icon">权限</span><span><strong>平台与扩展权限</strong><small>勾选的权限将成为该分组客户的完整权限集合</small></span></label>
            <div class="bulk-option-body">
              <div class="bulk-entitlements">
                <label><input data-bulk-field type="checkbox" name="entitlements[]" value="douyin" checked disabled> 抖音</label>
                <label><input data-bulk-field type="checkbox" name="entitlements[]" value="xiaohongshu" disabled> 小红书</label>
                <label><input data-bulk-field type="checkbox" name="entitlements[]" value="mcp" disabled> MCP</label>
                <label><input data-bulk-field type="checkbox" name="entitlements[]" value="skill" disabled> Skill</label>
              </div><small>未勾选的平台将从客户授权中移除；MCP/Skill 还需要主管理员开启云端总开关。</small>
            </div>
          </section>
        </div>
        <div class="bulk-impact"><strong>生效提示</strong><p>修改电脑名额、客户状态、授权期限或平台权限时，会撤销该分组客户现有的电脑会话。修改手机名额不会主动解绑已有手机。</p></div>
        <div class="bulk-submit"><div><strong id="bulk-summary">尚未选择修改项</strong><small>提交前请再次确认目标分组和修改范围</small></div><button class="btn primary" type="submit" data-confirm-submit="此操作将批量修改所选分组的指定授权字段，确认继续？">应用批量配置</button></div>
        </form>
        <?php
    } elseif ($view==='mobiles') {
        $phones=sql("SELECT p.id,p.phone_id,p.imei_hash,p.display_name,p.enabled,p.last_seen,p.created_at,u.username,
          EXISTS(SELECT 1 FROM phonehub_mobile_blacklist b WHERE b.enabled=1 AND
            ((b.identifier_type='phone_id' AND b.identifier_hash=p.phone_id) OR
             (b.identifier_type='imei_hash' AND p.imei_hash IS NOT NULL AND b.identifier_hash=p.imei_hash))) AS blacklisted
          FROM phonehub_mobile_devices p JOIN phonehub_users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 500")->fetchAll();
        $users=sql("SELECT u.id,u.username,COALESCE(m.mobile_limit,0) AS mobile_limit FROM phonehub_users u LEFT JOIN phonehub_user_meta m ON m.user_id=u.id ORDER BY u.username")->fetchAll();
        $blacklist=sql("SELECT id,identifier_type,identifier_hash,reason,created_at FROM phonehub_mobile_blacklist WHERE enabled=1 ORDER BY id DESC LIMIT 200")->fetchAll();
        $isOwner=(string)sql('SELECT role FROM phonehub_admins WHERE id=?',[admin_id()])->fetchColumn()==='owner';
        ?><div class="page-title"><div><h1>安卓手机绑定与黑名单</h1><p>设备指纹为主标识，IMEI 仅在客户端依法可读取时作为辅助校验；拉黑后立即停用匹配设备</p></div></div>
        <div class="card"><div class="card-head"><h2>管理员手工绑定设备</h2></div><form data-ajax="mobile_add"><input type="hidden" name="action" value="mobile_add">
        <div class="form-grid"><div class="field"><label>客户</label><select required name="user_id"><option value="">选择客户</option><?php foreach($users as $u): ?><option value="<?=(int)$u['id']?>"><?=h($u['username'])?>（手机额度 <?=(int)$u['mobile_limit']?>）</option><?php endforeach ?></select></div>
        <div class="field"><label>手机名称</label><input name="display_name" maxlength="120" placeholder="例如：客户安卓手机"></div>
        <div class="field"><label>手机设备指纹（SHA-256，64位）</label><input name="phone_id" required pattern="[a-fA-F0-9]{64}" placeholder="客户端生成的稳定设备指纹"></div>
        <div class="field"><label>IMEI（可选，14–16位数字）</label><input name="imei" inputmode="numeric" maxlength="16" pattern="[0-9]{14,16}" placeholder="服务器仅保存 HMAC 摘要"></div></div><button class="btn primary">绑定手机</button></form>
        <p class="footnote">原始 IMEI 只通过 HTTPS 提交并立即转换为服务器 HMAC 摘要，不保存明文。请备份 storage/mobile-identity.key；丢失后原有 IMEI 摘要无法再匹配。普通 Android 应用在 Android 10+ 通常无权读取 IMEI，不能为此申请或绕过特权权限。</p></div>
        <div class="card"><div class="card-head"><h2>设备绑定记录</h2><span class="count">最近 500 条</span></div><div class="table-scroll"><table><thead><tr><th>客户</th><th>备注</th><th>手机指纹</th><th>IMEI 摘要</th><th>状态</th><th>最近使用</th><th>操作</th></tr></thead><tbody>
        <?php foreach($phones as $p): ?><tr><td><?=h($p['username'])?></td><td><?=h($p['display_name'])?></td><td><code title="<?=h($p['phone_id'])?>"><?=h(substr($p['phone_id'],0,16))?>…</code></td><td><?=!empty($p['imei_hash'])?'<code>'.h(substr($p['imei_hash'],0,12)).'…</code>':'<span class="muted">未获取</span>'?></td><td><span class="pill <?=((int)$p['blacklisted'])?'off':((int)$p['enabled']?'ok':'off')?>"><?=(int)$p['blacklisted']?'已拉黑':((int)$p['enabled']?'已绑定':'已解绑')?></span></td><td><?=h(utc_to_cn($p['last_seen']?:$p['created_at']))?></td><td><?php if((int)$p['enabled']): ?><button class="small-link" data-action="mobile-revoke" data-id="<?=(int)$p['id']?>">解绑</button><?php endif ?><?php if($isOwner && !(int)$p['blacklisted']): ?><button class="small-link" data-action="mobile-blacklist" data-id="<?=(int)$p['id']?>">拉黑</button><?php endif ?></td></tr><?php endforeach ?></tbody></table></div></div>
        <div class="card"><div class="card-head"><h2>设备黑名单</h2><span class="count">最近 200 条有效记录</span></div><div class="table-scroll"><table><thead><tr><th>标识类型</th><th>摘要</th><th>拉黑原因</th><th>时间</th><th>操作</th></tr></thead><tbody>
        <?php foreach($blacklist as $b): ?><tr><td><?=h($b['identifier_type']==='imei_hash'?'IMEI 摘要':'手机指纹')?></td><td><code><?=h(substr($b['identifier_hash'],0,16))?>…</code></td><td><?=h($b['reason'])?></td><td><?=h(utc_to_cn($b['created_at']))?></td><td><?php if($isOwner): ?><button class="small-link" data-action="mobile-unblacklist" data-id="<?=(int)$b['id']?>">解除拉黑</button><?php else: ?><span class="muted">仅主管理员可操作</span><?php endif ?></td></tr><?php endforeach ?></tbody></table></div></div><?php
    } elseif ($view==='cloud_features') {
        require_owner();
        $rows=sql("SELECT setting_key,setting_value FROM phonehub_feature_settings WHERE setting_key IN ('mcp_enabled','skill_enabled')")->fetchAll();
        $flags=[];foreach($rows as $row)$flags[$row['setting_key']]=$row['setting_value']==='1';
        $mcp=!empty($flags['mcp_enabled']);$skill=!empty($flags['skill_enabled']);
        ?><div class="page-title"><div><h1>客户端能力控制</h1><p>统一管理客户端扩展的云端开放状态，默认全部关闭</p></div><span class="cloud-live-indicator"><i></i> 云端策略生效中</span></div>
        <div class="cloud-summary"><div><span class="cloud-summary-label">全局开放能力</span><strong><?=((int)$mcp+(int)$skill)?> <small>/ 2</small></strong></div><p>只有全局开关、客户单独授权、已启用签名版本三项同时满足，客户端才可以使用对应能力。</p></div>
        <form data-ajax="cloud_features_save" class="cloud-feature-form"><input type="hidden" name="action" value="cloud_features_save">
          <div class="cloud-feature-grid">
            <section class="cloud-feature-card <?=$mcp?'is-enabled':'is-disabled'?>">
              <div class="cloud-feature-top"><div class="cloud-feature-icon">M</div><span class="cloud-state"><?=$mcp?'全局已开放':'默认禁用'?></span></div>
              <h2>MCP 连接能力</h2><p>允许已获授权的客户获取并使用 PhoneHub MCP 连接包。</p>
              <label class="cloud-switch"><input type="checkbox" name="mcp_enabled" <?=$mcp?'checked':''?>><span class="cloud-switch-ui"></span><span><?=$mcp?'已开启':'关闭 MCP'?></span></label>
              <ul><li>控制 MCP 版本查询与下载</li><li>客户还必须单独获得 MCP 授权</li><li>需要存在已启用的签名发布版本</li></ul>
            </section>
            <section class="cloud-feature-card <?=$skill?'is-enabled':'is-disabled'?>">
              <div class="cloud-feature-top"><div class="cloud-feature-icon skill">S</div><span class="cloud-state"><?=$skill?'全局已开放':'默认禁用'?></span></div>
              <h2>Skill 技能能力</h2><p>允许已获授权的客户获取并使用 PhoneHub Skill 技能包。</p>
              <label class="cloud-switch"><input type="checkbox" name="skill_enabled" <?=$skill?'checked':''?>><span class="cloud-switch-ui"></span><span><?=$skill?'已开启':'关闭 Skill'?></span></label>
              <ul><li>控制 Skill 版本查询与下载</li><li>客户还必须单独获得 Skill 授权</li><li>需要存在已启用的签名发布版本</li></ul>
            </section>
          </div>
          <div class="cloud-savebar"><div><strong>修改云端开放策略</strong><small>保存后立即影响后续授权检查与下载请求</small></div><button class="btn primary" type="submit">保存设置</button></div>
        </form>
        <div class="cloud-warning"><strong>安全说明</strong><p>关闭总开关会立即阻止后续版本查询与下载，但不能远程删除客户已经下载的本地文件。桌面客户端必须定期查询 <code>license_status</code> / <code>capabilities</code>，在能力变为不可用时停止本地调用；离线设备在下次联网校验时收到撤销状态。</p></div><?php
    } elseif($view==='gateway') {
        require_owner();
        require_once __DIR__.'/gateway.php';
        $status=gateway_status();
        ?><div class="page-title"><div><h1>客户端接口接管</h1><p>确保旧的 /phonehub/api.php 也执行安卓手机绑定校验，杜绝直接绕过管理后台</p></div></div>
        <div class="card"><h2>当前状态</h2><p><?=h($status['message'])?></p><p class="muted">目标：<code><?=h($status['path'])?></code></p>
        <p class="muted">自动接管只支持安装目录为 /license/、旧接口为同站点 /phonehub/api.php 的典型目录结构，且旧文件与提供的 PhoneHub 0.7.1 参考源码一致。旧接口不同则拒绝覆盖，需要人工审核。</p>
        <?php if($status['can_install']): ?><button class="btn primary" data-action="gateway-install">备份并启用安卓手机绑定校验</button><?php endif ?>
        <p class="footnote">一旦接管，所有操作包下载必须先成功绑定手机。旧版客户端尚不支持 mobile_bind，接管前请为客户规划客户端升级或手工绑定设备。接管时保留旧接口文件备份，不修改签名密钥。</p></div><?php
    } elseif($view==='client_logs') {
        $logs=sql("SELECT l.level,l.event,l.message,l.created_at,u.username,LEFT(l.device_id,12) AS device_short FROM phonehub_client_logs l JOIN phonehub_users u ON u.id=l.user_id ORDER BY l.id DESC LIMIT 200")->fetchAll();
        ?><div class="page-title"><div><h1>客户端运行日志</h1><p>展示最新 200 条日志，客户端使用已授权会话上传</p></div></div><div class="card"><div class="table-scroll"><table><thead><tr><th>时间（北京时间）</th><th>客户</th><th>级别</th><th>事件</th><th>内容（最多 2000 字）</th></tr></thead><tbody><?php foreach($logs as $l): ?><tr><td><?=h(utc_to_cn($l['created_at']))?></td><td><?=h($l['username'])?></td><td><?=h($l['level'])?></td><td><?=h($l['event'])?></td><td style="white-space:normal;min-width:280px"><?=h($l['message'])?></td></tr><?php endforeach ?></tbody></table></div></div><?php
    }
}
