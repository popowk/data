<?php
declare(strict_types=1);
require_once __DIR__.'/mobile.php';
// When upgrading from an older updater, newly introduced modules may not yet
// be copied. Keep unrelated admin pages usable for module repair.
if (is_file(__DIR__.'/devices.php') && is_file(__DIR__.'/device_admin.php'))
    require_once __DIR__.'/device_admin.php';

function phonehub_group_member_snapshot(array $ids): string {
    // The list is ordered by user ID by both preview and the locked apply.
    return hash('sha256',implode(',',array_map(static fn($id)=>(string)(int)$id,$ids)));
}

function feature_action(string $action): never {
    phonehub_require_action($action);
    $id=(int)($_POST['id'] ?? 0);
    if ($action==='admin_create') {
        require_owner();
        $name=trim((string)($_POST['username'] ?? ''));validate_user($name);
        $role=(string)($_POST['role']??'admin');
        if (!in_array($role,['admin','viewer'],true)) throw new RuntimeException('管理员角色无效');
        $password=random_password();
        sql('INSERT INTO phonehub_admins(username,password_hash,role,enabled) VALUES(?,?,?,1)',
            [$name,password_hash_safe($password),$role]);
        audit('admin_create',$name);
        json_response(['ok'=>true,'message'=>'管理员已创建','password'=>$password,'username'=>$name]);
    }
    if (in_array($action,['admin_toggle','admin_reset','admin_delete'],true)) {
        require_owner();
        $target=sql('SELECT id,username,role,enabled FROM phonehub_admins WHERE id=?',[$id])->fetch();
        if (!$target || !in_array($target['role'],['admin','viewer'],true) || (int)$target['id']===admin_id())
            throw new RuntimeException('主管理员受到保护，禁止修改、重置或删除');
        if ($action==='admin_toggle') {
            $next=(int)$target['enabled'] ? 0 : 1;
            sql("UPDATE phonehub_admins SET enabled=?,auth_version=auth_version+1 WHERE id=? AND role IN ('admin','viewer')",[$next,$id]);
            audit('admin_toggle',(string)$target['username']);
            json_response(['ok'=>true,'message'=>$next?'管理员已启用':'管理员已停用']);
        }
        if ($action==='admin_reset') {
            $password=random_password();
            sql("UPDATE phonehub_admins SET password_hash=?,auth_version=auth_version+1 WHERE id=? AND role IN ('admin','viewer')",
                [password_hash_safe($password),$id]);
            audit('admin_reset',(string)$target['username']);
            json_response(['ok'=>true,'message'=>'管理员密码已重置','username'=>$target['username'],'password'=>$password]);
        }
        sql("DELETE FROM phonehub_admins WHERE id=? AND role IN ('admin','viewer')",[$id]);
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
    if (in_array($action,['group_bulk','group_bulk_preview'],true)) {
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
                if (array_diff($v,['douyin','xiaohongshu','mcp','skill','mcp-codex','mcp-harness'])) throw new RuntimeException('未知平台或扩展授权');
                if (array_intersect($v,['mcp','skill','mcp-codex','mcp-harness'])) require_owner();
                if (array_intersect($v,['mcp-codex','mcp-harness']) && !in_array('mcp',$v,true))
                    throw new RuntimeException('Codex 与 DeepSeek Harness MCP 必须同时授权上级 MCP 权限');
                $set[]='u.entitlements=?';$params[]=json_encode(array_values(array_unique($v)),JSON_UNESCAPED_UNICODE);
            }
        }
        $revoke=(bool)array_intersect($fields,['device_limit','enabled','license_until','entitlements']);
        if ($action==='group_bulk_preview') {
            $ids=sql('SELECT u.id FROM phonehub_users u
              JOIN phonehub_user_meta m ON m.user_id=u.id
              WHERE m.group_id=? ORDER BY u.id',[$group])->fetchAll(PDO::FETCH_COLUMN);
            if (!$ids) throw new RuntimeException('该分组没有客户');
            $labels=['device_limit'=>'电脑名额','mobile_limit'=>'安卓手机名额',
              'enabled'=>'账号状态','license_until'=>'授权期限','entitlements'=>'平台与扩展权限'];
            json_response(['ok'=>true,'members'=>count($ids),
              'fields'=>array_map(static fn($f)=>$labels[$f],$fields),
              'revoke_sessions'=>$revoke,'snapshot'=>phonehub_group_member_snapshot($ids)]);
        }
        $preview=(string)($_POST['preview_snapshot']??'');
        if (!preg_match('/^[a-f0-9]{64}$/D',$preview))
            throw new RuntimeException('批量修改需要先在当前页面完成服务端预览');
        db()->beginTransaction();
        try {
            $memberIds=sql('SELECT u.id FROM phonehub_users u
              JOIN phonehub_user_meta m ON m.user_id=u.id
              WHERE m.group_id=? ORDER BY u.id FOR UPDATE',[$group])->fetchAll(PDO::FETCH_COLUMN);
            if (!$memberIds) throw new RuntimeException('该分组没有客户');
            if (!hash_equals($preview,phonehub_group_member_snapshot($memberIds)))
                throw new RuntimeException('预览后分组成员发生变化，未执行修改；请重新预览确认');
            $placeholders=implode(',',array_fill(0,count($memberIds),'?'));
            // Target only the previewed members even if another request joins
            // the group while this transaction is in progress.
            $updateParams=array_merge($params,[$group],$memberIds);
            sql('UPDATE phonehub_users u INNER JOIN phonehub_user_meta m ON m.user_id=u.id
              SET '.implode(',',$set).' WHERE m.group_id=? AND u.id IN ('.$placeholders.')',$updateParams);
            if ($revoke) sql('DELETE FROM phonehub_sessions WHERE user_id IN ('.$placeholders.')',$memberIds);
            audit('group_bulk','group='.$group.' members='.count($memberIds).' fields='.implode(',',$fields));
            db()->commit();
        } catch (Throwable $e) {
            if (db()->inTransaction()) db()->rollBack();
            throw $e;
        }
        json_response(['ok'=>true,'message'=>'已批量更新 '.count($memberIds).' 个客户；'.($revoke?'相关电脑会话已撤销':'无需退出客户端')]);
    }
    if (in_array($action,['device_reveal','device_blacklist_add'],true)) {
        if (!function_exists('device_admin_action'))
            throw new RuntimeException('设备管理模块缺失；请通过系统更新补齐必要文件');
        device_admin_action($action);
    }
    if ($action==='mobile_add') {
        if (!function_exists('device_encrypt'))
            throw new RuntimeException('设备身份加密模块缺失；请通过系统更新补齐必要文件');
        $user=(int)($_POST['user_id']??0);
        $fingerprint=strtolower(trim((string)($_POST['phone_id']??'')));
        $name=trim((string)($_POST['display_name']??''));
        if ($user<1 || !preg_match('/^[a-f0-9]{64}$/D',$fingerprint)) throw new RuntimeException('请选择客户并输入 64 位手机设备指纹');
        if (utf8_length($name)>120) throw new RuntimeException('手机备注过长');
        $imeiRaw=trim((string)($_POST['imei']??''));
        $imeiHash=mobile_imei_hash($imeiRaw);
        $model=trim((string)($_POST['phone_model']??''));
        if (utf8_length($model)>120 || preg_match('/[\\x00-\\x1F]/',$model))
            throw new RuntimeException('手机型号格式错误');
        $phoneNumber=device_phone_normalize(isset($_POST['phone_number'])?(string)$_POST['phone_number']:null);
        $phoneHash=device_phone_hash($phoneNumber);
        $encImei=device_encrypt($imeiRaw);
        $encPhone=device_encrypt($phoneNumber);
        db()->beginTransaction();
        $u=sql('SELECT u.id,u.enabled,COALESCE(m.mobile_limit,0) AS mobile_limit FROM phonehub_users u LEFT JOIN phonehub_user_meta m ON m.user_id=u.id WHERE u.id=? FOR UPDATE',[$user])->fetch();
        if (!$u || !(int)$u['enabled']) throw new RuntimeException('客户不存在或已停用');
        if (mobile_blacklist_match(db(),$fingerprint,$imeiHash,$phoneHash)) throw new RuntimeException('该手机指纹或 IMEI 已在设备黑名单中');
        $existing=sql('SELECT id,enabled,imei_hash,phone_number_hash FROM phonehub_mobile_devices WHERE user_id=? AND phone_id=? FOR UPDATE',[$user,$fingerprint])->fetch();
        $knownImeiHash=$imeiHash??(($existing && !empty($existing['imei_hash']))?(string)$existing['imei_hash']:null);
        if (mobile_blacklist_match(db(),$fingerprint,$knownImeiHash,$phoneHash??($existing['phone_number_hash']??null))) throw new RuntimeException('该手机指纹或 IMEI 已在设备黑名单中');
        if ($existing && $phoneHash!==null && !empty($existing['phone_number_hash']) && !hash_equals((string)$existing['phone_number_hash'],$phoneHash))
            throw new RuntimeException('该设备已绑定不同手机号，需要先解除原有绑定后再核实');
        if ($existing && $imeiHash!==null && !empty($existing['imei_hash']) && !hash_equals((string)$existing['imei_hash'],$imeiHash))
            throw new RuntimeException('该手机指纹已绑定不同 IMEI，请先由主管理员核对设备');
        if ($imeiHash!==null) {
            $other=sql('SELECT id FROM phonehub_mobile_devices WHERE imei_hash=? AND enabled=1 AND NOT(user_id=? AND phone_id=?) LIMIT 1 FOR UPDATE',[$imeiHash,$user,$fingerprint])->fetch();
            if ($other) throw new RuntimeException('该 IMEI 已绑定其他手机记录');
        }
        $active=(int)sql('SELECT COUNT(*) FROM phonehub_mobile_devices WHERE user_id=? AND enabled=1',[$user])->fetchColumn();
        if ((!$existing || !(int)$existing['enabled']) && $active>=(int)$u['mobile_limit']) throw new RuntimeException('已达到客户安卓手机授权上限');
        sql("INSERT INTO phonehub_mobile_devices(user_id,phone_id,display_name,imei_hash,imei_encrypted,phone_model,phone_number_hash,phone_number_encrypted,enabled,last_seen)
            VALUES(?,?,?,?,?,?,?,?,1,UTC_TIMESTAMP()) ON DUPLICATE KEY UPDATE
            display_name=VALUES(display_name),imei_hash=COALESCE(VALUES(imei_hash),imei_hash),
            imei_encrypted=COALESCE(VALUES(imei_encrypted),imei_encrypted),
            phone_model=COALESCE(NULLIF(VALUES(phone_model),''),phone_model),
            phone_number_hash=COALESCE(VALUES(phone_number_hash),phone_number_hash),
            phone_number_encrypted=COALESCE(VALUES(phone_number_encrypted),phone_number_encrypted),
            enabled=1,last_seen=UTC_TIMESTAMP()",[$user,$fingerprint,$name,$imeiHash,$encImei,$model,$phoneHash,$encPhone]);
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
        $values=[
            'mcp_enabled'=>isset($_POST['mcp_enabled'])?'1':'0',
            'mcp_codex_enabled'=>isset($_POST['mcp_codex_enabled'])?'1':'0',
            'mcp_harness_enabled'=>isset($_POST['mcp_harness_enabled'])?'1':'0',
            'skill_enabled'=>isset($_POST['skill_enabled'])?'1':'0'
        ];
        foreach($values as $key=>$value) sql('INSERT INTO phonehub_feature_settings(setting_key,setting_value) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)',[$key,$value]);
        audit('cloud_features_save','mcp='.$values['mcp_enabled'].', codex='.$values['mcp_codex_enabled'].', harness='.$values['mcp_harness_enabled'].', skill='.$values['skill_enabled']);
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
    phonehub_require_view($view==='mobiles'?'devices':$view);
    if ($view==='admins') {
        require_owner();
        $admins=sql('SELECT id,username,role,enabled,created_at FROM phonehub_admins ORDER BY CASE WHEN role=\'owner\' THEN 0 ELSE 1 END,id')->fetchAll();
        ?><div class="page-title"><div><h1>管理员管理</h1><p>仅主管理员可以创建、停用、重置或删除其他管理员</p></div></div>
        <div class="card"><div class="card-head"><h2>创建管理员</h2></div>
        <form data-ajax="admin_create" class="inline-form admin-create-form"><input name="action" type="hidden" value="admin_create"><input name="username" placeholder="管理员登录名（3–64 位英文字符）" required minlength="3"><select name="role" aria-label="管理员角色" required><option value="admin">普通管理员（可维护授权）</option><option value="viewer">只读管理员（只能查看）</option></select><button class="btn primary">创建并生成密码</button></form><p class="footnote">只读管理员仅可浏览概览、客户授权、分组及操作包；后台 POST 由服务器拒绝。原普通管理员权限不变。</p></div>
        <div class="card"><div class="card-head"><h2>管理员列表</h2></div><div class="table-scroll"><table><thead><tr><th>管理员</th><th>权限</th><th>状态</th><th>创建时间</th><th>操作</th></tr></thead><tbody>
        <?php foreach($admins as $a): ?><tr><td><b><?=h($a['username'])?></b></td><td><?=h(phonehub_role_label((string)$a['role']))?><?= $a['role']==='owner'?'（受保护）':'' ?></td><td><span class="pill <?=(int)$a['enabled']?'ok':'off'?>"><?=(int)$a['enabled']?'正常':'已停用'?></span></td><td><?=h(utc_to_cn($a['created_at']))?></td><td>
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
                <label><input data-bulk-field type="checkbox" name="entitlements[]" value="mcp-codex" disabled> Codex MCP</label>
                <label><input data-bulk-field type="checkbox" name="entitlements[]" value="mcp-harness" disabled> DeepSeek Harness MCP</label>
                <label><input data-bulk-field type="checkbox" name="entitlements[]" value="skill" disabled> Skill</label>
              </div><small>未勾选的平台将从客户授权中移除；MCP/Skill 还需要主管理员开启云端总开关。</small>
            </div>
          </section>
        </div>
        <div class="bulk-impact"><strong>生效提示</strong><p>修改电脑名额、客户状态、授权期限或平台权限时，会撤销该分组客户现有的电脑会话。修改手机名额不会主动解绑已有手机。</p></div>
        <div class="bulk-submit"><div><strong id="bulk-summary">尚未选择修改项</strong><small>提交后先由服务器预检影响人数和字段，确认后才执行；分组成员变化时拒绝旧预览</small></div><button class="btn primary" type="submit" data-confirm-submit="此操作将批量修改所选分组的指定授权字段，确认继续？">应用批量配置</button></div>
        </form>
        <?php
    } elseif ($view==='mobiles' || $view==='devices') {
        if (!function_exists('device_admin_view')) {
            ?><div class="card"><h2>设备管理模块尚未补齐</h2>
            <p class="muted">缺少 app/devices.php 或 app/device_admin.php。旧版升级器未包含新模块时会出现这种情况。请进入「系统更新」检查并补齐缺失模块，不要清空客户数据。</p>
            <a class="btn primary" href="?view=update">前往系统更新</a></div><?php
        } else {
            device_admin_view();
        }
    } elseif ($view==='cloud_features') {
        require_owner();
        $rows=sql("SELECT setting_key,setting_value FROM phonehub_feature_settings WHERE setting_key IN ('mcp_enabled','skill_enabled','mcp_codex_enabled','mcp_harness_enabled')")->fetchAll();
        $flags=[];foreach($rows as $row)$flags[$row['setting_key']]=$row['setting_value']==='1';
        $mcp=!empty($flags['mcp_enabled']);$skill=!empty($flags['skill_enabled']);
        $codex=!empty($flags['mcp_codex_enabled']);$harness=!empty($flags['mcp_harness_enabled']);
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
          <div class="card" style="margin-top:14px">
          <div class="card-head"><h2>MCP 平台独立授权</h2></div>
          <p class="muted">Codex 和 DeepSeek Harness 默认关闭。实际开放还必须同时启用上方 MCP 总开关，并给客户同时授予 MCP 和对应平台权限。旧版 MCP 权限保持不变，不自动升级为新权限。</p>
          <div class="form-grid">
            <div class="field"><label class="check-row"><input type="checkbox" name="mcp_codex_enabled" <?=$codex?'checked':''?>> Codex MCP 全局开放</label></div>
            <div class="field"><label class="check-row"><input type="checkbox" name="mcp_harness_enabled" <?=$harness?'checked':''?>> DeepSeek Harness MCP 全局开放</label></div>
          </div>
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

// Embedded in this established signed module for updates from v0.5.4.
// Owner-only opening quota templates. No pricing, orders, billing or privileges.
function plan_admin_action(string $action): never {
    require_owner();
    if ($action==='plan_save') {
        $id=(int)($_POST['id']??0);
        $name=trim((string)($_POST['name']??''));
        $pc=(int)($_POST['device_limit']??0);
        $mobile=(int)($_POST['mobile_limit']??-1);
        $sort=(int)($_POST['sort_order']??100);
        if ($name==='' || utf8_length($name)>64 || preg_match('/[\\x00-\\x1F\\x7F]/u',$name))
            throw new RuntimeException('套餐名称须为 1–64 个字符');
        if ($pc<1 || $pc>100 || $mobile<0 || $mobile>1000 || $sort<0 || $sort>9999)
            throw new RuntimeException('套餐额度或排序范围不正确');
        db()->beginTransaction();
        try {
            if ($id && !sql('SELECT id FROM phonehub_plan_templates WHERE id=? FOR UPDATE',[$id])->fetch())
                throw new RuntimeException('套餐不存在');
            if ((int)sql('SELECT COUNT(*) FROM phonehub_plan_templates WHERE name=? AND id<>?',[$name,$id])->fetchColumn())
                throw new RuntimeException('套餐名称已存在');
            if ($id) sql('UPDATE phonehub_plan_templates SET name=?,device_limit=?,mobile_limit=?,sort_order=? WHERE id=?',
                [$name,$pc,$mobile,$sort,$id]);
            else {
                $code='plan_'.bin2hex(random_bytes(6));
                sql('INSERT INTO phonehub_plan_templates(plan_code,name,device_limit,mobile_limit,enabled,sort_order) VALUES(?,?,?,?,1,?)',
                    [$code,$name,$pc,$mobile,$sort]);
                $id=(int)db()->lastInsertId();
            }
            audit('plan_save','plan_id='.$id);
            db()->commit();
        } catch(Throwable $e) {if(db()->inTransaction())db()->rollBack();throw $e;}
        json_response(['ok'=>true,'message'=>'套餐保存成功，现有客户额度保持不变','id'=>$id]);
    }
    if ($action==='plan_toggle') {
        $id=(int)($_POST['id']??0);
        if ($id<1) throw new RuntimeException('套餐不存在');
        db()->beginTransaction();
        try {
            $row=sql('SELECT enabled FROM phonehub_plan_templates WHERE id=? FOR UPDATE',[$id])->fetch();
            if (!$row) throw new RuntimeException('套餐不存在');
            $enabled=(int)$row['enabled']?0:1;
            sql('UPDATE phonehub_plan_templates SET enabled=? WHERE id=?',[$enabled,$id]);
            audit('plan_toggle','plan_id='.$id.',enabled='.$enabled);
            db()->commit();
        } catch(Throwable $e) {if(db()->inTransaction())db()->rollBack();throw $e;}
        json_response(['ok'=>true,'message'=>$enabled?'已启用套餐':'已停用套餐，已有客户保持不变']);
    }
    throw new RuntimeException('无效套餐操作');
}
function plan_admin_view(): void {
    require_owner();
    $plans=sql('SELECT p.*,COALESCE(a.users,0) AS users,
        COALESCE(a.actual_computers,0) AS actual_computers,
        COALESCE(a.actual_mobiles,0) AS actual_mobiles
        FROM phonehub_plan_templates p LEFT JOIN (
          SELECT m.opening_plan_code,COUNT(*) AS users,
                 SUM(u.device_limit) AS actual_computers,SUM(m.mobile_limit) AS actual_mobiles
          FROM phonehub_user_meta m JOIN phonehub_users u ON u.id=m.user_id
          WHERE m.opening_plan_code IS NOT NULL
          GROUP BY m.opening_plan_code
        ) a ON a.opening_plan_code=p.plan_code
        ORDER BY p.sort_order,p.id')->fetchAll();
    $historical=sql("SELECT
      SUM(CASE WHEN opening_plan_code IS NULL THEN 1 ELSE 0 END) AS legacy,
      SUM(CASE WHEN opening_plan_code='custom' THEN 1 ELSE 0 END) AS custom
      FROM phonehub_user_meta")->fetch();
    $activePlans=count(array_filter($plans,static fn($p)=>(int)$p['enabled']===1));
    $assignedAccounts=array_sum(array_map(static fn($p)=>(int)$p['users'],$plans));
    ?>
    <div class="page-title"><div><h1>套餐管理</h1><p>用于新客户开户的电脑与手机额度；不包含价格、订单或支付</p></div><button class="btn primary" type="button" data-action="new-plan">+ 新增套餐</button></div>
    <div class="stats plan-stats">
      <div class="stat"><span>已启用模板</span><strong><?=$activePlans?></strong><small>共 <?=count($plans)?> 个模板</small></div>
      <div class="stat"><span>模板开户客户</span><strong><?=$assignedAccounts?></strong><small>仅统计目前仍可识别的模板代码</small></div>
      <div class="stat"><span>自定义开户</span><strong><?=(int)($historical['custom']??0)?></strong><small>客户当前额度独立管理</small></div>
      <div class="stat"><span>原有授权</span><strong><?=(int)($historical['legacy']??0)?></strong><small>历史创建且没有套餐标签</small></div>
    </div>
    <div class="card editor" id="plan-editor" hidden>
      <div class="card-head"><h2 id="plan-editor-title">新增套餐</h2><button class="text-button" type="button" data-action="close-plan-editor">关闭</button></div>
      <form data-ajax="plan_save"><input type="hidden" name="action" value="plan_save"><input type="hidden" name="id" value="0">
        <div class="form-grid">
          <div class="field span2"><label>套餐名称</label><input name="name" maxlength="64" required placeholder="例如：企业版"></div>
          <div class="field"><label>电脑名额</label><input name="device_limit" type="number" min="1" max="100" required value="3"></div>
          <div class="field"><label>安卓手机名额</label><input name="mobile_limit" type="number" min="0" max="1000" required value="5"></div>
          <div class="field"><label>排序</label><input name="sort_order" type="number" min="0" max="9999" required value="100"></div>
        </div>
        <p class="footnote">修改或停用套餐不影响已有客户，也不开放额外软件、AI 或 MCP 权限。</p>
        <button class="btn primary" type="submit">保存套餐</button>
      </form>
    </div>
    <div class="card"><div class="card-head"><h2>开户套餐</h2><span class="count"><?=count($plans)?> 个</span></div>
      <div class="table-scroll"><table><thead><tr><th>名称</th><th>模板电脑</th><th>模板手机</th><th>已开户客户</th><th>历史客户当前总额度</th><th>排序</th><th>状态</th><th>操作</th></tr></thead><tbody>
      <?php foreach($plans as $p):
        $edit=['id'=>(int)$p['id'],'name'=>$p['name'],'device_limit'=>(int)$p['device_limit'],
           'mobile_limit'=>(int)$p['mobile_limit'],'sort_order'=>(int)$p['sort_order']];
      ?>
        <tr><td><b><?=h($p['name'])?></b><small class="device-subline"><?=h($p['plan_code'])?></small></td>
          <td><?=(int)$p['device_limit']?></td><td><?=(int)$p['mobile_limit']?></td>
          <td><a class="small-link" href="?view=accounts&amp;plan=<?=rawurlencode($p['plan_code'])?>"><?=(int)$p['users']?> 位</a></td>
          <td><?=(int)$p['actual_computers']?> 台电脑 / <?=(int)$p['actual_mobiles']?> 部手机</td><td><?=(int)$p['sort_order']?></td>
          <td><span class="pill <?=(int)$p['enabled']?'ok':'off'?>"><?=(int)$p['enabled']?'启用':'停用'?></span></td>
          <td><button class="small-link" type="button" data-plan-edit="<?=h(json_encode($edit,JSON_UNESCAPED_UNICODE|JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_QUOT|JSON_HEX_APOS))?>">编辑</button>
          <button class="small-link <?=(int)$p['enabled']?'danger-action':''?>" type="button" data-action="plan-toggle" data-id="<?=(int)$p['id']?>"><?=(int)$p['enabled']?'停用':'启用'?></button></td>
        </tr>
      <?php endforeach ?></tbody></table></div>
    </div>
    <p class="footnote">“模板电脑/手机”是新开户采用的额度；“历史客户当前总额度”汇总实际客户名额，修改或停用模板不会改变历史客户。点击开户客户数可查看对应客户。</p>
    <?php
}

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
