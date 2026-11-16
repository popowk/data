<?php
declare(strict_types=1);
require __DIR__.'/app/core.php';
if (!installed()) { header('Location: install.php'); exit; }

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        check_csrf();
        $action = (string)($_POST['action'] ?? '');
        if ($action === 'login') {
            $name = trim((string)($_POST['username'] ?? ''));
            $pass = (string)($_POST['password'] ?? '');
            $bucket = hash('sha256',strtolower($name).'|'.($_SERVER['REMOTE_ADDR'] ?? ''));
            sql("DELETE FROM phonehub_admin_attempts WHERE attempted_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 HOUR)");
            if ((int)sql("SELECT COUNT(*) FROM phonehub_admin_attempts WHERE bucket=? AND attempted_at>DATE_SUB(UTC_TIMESTAMP(), INTERVAL 15 MINUTE)",[$bucket])->fetchColumn() >= 10) {
                throw new RuntimeException('尝试次数过多，请 15 分钟后再试');
            }
            sql('INSERT INTO phonehub_admin_attempts(bucket,attempted_at) VALUES(?,UTC_TIMESTAMP())',[$bucket]);
            $admin = sql('SELECT id,password_hash FROM phonehub_admins WHERE username=?',[$name])->fetch();
            $dummy = '$2y$12$Opl.I2mSCM0yvkJqMD4I1eTUpr3Z1dPRqaY51Jcz9OqJRDCqTWX7i';
            if (!$admin || !password_verify($pass,(string)($admin['password_hash'] ?? $dummy))) throw new RuntimeException('管理员账号或密码错误');
            sql('DELETE FROM phonehub_admin_attempts WHERE bucket=?',[$bucket]);
            session_regenerate_id(true); $_SESSION['admin_id']=(int)$admin['id']; $_SESSION['admin_user']=$name;
            json_response(['ok'=>true]);
        }
        require_admin();
        if ($action === 'logout') {
            $_SESSION=[]; session_regenerate_id(true);
            json_response(['ok'=>true]);
        }
        if ($action === 'group_create') {
            $name = trim((string)($_POST['name'] ?? ''));
            if ($name==='' || mb_strlen($name)>100) throw new RuntimeException('请输入 1–100 字的分组名称');
            sql('INSERT INTO phonehub_groups(name) VALUES(?)',[$name]);
            audit('group_create',$name);
            json_response(['ok'=>true,'message'=>'分组已创建']);
        }
        if ($action === 'group_delete') {
            $id=(int)($_POST['id'] ?? 0);
            if ($id<1) throw new RuntimeException('分组无效');
            if ((int)sql('SELECT COUNT(*) FROM phonehub_user_meta WHERE group_id=?',[$id])->fetchColumn()>0) throw new RuntimeException('请先将客户移出此分组');
            sql('DELETE FROM phonehub_groups WHERE id=?',[$id]);
            audit('group_delete',(string)$id);
            json_response(['ok'=>true,'message'=>'分组已删除']);
        }
        if ($action === 'account_save') {
            $id=(int)($_POST['id'] ?? 0);
            $name=trim((string)($_POST['username'] ?? ''));
            validate_user($name);
            $limit=(int)($_POST['device_limit'] ?? 3);
            $mobile=(int)($_POST['mobile_limit'] ?? 0);
            $group=(int)($_POST['group_id'] ?? 0);
            $enabled=isset($_POST['enabled']) ? 1 : 0;
            if ($limit<1 || $limit>100 || $mobile<0 || $mobile>1000) throw new RuntimeException('电脑限额为 1–100，手机限额为 0–1000');
            if ($group && !(int)sql('SELECT COUNT(*) FROM phonehub_groups WHERE id=?',[$group])->fetchColumn()) throw new RuntimeException('分组不存在');
            $entitlements=array_values(array_intersect(['douyin','xiaohongshu'],(array)($_POST['entitlements'] ?? [])));
            $until=input_to_utc(trim((string)($_POST['license_until'] ?? '')));
            $notes=trim((string)($_POST['notes'] ?? ''));
            if (mb_strlen($notes)>500) throw new RuntimeException('备注不能超过 500 字');
            $pass=(string)($_POST['password'] ?? '');
            db()->beginTransaction();
            if ($id) {
                $old=sql('SELECT username,enabled,device_limit FROM phonehub_users WHERE id=? FOR UPDATE',[$id])->fetch();
                if (!$old) throw new RuntimeException('账号不存在');
                if ($pass!=='') {
                    $hash=password_hash_safe($pass);
                    sql('UPDATE phonehub_users SET username=?,password_hash=?,enabled=?,device_limit=?,license_until=?,entitlements=? WHERE id=?',
                        [$name,$hash,$enabled,$limit,$until,json_encode($entitlements),$id]);
                } else {
                    sql('UPDATE phonehub_users SET username=?,enabled=?,device_limit=?,license_until=?,entitlements=? WHERE id=?',
                        [$name,$enabled,$limit,$until,json_encode($entitlements),$id]);
                }
                if (!$enabled || $pass!=='' || $limit<(int)$old['device_limit']) sql('DELETE FROM phonehub_sessions WHERE user_id=?',[$id]);
            } else {
                $hash=password_hash_safe($pass);
                sql('INSERT INTO phonehub_users(username,password_hash,enabled,device_limit,license_until,entitlements) VALUES(?,?,?,?,?,?)',
                    [$name,$hash,$enabled,$limit,$until,json_encode($entitlements)]);
                $id=(int)db()->lastInsertId();
            }
            sql('INSERT INTO phonehub_user_meta(user_id,group_id,mobile_limit,notes) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE group_id=VALUES(group_id),mobile_limit=VALUES(mobile_limit),notes=VALUES(notes)',
                [$id,$group?:null,$mobile,$notes]);
            audit('account_save',$name);
            db()->commit();
            json_response(['ok'=>true,'message'=>'授权已保存','id'=>$id]);
        }
        if ($action === 'reset_sessions') {
            $id=(int)($_POST['id'] ?? 0);
            if ($id<1) throw new RuntimeException('账号无效');
            sql('DELETE FROM phonehub_sessions WHERE user_id=?',[$id]);
            audit('sessions_revoke',(string)$id);
            json_response(['ok'=>true,'message'=>'该客户会话已撤销']);
        }
        if ($action === 'revoke_session') {
            $id=(int)($_POST['id'] ?? 0);
            sql('DELETE FROM phonehub_sessions WHERE id=?',[$id]);
            audit('session_revoke',(string)$id);
            json_response(['ok'=>true,'message'=>'会话已撤销']);
        }
        if (in_array($action,['update_check','update_apply'],true)) {
            require __DIR__.'/app/updater.php';
            if ($action==='update_check') json_response(['ok'=>true]+check_update());
            $result=apply_update();
            audit('system_update',(string)($result['version'] ?? ''));
            json_response(['ok'=>true]+$result);
        }
        throw new RuntimeException('未知操作');
    } catch (Throwable $e) {
        if (db_safe_in_transaction()) db()->rollBack();
        $message = $e instanceof PDOException ? '数据库操作失败，请检查是否重复或数据格式不正确' : $e->getMessage();
        error_log('PhoneHub admin: '.get_class($e));
        json_response(['ok'=>false,'error'=>$message],400);
    }
}
function db_safe_in_transaction(): bool {
    try {return installed() && db()->inTransaction();} catch (Throwable $e) {return false;}
}
if (admin_id()) {
    $exists=sql('SELECT id FROM phonehub_admins WHERE id=?',[admin_id()])->fetchColumn();
    if (!$exists) {$_SESSION=[];session_regenerate_id(true);}
}
if (!admin_id()) {
?>
<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>登录 · PhoneHub</title><link rel="stylesheet" href="assets/app.css"><meta name="csrf" content="<?=h(csrf())?>"></head>
<body class="auth-body"><main class="auth-card">
<div class="brand"><span class="brand-mark">P</span><div><strong>PhoneHub</strong><small>License Console</small></div></div>
<h1>登录管理后台</h1><p class="muted">统一管理客户、授权、设备会话及系统更新。</p>
<form data-ajax="login"><input type="hidden" name="action" value="login"><div class="field"><label>管理员账号</label><input name="username" autocomplete="username" required autofocus></div><div class="field"><label>管理员密码</label><input type="password" name="password" autocomplete="current-password" required></div>
<button class="btn primary full">登录</button></form><p id="message" class="footnote"></p></main><script src="assets/app.js" defer></script></body></html>
<?php exit; }
$view=(string)($_GET['view'] ?? 'dashboard');
if (!in_array($view,['dashboard','accounts','groups','sessions','packages','update','audit'],true)) $view='dashboard';
$groups=sql('SELECT id,name,(SELECT COUNT(*) FROM phonehub_user_meta m WHERE m.group_id=g.id) AS users FROM phonehub_groups g ORDER BY id DESC')->fetchAll();
$accounts=($view==='accounts'||$view==='dashboard') ? sql("SELECT u.id,u.username,u.enabled,u.device_limit,u.license_until,u.entitlements,u.created_at,m.group_id,COALESCE(m.mobile_limit,0) AS mobile_limit,COALESCE(m.notes,'') AS notes,g.name AS group_name,(SELECT COUNT(DISTINCT s.device_id) FROM phonehub_sessions s WHERE s.user_id=u.id AND s.expires_at>UTC_TIMESTAMP()) AS active_devices FROM phonehub_users u LEFT JOIN phonehub_user_meta m ON m.user_id=u.id LEFT JOIN phonehub_groups g ON g.id=m.group_id ORDER BY u.id DESC")->fetchAll() : [];
$nav=['dashboard'=>['概览','▦'],'accounts'=>['客户授权','♙'],'groups'=>['客户分组','◫'],'sessions'=>['电脑会话','▣'],'packages'=>['操作包','⬡'],'update'=>['系统更新','⟳'],'audit'=>['操作记录','☷']];
?>
<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf" content="<?=h(csrf())?>"><title>PhoneHub 管理控制台</title><link rel="stylesheet" href="assets/app.css"></head>
<body><div class="app"><aside class="sidebar"><div class="brand"><span class="brand-mark">P</span><div><strong>PhoneHub</strong><small>授权管理中心</small></div></div>
<nav><?php foreach ($nav as $route=>$item): ?><a class="<?= $view===$route?'active':'' ?>" href="?view=<?=h($route)?>"><span class="nav-icon"><?=h($item[1])?></span><?=h($item[0])?></a><?php endforeach ?></nav>
<div class="sidebar-footer"><span class="status-dot"></span> 运行中 <small>v<?=h(app_version())?></small></div></aside>
<div class="main"><header class="topbar"><div><span class="crumb">PhoneHub /</span> <?=h($nav[$view][0])?></div><div class="top-right"><span class="avatar"><?=h(mb_substr((string)($_SESSION['admin_user']??'A'),0,1))?></span><?=h($_SESSION['admin_user']??'管理员')?><button class="text-button" data-action="logout">退出</button></div></header>
<main id="content" class="content">
<?php if ($view==='dashboard'):
    $total=count($accounts);$enabled=count(array_filter($accounts,fn($u)=>(int)$u['enabled']===1));$devices=array_sum(array_map(fn($u)=>(int)$u['active_devices'],$accounts));
?>
<div class="page-title"><div><h1>运营概览</h1><p>客户授权与电脑会话状态一览</p></div><a class="btn primary" href="?view=accounts">+ 新增授权</a></div>
<div class="stats"><div class="stat"><span>客户总数</span><strong><?=$total?></strong><small>全部授权账号</small></div><div class="stat"><span>正常授权</span><strong><?=$enabled?></strong><small>账号启用中（不含到期校验）</small></div><div class="stat"><span>电脑名额占用</span><strong><?=$devices?></strong><small>未过期的设备会话</small></div><div class="stat"><span>客户分组</span><strong><?=count($groups)?></strong><small>支持自主分组管理</small></div></div>
<div class="card"><div class="card-head"><h2>最近客户</h2><a href="?view=accounts">查看全部</a></div><div class="table-scroll"><table><thead><tr><th>客户账号</th><th>分组</th><th>电脑名额</th><th>授权期限</th><th>状态</th></tr></thead><tbody><?php foreach (array_slice($accounts,0,8) as $a): ?><tr><td><b><?=h($a['username'])?></b></td><td><?=h($a['group_name']??'未分组')?></td><td><?= (int)$a['active_devices']?> / <?= (int)$a['device_limit']?></td><td><?=h(utc_to_cn($a['license_until']))?></td><td><span class="pill <?= (int)$a['enabled']?'ok':'off'?>"><?= (int)$a['enabled']?'启用':'停用'?></span></td></tr><?php endforeach ?></tbody></table></div></div>
<?php elseif ($view==='accounts'): ?>
<div class="page-title"><div><h1>客户授权</h1><p>电脑名额实时校验，手机额度供后续客户端接入</p></div><button class="btn primary" data-action="new-account">+ 创建客户</button></div>
<div class="card editor" id="account-editor" hidden><div class="card-head"><h2 id="editor-title">创建客户</h2><button class="text-button" data-action="close-editor">关闭</button></div>
<form data-ajax="account_save"><input name="action" type="hidden" value="account_save"><input name="id" type="hidden" value="0">
<div class="form-grid"><div class="field"><label>客户账号</label><input name="username" required minlength="3" maxlength="64"></div>
<div class="field"><label>密码（新增必填，编辑留空不修改）</label><input name="password" type="password" autocomplete="new-password"></div>
<div class="field"><label>客户分组</label><select name="group_id"><option value="0">未分组</option><?php foreach($groups as $g): ?><option value="<?=(int)$g['id']?>"><?=h($g['name'])?></option><?php endforeach ?></select></div>
<div class="field"><label>授权截止时间（北京时间，留空永久）</label><input name="license_until" type="datetime-local"></div>
<div class="field"><label>电脑授权名额（1–100）</label><input name="device_limit" type="number" min="1" max="100" value="3"></div>
<div class="field"><label>安卓手机名额（预留配置）</label><input name="mobile_limit" type="number" min="0" max="1000" value="0"></div>
<div class="field"><label>平台权限</label><div class="check-row"><label><input type="checkbox" name="entitlements[]" value="douyin" checked> 抖音</label><label><input type="checkbox" name="entitlements[]" value="xiaohongshu"> 小红书（预留）</label></div></div>
<div class="field"><label>账号状态</label><label class="check-row"><input type="checkbox" name="enabled" checked> 启用账号</label></div>
<div class="field span2"><label>内部备注</label><input name="notes" maxlength="500" placeholder="可填写客户联系方式、购买产品等"></div>
</div><div class="editor-actions"><button class="btn primary">保存授权</button></div></form></div>
<div class="card"><div class="card-head"><h2>全部客户</h2><span class="count"><?=count($accounts)?> 个账号</span></div>
<div class="table-scroll"><table><thead><tr><th>客户账号</th><th>分组</th><th>电脑名额</th><th>手机额度</th><th>授权截止（北京时间）</th><th>平台权限</th><th>状态</th><th>操作</th></tr></thead><tbody>
<?php foreach($accounts as $a): $payload=['id'=>(int)$a['id'],'username'=>$a['username'],'group_id'=>(int)$a['group_id'],'device_limit'=>(int)$a['device_limit'],'mobile_limit'=>(int)$a['mobile_limit'],'license_until'=>utc_to_input($a['license_until']),'entitlements'=>json_decode((string)$a['entitlements'],true)?:[],'notes'=>$a['notes'],'enabled'=>(bool)$a['enabled']]; ?>
<tr><td><b><?=h($a['username'])?></b></td><td><?=h($a['group_name']??'未分组')?></td><td><?= (int)$a['active_devices']?> / <?= (int)$a['device_limit']?></td><td><?= (int)$a['mobile_limit']?></td><td><?=h(utc_to_cn($a['license_until']))?></td><td><?=h(implode('、',json_decode((string)$a['entitlements'],true)?:[]))?></td>
<td><span class="pill <?= (int)$a['enabled']?'ok':'off'?>"><?= (int)$a['enabled']?'启用':'停用'?></span></td><td class="actions">
<button class="small-link" data-edit="<?=h(json_encode($payload,JSON_UNESCAPED_UNICODE|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP|JSON_HEX_TAG))?>">编辑</button>
<button class="small-link" data-action="revoke-account" data-id="<?=(int)$a['id']?>">踢下线</button></td></tr><?php endforeach ?></tbody></table></div></div>
<?php elseif($view==='groups'): ?>
<div class="page-title"><div><h1>客户分组</h1><p>将代理商、企业或购买渠道分组管理</p></div></div><div class="card"><div class="card-head"><h2>新建分组</h2></div><form class="inline-form" data-ajax="group_create"><input type="hidden" name="action" value="group_create"><input name="name" placeholder="例如：代理商A / 企业客户" maxlength="100" required><button class="btn primary">创建分组</button></form></div>
<div class="card"><div class="card-head"><h2>已创建分组</h2></div><div class="table-scroll"><table><thead><tr><th>分组名称</th><th>客户数</th><th>操作</th></tr></thead><tbody><?php foreach($groups as $g): ?><tr><td><b><?=h($g['name'])?></b></td><td><?=(int)$g['users']?></td><td><button class="small-link" data-action="delete-group" data-id="<?=(int)$g['id']?>">删除</button></td></tr><?php endforeach ?></tbody></table></div></div>
<?php elseif($view==='sessions'): $sessions=sql("SELECT s.id,u.username,s.device_id,s.expires_at FROM phonehub_sessions s JOIN phonehub_users u ON u.id=s.user_id WHERE s.expires_at>UTC_TIMESTAMP() ORDER BY s.expires_at DESC LIMIT 500")->fetchAll(); ?>
<div class="page-title"><div><h1>电脑会话</h1><p>当前列出未过期的登录会话；这不代表实时在线</p></div></div><div class="card"><div class="table-scroll"><table><thead><tr><th>客户账号</th><th>设备安装标识</th><th>会话截止（北京时间）</th><th>操作</th></tr></thead><tbody><?php foreach($sessions as $s): ?><tr><td><?=h($s['username'])?></td><td><code title="<?=h($s['device_id'])?>"><?=h(substr($s['device_id'],0,16))?>…</code></td><td><?=h(utc_to_cn($s['expires_at']))?></td><td><button class="small-link" data-action="revoke-session" data-id="<?=(int)$s['id']?>">强制下线</button></td></tr><?php endforeach ?></tbody></table></div></div>
<?php elseif($view==='packages'): $packages=sql('SELECT package_id,MAX(version) AS version,COUNT(*) AS versions FROM phonehub_packages GROUP BY package_id ORDER BY package_id')->fetchAll(); ?>
<div class="page-title"><div><h1>平台操作包</h1><p>兼容现有 PhoneHub 加密包协议；本版本仅展示，不处理签名私钥</p></div></div>
<div class="card"><div class="table-scroll"><table><thead><tr><th>平台包</th><th>最高版本</th><th>历史版本数量</th></tr></thead><tbody><?php foreach($packages as $p): ?><tr><td><?=h($p['package_id'])?></td><td><?=h($p['version'])?></td><td><?=h($p['versions'])?></td></tr><?php endforeach ?></tbody></table></div></div>
<?php elseif($view==='update'): ?>
<div class="page-title"><div><h1>系统更新</h1><p>从国内镜像获取 GitHub 仓库最新代码，完成备份后在线安装</p></div></div>
<div class="card update-card"><div class="update-icon">⟳</div><h2>当前版本 v<?=h(app_version())?></h2><p class="muted">更新源：<code>https://git.wksite.cn/popowk/data</code></p><p class="muted">仅更新管理程序文件，自动跳过 storage 内的数据库配置和运行数据。</p>
<div class="update-actions"><button class="btn" data-action="check-update">检查更新</button><button class="btn primary" id="apply-update" data-action="apply-update" disabled>下载并安装更新</button></div><p id="update-status" class="update-status">正在等待检查…</p></div>
<div class="card"><h2>更新说明</h2><p class="muted">安装前自动备份原文件。下载、解压、写入或校验失败会报错；写入阶段失败将尝试自动回滚。更新过程不删除客户、会话和数据库。镜像站需要支持 GitHub 源码 ZIP 下载接口。</p></div>
<?php elseif($view==='audit'): $audits=sql("SELECT a.action,a.target,a.ip,a.created_at,m.username FROM phonehub_admin_audit a LEFT JOIN phonehub_admins m ON m.id=a.admin_id ORDER BY a.id DESC LIMIT 100")->fetchAll(); ?>
<div class="page-title"><div><h1>管理员操作记录</h1><p>记录授权、分组、设备与更新操作</p></div></div><div class="card"><div class="table-scroll"><table><thead><tr><th>时间（北京时间）</th><th>管理员</th><th>操作</th><th>目标</th><th>IP</th></tr></thead><tbody><?php foreach($audits as $a): ?><tr><td><?=h(utc_to_cn($a['created_at']))?></td><td><?=h($a['username'])?></td><td><?=h($a['action'])?></td><td><?=h($a['target'])?></td><td><?=h($a['ip'])?></td></tr><?php endforeach ?></tbody></table></div></div>
<?php endif ?>
</main></div></div><div class="toast" id="toast" role="status" aria-live="polite"></div><script src="assets/app.js" defer></script></body></html>
