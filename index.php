<?php
declare(strict_types=1);
require __DIR__.'/app/core.php';
// Keep login and self-update available if a legacy updater missed accounts.php.
if (is_file(__DIR__.'/app/accounts.php'))
    require_once __DIR__.'/app/accounts.php';
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
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
            $admin = sql('SELECT id,password_hash,enabled,auth_version FROM phonehub_admins WHERE username=?',[$name])->fetch();
            $dummy = '$2y$12$Opl.I2mSCM0yvkJqMD4I1eTUpr3Z1dPRqaY51Jcz9OqJRDCqTWX7i';
            if (!$admin || !(int)$admin['enabled'] || !password_verify($pass,(string)($admin['password_hash'] ?? $dummy))) throw new RuntimeException('管理员账号或密码错误');
            sql('DELETE FROM phonehub_admin_attempts WHERE bucket=?',[$bucket]);
            session_regenerate_id(true); $_SESSION['admin_id']=(int)$admin['id']; $_SESSION['admin_user']=$name; $_SESSION['auth_version']=(int)$admin['auth_version'];
            json_response(['ok'=>true]);
        }
        require_admin();
        if ($action === 'logout') {
            $_SESSION=[]; session_regenerate_id(true);
            json_response(['ok'=>true]);
        }
        if ($action === 'group_create') {
            $name = trim((string)($_POST['name'] ?? ''));
            if ($name==='' || utf8_length($name)>100) throw new RuntimeException('请输入 1–100 字的分组名称');
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
            $creating=$id===0;
            $name=trim((string)($_POST['username'] ?? ''));
            validate_user($name);
            $limit=(int)($_POST['device_limit'] ?? 3);
            $mobile=(int)($_POST['mobile_limit'] ?? 1);
            $aiEnabled=isset($_POST['ai_enabled'])?1:0;
            $allowClientAiKey=isset($_POST['allow_client_ai_key'])?1:0;
            if ($allowClientAiKey) {
                $alreadyAllowed=$id?(int)sql('SELECT allow_client_ai_key FROM phonehub_users WHERE id=?',[$id])->fetchColumn():0;
                if (!$alreadyAllowed) require_owner();
            }
            $aiDailyLimit=(int)($_POST['ai_daily_limit']??100);
            if ($aiDailyLimit<0 || $aiDailyLimit>5000) throw new RuntimeException('AI 每日请求额度必须为 0–5000');
            if ($allowClientAiKey && !$aiEnabled) throw new RuntimeException('关闭 AI 功能时不能单独开放客户端自带 Key');
            $group=(int)($_POST['group_id'] ?? 0);
            $enabled=isset($_POST['enabled']) ? 1 : 0;
            if ($limit<1 || $limit>100 || $mobile<0 || $mobile>1000) throw new RuntimeException('电脑限额为 1–100，手机限额为 0–1000');
            if ($group && !(int)sql('SELECT COUNT(*) FROM phonehub_groups WHERE id=?',[$group])->fetchColumn()) throw new RuntimeException('分组不存在');
            $entitlements=array_values(array_intersect(['douyin','xiaohongshu','mcp','skill','mcp-codex','mcp-harness'],(array)($_POST['entitlements'] ?? [])));
            if (array_intersect($entitlements,['mcp-codex','mcp-harness']) && !in_array('mcp',$entitlements,true))
                throw new RuntimeException('Codex、DeepSeek Harness MCP 必须同时授予 MCP 上级权限');
            $previousEntitlements=$id?(json_decode((string)sql('SELECT entitlements FROM phonehub_users WHERE id=?',[$id])->fetchColumn(),true)?:[]):[];
            if (array_diff(array_intersect(['mcp','skill','mcp-codex','mcp-harness'],$entitlements),$previousEntitlements)) require_owner();
            $until=input_to_utc(trim((string)($_POST['license_until'] ?? '')));
            $notes=trim((string)($_POST['notes'] ?? ''));
            if (utf8_length($notes)>500) throw new RuntimeException('备注不能超过 500 字');
            $pass=(string)($_POST['password'] ?? '');
            db()->beginTransaction();
            if ($id) {
                $old=sql('SELECT username,enabled,device_limit FROM phonehub_users WHERE id=? FOR UPDATE',[$id])->fetch();
                if (!$old) throw new RuntimeException('账号不存在');
                if ($pass!=='') {
                    $hash=password_hash_safe($pass);
                    sql('UPDATE phonehub_users SET username=?,password_hash=?,enabled=?,device_limit=?,license_until=?,entitlements=?,ai_enabled=?,allow_client_ai_key=?,ai_daily_limit=? WHERE id=?',
                        [$name,$hash,$enabled,$limit,$until,json_encode($entitlements),$aiEnabled,$allowClientAiKey,$aiDailyLimit,$id]);
                } else {
                    sql('UPDATE phonehub_users SET username=?,enabled=?,device_limit=?,license_until=?,entitlements=?,ai_enabled=?,allow_client_ai_key=?,ai_daily_limit=? WHERE id=?',
                        [$name,$enabled,$limit,$until,json_encode($entitlements),$aiEnabled,$allowClientAiKey,$aiDailyLimit,$id]);
                }
                if (!$enabled || $pass!=='' || $limit<(int)$old['device_limit']) sql('DELETE FROM phonehub_sessions WHERE user_id=?',[$id]);
            } else {
                $pass=random_password();
                $hash=password_hash_safe($pass);
                sql('INSERT INTO phonehub_users(username,password_hash,enabled,device_limit,license_until,entitlements,ai_enabled,allow_client_ai_key,ai_daily_limit) VALUES(?,?,?,?,?,?,?,?,?)',
                    [$name,$hash,$enabled,$limit,$until,json_encode($entitlements),$aiEnabled,$allowClientAiKey,$aiDailyLimit]);
                $id=(int)db()->lastInsertId();
            }
            sql('INSERT INTO phonehub_user_meta(user_id,group_id,mobile_limit,notes) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE group_id=VALUES(group_id),mobile_limit=VALUES(mobile_limit),notes=VALUES(notes)',
                [$id,$group?:null,$mobile,$notes]);
            audit('account_save',$name);
            db()->commit();
            json_response(array_merge(['ok'=>true,'message'=>'授权已保存','id'=>$id],$creating?['password'=>$pass,'username'=>$name]:[]));
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
        if ($action==='account_password') {
            if (!function_exists('account_reset_password'))
                throw new RuntimeException('客户管理模块缺失；请在系统更新中补齐 app/accounts.php');
            $result=account_reset_password((int)($_POST['id']??0));
            json_response(['ok'=>true,'message'=>'客户密码已重置，原电脑会话已撤销','username'=>$result['username'],'password'=>$result['password']]);
        }
        if (in_array($action,['signing_generate','signing_activate'],true)) {
            require_owner();
            if (!is_file(__DIR__.'/app/signing_admin.php'))
                throw new RuntimeException('签名管理模块缺失；请先在系统更新中补齐必要文件');
            require_once __DIR__.'/app/signing_admin.php';
            if ($action==='signing_generate')
                json_response(['ok'=>true]+signing_generate_and_publish(trim((string)($_POST['github_token']??''))));
            json_response(['ok'=>true]+signing_activate_trust());
        }
        if (in_array($action,['update_check','update_apply','update_diagnostics'],true)) {
            require_owner();
            require __DIR__.'/app/updater.php';
            if ($action==='update_check') json_response(['ok'=>true]+check_update());
            if ($action==='update_diagnostics') json_response(['ok'=>true]+update_diagnostics());
            $result=apply_update();
            audit('system_update',(string)($result['version'] ?? ''));
            json_response(['ok'=>true]+$result);
        }
        if (in_array($action,['release_publish','release_toggle','logs_purge'],true)) {
            require __DIR__.'/app/release_admin.php';
            release_admin_action($action);
        }
        if ($action==='ai_settings_save') {
            require __DIR__.'/app/ai.php';
            ai_admin_action($action);
        }
        require __DIR__.'/app/features.php';
        feature_action($action);
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
    try { require_admin(); } catch (Throwable $e) { $_SESSION=[];session_regenerate_id(true); }
}
if (!admin_id()) {
?>
<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>登录 · PhoneHub</title><link rel="stylesheet" href="assets/app.css?v=<?=rawurlencode(app_version())?>"><meta name="csrf" content="<?=h(csrf())?>"></head>
<body class="auth-body"><main class="auth-card">
<div class="brand"><span class="brand-mark">P</span><div><strong>PhoneHub</strong><small>License Console</small></div></div>
<h1>登录管理后台</h1><p class="muted">统一管理客户、授权、设备会话及系统更新。</p>
<form data-ajax="login"><input type="hidden" name="action" value="login"><div class="field"><label>管理员账号</label><input name="username" autocomplete="username" required autofocus></div><div class="field"><label>管理员密码</label><input type="password" name="password" autocomplete="current-password" required></div>
<button class="btn primary full">登录</button></form><p id="message" class="footnote"></p></main><script src="assets/app.js?v=<?=rawurlencode(app_version())?>" defer></script></body></html>
<?php exit; }
$view=(string)($_GET['view'] ?? 'dashboard');
if (in_array($view,['mobiles','sessions'],true)) {header('Location: index.php?view=devices',true,302);exit;}
if (!in_array($view,['dashboard','accounts','groups','group_bulk','devices','packages','client_logs','releases','ai','update','gateway','admins','audit','cloud_features'],true)) $view='dashboard';
$adminRole=admin_role();
if (in_array($view,['admins','gateway','update','releases','ai','cloud_features'],true) && $adminRole!=='owner') { http_response_code(403); exit('该页面仅主管理员可以访问'); }
$groups=in_array($view,['dashboard','accounts','groups','group_bulk'],true) ? sql('SELECT id,name,(SELECT COUNT(*) FROM phonehub_user_meta m WHERE m.group_id=g.id) AS users FROM phonehub_groups g ORDER BY id DESC')->fetchAll() : [];
$accounts=($view==='accounts'||$view==='dashboard') ? sql("SELECT u.id,u.username,u.enabled,u.device_limit,u.license_until,u.entitlements,u.created_at,u.ai_enabled,u.allow_client_ai_key,u.ai_daily_limit,m.group_id,COALESCE(m.mobile_limit,0) AS mobile_limit,COALESCE(m.notes,'') AS notes,g.name AS group_name,(SELECT COUNT(DISTINCT s.device_id) FROM phonehub_sessions s WHERE s.user_id=u.id AND s.expires_at>UTC_TIMESTAMP()) AS active_devices FROM phonehub_users u LEFT JOIN phonehub_user_meta m ON m.user_id=u.id LEFT JOIN phonehub_groups g ON g.id=m.group_id ORDER BY u.id DESC")->fetchAll() : [];
$nav=[
'dashboard'=>['概览','▦'],
'accounts'=>['客户授权','♙'],
'groups'=>['客户分组','◫'],
'group_bulk'=>['分组批量配置','≡'],
'devices'=>['设备管理','▣'],
'packages'=>['操作包','⬡'],
'client_logs'=>['客户端日志','☷'],
'releases'=>['核心更新发布','⇧'],
'ai'=>['AI 接口管理','✧'],
'cloud_features'=>['客户端能力控制','⚙'],
'update'=>['系统更新','⟳'],
'gateway'=>['客户端接口接管','↪'],
'admins'=>['管理员管理','♧'],
'audit'=>['操作记录','☷']
];
?>
<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf" content="<?=h(csrf())?>"><title>PhoneHub 管理控制台</title><link rel="stylesheet" href="assets/app.css?v=<?=rawurlencode(app_version())?>"></head>
<body><div class="app"><aside class="sidebar"><div class="brand"><span class="brand-mark">P</span><div><strong>PhoneHub</strong><small>授权管理中心</small></div></div>
<nav><?php foreach ($nav as $route=>$item): if ($adminRole!=='owner' && in_array($route,['update','gateway','admins','releases','ai','cloud_features'],true)) continue; ?><a class="<?= $view===$route?'active':'' ?>" href="?view=<?=h($route)?>"><span class="nav-icon"><?=h($item[1])?></span><?=h($item[0])?></a><?php endforeach ?></nav>
<div class="sidebar-footer"><span class="status-dot"></span> 运行中 <small>v<?=h(app_version())?></small></div></aside>
<div class="main"><header class="topbar"><div><span class="crumb">PhoneHub /</span> <?=h($nav[$view][0])?></div><div class="top-right"><span class="avatar"><?=h(substr((string)($_SESSION['admin_user']??'A'),0,1))?></span><?=h($_SESSION['admin_user']??'管理员')?><button class="text-button" data-action="logout">退出</button></div></header>
<main id="content" class="content">
<?php if ($view==='dashboard'):
    $total=count($accounts);$enabled=count(array_filter($accounts,fn($u)=>(int)$u['enabled']===1));$devices=array_sum(array_map(fn($u)=>(int)$u['active_devices'],$accounts));
?>
<div class="page-title"><div><h1>运营概览</h1><p>客户授权与电脑会话状态一览</p></div><a class="btn primary" href="?view=accounts">+ 新增授权</a></div>
<div class="stats"><div class="stat"><span>客户总数</span><strong><?=$total?></strong><small>全部授权账号</small></div><div class="stat"><span>正常授权</span><strong><?=$enabled?></strong><small>账号启用中（不含到期校验）</small></div><div class="stat"><span>电脑名额占用</span><strong><?=$devices?></strong><small>未过期的设备会话</small></div><div class="stat"><span>客户分组</span><strong><?=count($groups)?></strong><small>支持自主分组管理</small></div></div>
<div class="card"><div class="card-head"><h2>最近客户</h2><a href="?view=accounts">查看全部</a></div><div class="table-scroll"><table><thead><tr><th>客户账号</th><th>分组</th><th>电脑名额</th><th>授权期限</th><th>状态</th></tr></thead><tbody><?php foreach (array_slice($accounts,0,8) as $a): ?><tr><td><b><?=h($a['username'])?></b></td><td><?=h($a['group_name']??'未分组')?></td><td><?= (int)$a['active_devices']?> / <?= (int)$a['device_limit']?></td><td><?=h(utc_to_cn($a['license_until']))?></td><td><span class="pill <?= (int)$a['enabled']?'ok':'off'?>"><?= (int)$a['enabled']?'启用':'停用'?></span></td></tr><?php endforeach ?></tbody></table></div></div>
<?php elseif ($view==='accounts'): ?>
<div class="page-title"><div><h1>客户授权</h1><p>新增客户自动生成随机密码；安卓手机额度需要接管客户端接口后才能强制执行</p></div><button class="btn primary" data-action="new-account">+ 创建客户</button></div>
<div class="card editor" id="account-editor" hidden><div class="card-head"><h2 id="editor-title">创建客户</h2><button class="text-button" data-action="close-editor">关闭</button></div>
<form data-ajax="account_save"><input name="action" type="hidden" value="account_save"><input name="id" type="hidden" value="0">
<div class="form-grid"><div class="field"><label>客户账号</label><input name="username" required minlength="3" maxlength="64"></div>
<div class="field"><label>客户密码</label><input name="password" type="password" autocomplete="new-password" placeholder="新建自动生成；编辑留空保持不变" readonly tabindex="-1"><span class="footnote">需要修改密码时，请在客户列表点击“重置密码”，随机生成后只显示一次。</span></div>
<div class="field"><label>客户分组</label><select name="group_id"><option value="0">未分组</option><?php foreach($groups as $g): ?><option value="<?=(int)$g['id']?>"><?=h($g['name'])?></option><?php endforeach ?></select></div>
<div class="field"><label>授权截止时间（北京时间，留空永久）</label><input name="license_until" type="datetime-local" step="1"></div>
<div class="field"><label>电脑授权名额（1–100）</label><input name="device_limit" type="number" min="1" max="100" value="3"></div>
<div class="field"><label>安卓手机名额（0 表示禁止绑定）</label><input name="mobile_limit" type="number" min="0" max="1000" value="1"></div>
<div class="field span2"><label>平台与扩展权限</label><div class="check-row"><label><input type="checkbox" name="entitlements[]" value="douyin" checked> 抖音</label><label><input type="checkbox" name="entitlements[]" value="xiaohongshu"> 小红书</label><label><input type="checkbox" name="entitlements[]" value="mcp"> MCP</label><label><input type="checkbox" name="entitlements[]" value="mcp-codex"> Codex MCP</label><label><input type="checkbox" name="entitlements[]" value="mcp-harness"> DeepSeek Harness MCP</label><label><input type="checkbox" name="entitlements[]" value="skill"> Skill</label></div><span class="footnote">MCP/Skill 还需在「客户端能力控制」打开全局开关；新客户默认不授权。</span></div>
<div class="field"><label>账号状态</label><label class="check-row"><input type="checkbox" name="enabled" checked> 启用账号</label></div>
<div class="field"><label>AI 功能</label><label class="check-row"><input type="checkbox" name="ai_enabled" checked> 允许使用 AI</label></div>
<div class="field"><label>AI 每日请求额度（0–5000）</label><input name="ai_daily_limit" type="number" min="0" max="5000" value="100"></div>
<div class="field span2"><label>客户端自带 API Key</label><label class="check-row"><input type="checkbox" name="allow_client_ai_key"> 允许该客户自带 Key（还需主管理员开启全局开关）</label></div>
<div class="field span2"><label>内部备注</label><input name="notes" maxlength="500" placeholder="可填写客户联系方式、购买产品等"></div>
</div><div class="editor-actions"><button class="btn primary">保存授权</button></div></form></div>
<div class="card"><div class="card-head"><h2>全部客户</h2><span class="count"><?=count($accounts)?> 个账号</span></div>
<div class="table-scroll"><table><thead><tr><th>客户账号</th><th>分组</th><th>电脑名额</th><th>手机额度</th><th>授权截止（北京时间）</th><th>平台权限</th><th>状态</th><th>操作</th></tr></thead><tbody>
<?php foreach($accounts as $a): $payload=['id'=>(int)$a['id'],'username'=>$a['username'],'group_id'=>(int)$a['group_id'],'device_limit'=>(int)$a['device_limit'],'mobile_limit'=>(int)$a['mobile_limit'],'license_until'=>utc_to_input($a['license_until']),'entitlements'=>json_decode((string)$a['entitlements'],true)?:[],'notes'=>$a['notes'],'enabled'=>(bool)$a['enabled'],'ai_enabled'=>(bool)$a['ai_enabled'],'allow_client_ai_key'=>(bool)$a['allow_client_ai_key'],'ai_daily_limit'=>(int)$a['ai_daily_limit']]; ?>
<tr><td><b><?=h($a['username'])?></b></td><td><?=h($a['group_name']??'未分组')?></td><td><?= (int)$a['active_devices']?> / <?= (int)$a['device_limit']?></td><td><?= (int)$a['mobile_limit']?></td><td><?=h(utc_to_cn($a['license_until']))?></td><td><?=h(implode('、',array_map(static fn($x)=>['douyin'=>'抖音','xiaohongshu'=>'小红书','mcp'=>'MCP','skill'=>'Skill','mcp-codex'=>'Codex MCP','mcp-harness'=>'DeepSeek Harness MCP'][$x]??$x,json_decode((string)$a['entitlements'],true)?:[])))?></td>
<td><span class="pill <?= (int)$a['enabled']?'ok':'off'?>"><?= (int)$a['enabled']?'启用':'停用'?></span></td><td class="actions">
<button class="small-link" data-edit="<?=h(json_encode($payload,JSON_UNESCAPED_UNICODE|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP|JSON_HEX_TAG))?>">编辑</button>
<button class="small-link" data-action="reset-account-password" data-id="<?=(int)$a['id']?>">重置密码</button>
<button class="small-link" data-action="revoke-account" data-id="<?=(int)$a['id']?>">踢下线</button></td></tr><?php endforeach ?></tbody></table></div></div>
<?php elseif($view==='groups'): ?>
<div class="page-title"><div><h1>客户分组</h1><p>将代理商、企业或购买渠道分组管理</p></div><a class="btn primary" href="?view=group_bulk">统一修改分组授权</a></div><div class="card"><div class="card-head"><h2>新建分组</h2></div><form class="inline-form" data-ajax="group_create"><input type="hidden" name="action" value="group_create"><input name="name" placeholder="例如：代理商A / 企业客户" maxlength="100" required><button class="btn primary">创建分组</button></form></div>
<div class="card"><div class="card-head"><h2>已创建分组</h2></div><div class="table-scroll"><table><thead><tr><th>分组名称</th><th>客户数</th><th>操作</th></tr></thead><tbody><?php foreach($groups as $g): ?><tr><td><b><?=h($g['name'])?></b></td><td><?=(int)$g['users']?></td><td><button class="small-link" data-action="delete-group" data-id="<?=(int)$g['id']?>">删除</button></td></tr><?php endforeach ?></tbody></table></div></div>
<?php elseif($view==='packages'): $packages=sql('SELECT package_id,MAX(version) AS version,COUNT(*) AS versions FROM phonehub_packages GROUP BY package_id ORDER BY package_id')->fetchAll(); ?>
<div class="page-title"><div><h1>平台操作包</h1><p>兼容现有 PhoneHub 加密包协议；本版本仅展示，不处理签名私钥</p></div></div>
<div class="card"><div class="table-scroll"><table><thead><tr><th>平台包</th><th>最高版本</th><th>历史版本数量</th></tr></thead><tbody><?php foreach($packages as $p): ?><tr><td><?=h($p['package_id'])?></td><td><?=h($p['version'])?></td><td><?=h($p['versions'])?></td></tr><?php endforeach ?></tbody></table></div></div>
<?php elseif($view==='update'): ?>
<div class="page-title"><div><h1>系统更新</h1><p>从国内镜像获取 GitHub 仓库最新代码，完成备份后在线安装</p></div></div>
<div class="card update-card"><div class="update-icon">⟳</div><h2>当前版本 v<?=h(app_version())?></h2><p class="muted">更新源：<code>https://git.wksite.cn/popowk/data</code></p><p class="muted">仅更新管理程序文件，自动跳过 storage 内的数据库配置和运行数据。</p>
<div class="update-actions"><button class="btn" data-action="check-update">检查更新</button><button class="btn" data-action="diagnose-update">运行环境自检</button><button class="btn primary" id="apply-update" data-action="apply-update" disabled>下载并安装更新</button></div><p id="update-status" class="update-status">正在等待检查…</p><div id="update-diagnostics" class="update-status" role="status" aria-live="polite"></div></div>
<?php
$signingModuleReady=is_file(__DIR__.'/app/signing_admin.php');
if ($signingModuleReady) {
    require_once __DIR__.'/app/signing_admin.php';
    $signing=signing_status();
} else {
    $signing=['state'=>'unavailable'];
}
?>
<?php if (!$signingModuleReady): ?>
<div class="card"><h2>更新模块尚未补齐</h2>
<p class="muted">当前程序缺少 app/signing_admin.php。此前版本的更新清单可能未包含新增模块。请先在上方点击「检查更新」，再执行「补齐缺失模块」。该操作不会清空客户数据或 storage。</p>
</div>
<?php else: ?>
<div class="card">
 <div class="card-head"><h2>Ed25519 签名密钥管理</h2><span class="pill <?=$signing['state']==='active'?'ok':'off'?>"><?=$signing['state']==='active'?'强制验签已启用':($signing['state']==='pending'?'等待发布签名':'尚未初始化')?></span></div>
 <p class="muted">主管理员在这里直接初始化签名密钥，服务器生成 Ed25519 私钥并加密传入 GitHub Actions Secret，随后擦除本次服务器内存中的私钥；只保留固定公钥。使用 GitHub 一次性 Token，不保存 Token、私钥或签名明文在数据库。</p>
 <?php if(isset($signing['fingerprint'])): ?><p class="muted">公钥 SHA-256 指纹：<code><?=h($signing['fingerprint'])?></code></p><?php endif ?>
 <?php if($signing['state']==='unconfigured'): ?>
 <form data-ajax="signing_generate"><input type="hidden" name="action" value="signing_generate">
  <div class="field"><label>GitHub 临时访问 Token（须有 popowk/data 仓库 Actions Secrets 写入权限）</label><input type="password" name="github_token" autocomplete="off" required placeholder="只用于本次安全配置，不保存"></div>
  <p class="footnote">初始化后由 GitHub Actions 自动签名。镜像签名尚未发布时不会启用固定公钥，避免锁死现有更新通道。</p>
  <button class="btn primary" type="submit">生成密钥并自动配置签名</button>
 </form>
 <?php elseif($signing['state']==='pending'): ?>
 <div class="update-actions"><button class="btn primary" data-action="signing-activate">验证镜像并启用签名</button></div>
 <p class="muted">签名发布或镜像同步尚未完成时，验证会安全失败，可稍后重新点击；不会覆盖已有公钥。</p>
 <?php else: ?>
 <p class="muted">今后每次后台安装更新都必须先通过独立 Ed25519 签名和完整文件摘要校验，不允许重新生成新密钥覆盖当前信任链。</p>
 <?php endif ?>
 </div>
<?php endif ?>
<div class="card"><h2>更新说明</h2><p class="muted">安装前自动备份原文件。下载、解压、写入或校验失败会报错；写入阶段失败将尝试自动回滚。更新过程不删除客户、会话和数据库。镜像站需要支持 GitHub 源码 ZIP 下载接口。</p></div>
<?php elseif($view==='audit'): $before=max(0,(int)($_GET['before']??0)); $auditSql="SELECT a.id,a.action,a.target,a.ip,a.created_at,m.username FROM phonehub_admin_audit a LEFT JOIN phonehub_admins m ON m.id=a.admin_id ORDER BY a.id DESC LIMIT 51"; $audits=$before>0?sql("SELECT a.id,a.action,a.target,a.ip,a.created_at,m.username FROM phonehub_admin_audit a LEFT JOIN phonehub_admins m ON m.id=a.admin_id WHERE a.id < ? ORDER BY a.id DESC LIMIT 51",[$before])->fetchAll():sql($auditSql)->fetchAll(); $hasOlder=count($audits)>50; if($hasOlder)array_pop($audits); $nextBefore=$audits?(int)$audits[count($audits)-1]['id']:0; ?>
<div class="page-title"><div><h1>管理员操作记录</h1><p>按时间倒序展示，每页 50 条；可继续加载更早记录</p></div><?php if($before>0): ?><a class="btn" href="?view=audit">返回最新记录</a><?php endif ?></div><div class="card"><div class="table-scroll"><table><thead><tr><th>时间（北京时间）</th><th>管理员</th><th>操作</th><th>目标</th><th>IP</th></tr></thead><tbody><?php foreach($audits as $a): ?><tr><td><?=h(utc_to_cn($a['created_at']))?></td><td><?=h($a['username'])?></td><td><?=h($a['action'])?></td><td><?=h($a['target'])?></td><td><?=h($a['ip'])?></td></tr><?php endforeach ?></tbody></table></div><?php if($hasOlder && $nextBefore>0): ?><div class="editor-actions"><a class="btn" href="?view=audit&amp;before=<?=$nextBefore?>">更早记录</a></div><?php endif ?></div>
<?php elseif ($view==='releases'): require __DIR__.'/app/release_admin.php'; release_admin_view(); ?>
<?php elseif ($view==='ai'): require __DIR__.'/app/ai.php'; try { ai_admin_view(); } catch (Throwable $e) {
    $errorRef=bin2hex(random_bytes(4));
    error_log('PhoneHub AI admin page ['.$errorRef.']: '.get_class($e).' '.$e->getMessage());
    http_response_code(500);
    ?><div class="card"><h2>AI 管理页面暂时无法加载</h2><p class="muted">服务器已记录错误，请检查 PHP 错误日志。错误编号：<code><?=h($errorRef)?></code></p><a class="btn" href="?view=ai">重新加载</a></div><?php
} ?>
<?php elseif (in_array($view,['admins','group_bulk','devices','gateway','client_logs','cloud_features'],true)): require __DIR__.'/app/features.php'; feature_view($view); ?>
<?php endif ?>
</main></div></div><div class="toast" id="toast" role="status" aria-live="polite"></div><script src="assets/app.js?v=<?=rawurlencode(app_version())?>" defer></script></body></html>
