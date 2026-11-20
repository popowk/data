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
        phonehub_require_action($action);
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
            // Explicit plan reassignment for existing customers; omitted/blank
            // opening_plan keeps the old label and all manually edited quotas.
            $openingPlan=null;
            $rawPlan=$_POST['opening_plan']??'';
            if (!is_string($rawPlan) || strlen($rawPlan)>24 ||
                ($rawPlan!=='' && !preg_match('/^[A-Za-z0-9_-]{1,24}$/D',$rawPlan)))
                throw new RuntimeException('客户套餐参数格式不正确');
            $requestedPlan=$rawPlan;
            $planChanged=false;
            if ($creating) {
                if ($requestedPlan==='') throw new RuntimeException('创建客户时请选择开户套餐');
                if ($requestedPlan==='custom') $openingPlan='custom';
                else {
                    $plans=phonehub_opening_plans();
                    if (!isset($plans[$requestedPlan])) throw new RuntimeException('开户套餐不存在或已停用');
                    $openingPlan=$requestedPlan;
                    $limit=(int)$plans[$requestedPlan]['device_limit'];
                    $mobile=(int)$plans[$requestedPlan]['mobile_limit'];
                }
            }
            $aiEnabled=isset($_POST['ai_enabled'])?1:0;
            $allowClientAiKey=isset($_POST['allow_client_ai_key'])?1:0;
            $isGlobalOperator=in_array(admin_role(),['owner','global'],true);
            $alreadyAllowed=$id?(int)sql('SELECT allow_client_ai_key FROM phonehub_users WHERE id=?',[$id])->fetchColumn():0;
            if ($allowClientAiKey && !$alreadyAllowed) require_global_admin();
            // A staff edit must not revoke an existing global-only BYOK grant.
            if (!$isGlobalOperator) $allowClientAiKey=$alreadyAllowed;
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
            $protectedEntitlements=['mcp','skill','mcp-codex','mcp-harness'];
            if (array_diff(array_intersect($protectedEntitlements,$entitlements),$previousEntitlements))
                require_global_admin();
            if (!$isGlobalOperator) {
                // A staff edit must preserve previously granted advanced scopes.
                $entitlements=array_values(array_unique(array_merge(
                    $entitlements,array_values(array_intersect($protectedEntitlements,$previousEntitlements))
                )));
            }
            $until=input_to_utc(trim((string)($_POST['license_until'] ?? '')));
            $notes=trim((string)($_POST['notes'] ?? ''));
            if (utf8_length($notes)>500) throw new RuntimeException('备注不能超过 500 字');
            // A password may be selected at creation time only. Editing an
            // existing customer never changes its password; reset remains
            // exclusively available through account_password.
            $submittedPassword=$_POST['password']??'';
            if (!is_string($submittedPassword))
                throw new RuntimeException('客户密码格式不正确');
            if (!$creating && $submittedPassword!=='')
                throw new PhoneHubPermissionException('已有客户密码请使用独立的密码重置功能修改');
            // Empty on creation retains existing secure random generation.
            $newPassword=$creating
                ? ($submittedPassword!==''?$submittedPassword:random_password())
                : '';
            $newPasswordHash=$creating?password_hash_safe($newPassword):'';
            db()->beginTransaction();
            if ($id) {
                $old=sql('SELECT username,enabled,device_limit FROM phonehub_users WHERE id=? FOR UPDATE',[$id])->fetch();
                if (!$old) throw new RuntimeException('账号不存在');
                $oldMeta=sql('SELECT opening_plan_code FROM phonehub_user_meta WHERE user_id=? FOR UPDATE',[$id])->fetch();
                $previousPlan=$oldMeta?($oldMeta['opening_plan_code']??null):null;
                if ($requestedPlan!=='' && $requestedPlan!==$previousPlan) {
                    if ($requestedPlan!=='custom') {
                        // Lock the currently enabled preset; never trust a
                        // browser-supplied quota or a disabled plan code.
                        $preset=sql('SELECT device_limit,mobile_limit FROM phonehub_plan_templates WHERE plan_code=? AND enabled=1 FOR UPDATE',[$requestedPlan])->fetch();
                        if (!$preset) throw new RuntimeException('目标套餐不存在或已停用，请刷新后重新选择');
                        $limit=(int)$preset['device_limit'];
                        $mobile=(int)$preset['mobile_limit'];
                    }
                    $openingPlan=$requestedPlan;
                    $planChanged=true;
                }
                if ($limit<1 || $limit>100 || $mobile<0 || $mobile>1000)
                    throw new RuntimeException('套餐额度无效，请联系管理员检查套餐配置');
                sql('UPDATE phonehub_users SET username=?,enabled=?,device_limit=?,license_until=?,entitlements=?,ai_enabled=?,allow_client_ai_key=?,ai_daily_limit=? WHERE id=?',
                    [$name,$enabled,$limit,$until,json_encode($entitlements),$aiEnabled,$allowClientAiKey,$aiDailyLimit,$id]);
                if (!$enabled || $limit<(int)$old['device_limit'])
                    sql('DELETE FROM phonehub_sessions WHERE user_id=?',[$id]);
            } else {
                sql('INSERT INTO phonehub_users(username,password_hash,enabled,device_limit,license_until,entitlements,ai_enabled,allow_client_ai_key,ai_daily_limit) VALUES(?,?,?,?,?,?,?,?,?)',
                    [$name,$newPasswordHash,$enabled,$limit,$until,json_encode($entitlements),$aiEnabled,$allowClientAiKey,$aiDailyLimit]);
                $id=(int)db()->lastInsertId();
            }
            sql('INSERT INTO phonehub_user_meta(user_id,group_id,mobile_limit,notes,opening_plan_code) VALUES(?,?,?,?,?) ON DUPLICATE KEY UPDATE group_id=VALUES(group_id),mobile_limit=VALUES(mobile_limit),notes=VALUES(notes),opening_plan_code=COALESCE(VALUES(opening_plan_code),opening_plan_code)',
                [$id,$group?:null,$mobile,$notes,$openingPlan]);
            audit('account_save',$name);
            if ($planChanged)
                audit('account_plan_change',$name.' '.($previousPlan??'legacy').' -> '.$openingPlan);
            db()->commit();
            json_response(array_merge(['ok'=>true,'message'=>'授权已保存','id'=>$id],$creating?['password'=>$newPassword,'username'=>$name]:[]));
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
            if ($id<1) throw new RuntimeException('电脑会话无效');
            $pdo=db();
            $pdo->beginTransaction();
            try {
                $candidate=sql('SELECT user_id FROM phonehub_sessions WHERE id=?',[$id])->fetch();
                if (!$candidate) throw new RuntimeException('电脑会话已过期或撤销，请刷新页面');
                // Preserve login lock ordering (customer row -> session rows).
                sql('SELECT id FROM phonehub_users WHERE id=? FOR UPDATE',[$candidate['user_id']])->fetch();
                $target=sql('SELECT user_id,device_id FROM phonehub_sessions WHERE id=? FOR UPDATE',[$id])->fetch();
                if (!$target || (int)$target['user_id']!==(int)$candidate['user_id'])
                    throw new RuntimeException('电脑会话状态已变化，请刷新页面');
                $revoked=sql('DELETE FROM phonehub_sessions WHERE user_id=? AND device_id=?',
                    [$target['user_id'],$target['device_id']])->rowCount();
                audit('computer_sessions_revoke','user='.$target['user_id'].' sessions='.$revoked);
                $pdo->commit();
            } catch(Throwable $e) {
                if ($pdo->inTransaction()) $pdo->rollBack();
                throw $e;
            }
            json_response(['ok'=>true,'revoked_sessions'=>$revoked,
                'message'=>'已撤销该电脑全部 '.$revoked.' 个有效会话']);
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
        if (in_array($action,['plan_save','plan_toggle'],true)) {
            require_once __DIR__.'/app/features.php';
            plan_admin_action($action);
        }
        if ($action==='backup_key_generate') {
            require_owner();
            require_once __DIR__.'/app/features.php';
            backup_admin_download_once();
        }
        if (in_array($action,['update_check','update_apply','update_diagnostics'],true)) {
            if ($action==='update_apply') require_owner();
            else require_global_admin();
            require __DIR__.'/app/updater.php';
            if ($action==='update_check') json_response(['ok'=>true]+check_update());
            if ($action==='update_diagnostics') json_response(['ok'=>true]+update_diagnostics());
            $result=apply_update();
            audit('system_update',(string)($result['version'] ?? ''));
            json_response(['ok'=>true]+$result);
        }
        if (str_starts_with($action,'automation_')) {
            require __DIR__.'/app/automation.php';
            automation_admin_action($action);
        }
        if (in_array($action,['release_publish','release_toggle','package_publish','package_toggle','scrcpy_url_save','main_program_url_save','logs_purge'],true)) {
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
        json_response(['ok'=>false,'error'=>$message],$e instanceof PhoneHubPermissionException ? 403 : 400);
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
$adminRole=admin_role();
$view=(string)($_GET['view'] ?? ($adminRole==='admin'?'accounts':'dashboard'));
if (in_array($view,['mobiles','sessions'],true)) {header('Location: index.php?view=devices',true,302);exit;}
if ($view==='gateway') {http_response_code(404);exit('旧客户端接口接管功能已移除；请使用新版授权 API');}
if (!in_array($view,['dashboard','accounts','groups','group_bulk','devices','packages','plans','backup_keys','client_logs','releases','ai','update','admins','audit','cloud_features','performance'],true))
    $view=$adminRole==='admin'?'accounts':'dashboard';
// Keep old saved links working while removing duplicate sidebar entries.
if ($view==='ai') { header('Location: index.php?view=cloud_features#ai-management',true,302);exit; }
if ($view==='packages' && in_array($adminRole,['owner','global'],true)) { header('Location: index.php?view=releases#legacy-operation-packages',true,302);exit; }
if (!phonehub_role_can_view($adminRole,$view)) { http_response_code(403); exit('当前管理员无权访问此页面'); }
// Keep only internal administrative bookmarks: no legacy client API endpoint.
if ($view==='group_bulk') {header('Location: index.php?view=groups#group-bulk',true,302);exit;}
if ($view==='backup_keys') {header('Location: index.php?view=update#maintenance-backup',true,302);exit;}
$groups=in_array($view,['dashboard','accounts','groups','group_bulk'],true) ? sql('SELECT id,name,(SELECT COUNT(*) FROM phonehub_user_meta m WHERE m.group_id=g.id) AS users FROM phonehub_groups g ORDER BY id DESC')->fetchAll() : [];
$accounts=[];
$accountTotal=0;$accountPage=1;$accountPages=1;
$accountFilters=['q'=>'','group'=>'all','status'=>'all','expiry'=>'all','plan'=>'all','page'=>1];
$accountSelect="SELECT u.id,u.username,u.enabled,u.device_limit,u.license_until,u.entitlements,u.created_at,
    u.ai_enabled,u.allow_client_ai_key,u.ai_daily_limit,m.group_id,COALESCE(m.mobile_limit,0) AS mobile_limit,
    m.opening_plan_code,COALESCE(m.notes,'') AS notes,g.name AS group_name,
    (SELECT COUNT(DISTINCT s.device_id) FROM phonehub_sessions s
      WHERE s.user_id=u.id AND s.expires_at>UTC_TIMESTAMP()) AS active_devices
    FROM phonehub_users u
    LEFT JOIN phonehub_user_meta m ON m.user_id=u.id
    LEFT JOIN phonehub_groups g ON g.id=m.group_id";
if ($view==='dashboard') {
    $dashboardSummary=sql('SELECT COUNT(*) AS total,SUM(CASE WHEN enabled=1 THEN 1 ELSE 0 END) AS enabled FROM phonehub_users')->fetch();
    $total=(int)($dashboardSummary['total']??0);
    $enabled=(int)($dashboardSummary['enabled']??0);
    $devices=(int)sql('SELECT COUNT(*) FROM (
      SELECT user_id,device_id FROM phonehub_sessions WHERE expires_at>UTC_TIMESTAMP()
      GROUP BY user_id,device_id
    ) live')->fetchColumn();
    $accounts=sql($accountSelect.' ORDER BY u.id DESC LIMIT 8')->fetchAll();
}
if ($view==='accounts') {
    $accountFilters=phonehub_account_filters($_GET);
    $where=$accountFilters['where'];$params=$accountFilters['params'];
    $accountTotal=(int)sql('SELECT COUNT(*) FROM phonehub_users u
      LEFT JOIN phonehub_user_meta m ON m.user_id=u.id'.$where,$params)->fetchColumn();
    $accountPages=max(1,(int)ceil($accountTotal/30));
    $accountPage=min($accountFilters['page'],$accountPages);
    $offset=($accountPage-1)*30;
    $accounts=sql($accountSelect.$where.' ORDER BY u.id DESC LIMIT 30 OFFSET '.$offset,$params)->fetchAll();
}
$nav=[
'dashboard'=>['概览','▦'],
'accounts'=>['客户授权','♙'],
'groups'=>['客户分组与批量配置','◫'],
'devices'=>['设备管理','▣'],
'plans'=>['套餐管理','▤'],
'client_logs'=>['客户端日志','☷'],
'performance'=>['接口性能监控','▤'],
'releases'=>['版本发布与操作包','⇧'],
'cloud_features'=>['客户端能力与 AI','⚙'],
'update'=>['系统维护','⟳'],
'admins'=>['管理员管理','♧'],
'audit'=>['操作记录','☷']
];
?>
<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf" content="<?=h(csrf())?>"><title>PhoneHub 管理控制台</title><link rel="stylesheet" href="assets/app.css?v=<?=rawurlencode(app_version())?>"></head>
<body><div class="app"><aside class="sidebar"><div class="brand"><span class="brand-mark">P</span><div><strong>PhoneHub</strong><small>授权管理中心</small></div></div>
<nav><?php foreach ($nav as $route=>$item): if (!phonehub_role_can_view($adminRole,$route)) continue; ?><a class="<?= $view===$route?'active':'' ?>" href="?view=<?=h($route)?>"><span class="nav-icon"><?=h($item[1])?></span><?=h($item[0])?></a><?php endforeach ?></nav>
<div class="sidebar-footer"><span class="status-dot"></span> 运行中 <small><?=h(phonehub_role_label($adminRole))?> · v<?=h(app_version())?></small></div></aside>
<div class="main"><header class="topbar"><div><span class="crumb">PhoneHub /</span> <?=h($nav[$view][0]??($view==='packages'?'历史操作包':'管理页面'))?></div><div class="top-right"><span class="avatar"><?=h(substr((string)($_SESSION['admin_user']??'A'),0,1))?></span><?=h($_SESSION['admin_user']??'管理员')?><button class="text-button" data-action="logout">退出</button></div></header>
<main id="content" class="content">
<?php if ($view==='dashboard'): ?>
<div class="page-title"><div><h1>运营概览</h1><p>客户授权与电脑会话状态一览</p></div><a class="btn primary" href="?view=accounts"><?=$adminRole==='viewer'?'查看客户':'+ 新增授权'?></a></div>
<div class="stats"><div class="stat"><span>客户总数</span><strong><?=$total?></strong><small>全部授权账号</small></div><div class="stat"><span>正常授权</span><strong><?=$enabled?></strong><small>账号启用中（不含到期校验）</small></div><div class="stat"><span>电脑名额占用</span><strong><?=$devices?></strong><small>未过期的设备会话</small></div><div class="stat"><span>客户分组</span><strong><?=count($groups)?></strong><small>支持自主分组管理</small></div></div>
<div class="card"><div class="card-head"><h2>最近客户</h2><a href="?view=accounts">查看全部</a></div><div class="table-scroll"><table><thead><tr><th>客户账号</th><th>分组</th><th>电脑名额</th><th>授权期限</th><th>状态</th></tr></thead><tbody><?php foreach (array_slice($accounts,0,8) as $a): ?><tr><td><b><?=h($a['username'])?></b></td><td><?=h($a['group_name']??'未分组')?></td><td><?= (int)$a['active_devices']?> / <?= (int)$a['device_limit']?></td><td><?=h(utc_to_cn($a['license_until']))?></td><td><span class="pill <?= (int)$a['enabled']?'ok':'off'?>"><?= (int)$a['enabled']?'启用':'停用'?></span></td></tr><?php endforeach ?></tbody></table></div></div>
<?php elseif ($view==='accounts'): ?>
<div class="page-title"><div><h1>客户授权</h1><p>新建客户可设置密码，留空则生成安全随机密码；已有客户只能通过独立重置功能改密</p></div><?php if(phonehub_role_can_action($adminRole,'account_save')): ?><button class="btn primary" data-action="new-account">+ 创建客户</button><?php else: ?><span class="muted">只读查看，不允许修改授权</span><?php endif ?></div>
<?php if(phonehub_role_can_action($adminRole,'account_save')): ?>
<div class="card editor" id="account-editor" hidden><div class="card-head"><h2 id="editor-title">创建客户</h2><button class="text-button" data-action="close-editor">关闭</button></div>
<form data-ajax="account_save"><input name="action" type="hidden" value="account_save"><input name="id" type="hidden" value="0">
<div class="form-grid">
<div class="field span2" id="opening-plan-field"><label for="opening-plan">客户套餐（创建后可修改）</label><select id="opening-plan" name="opening_plan" required><option value="">请选择客户套餐</option><?php foreach(phonehub_opening_plans(false) as $code=>$plan): ?><option value="<?=h($code)?>" data-pc="<?=(int)$plan['device_limit']?>" data-mobile="<?=(int)$plan['mobile_limit']?>" data-enabled="<?=(int)$plan['enabled']?>" <?=$plan['enabled']?'':'disabled'?>><?=h($plan['label'])?><?=$plan['enabled']?'':'（已停用）'?> · <?=(int)$plan['device_limit']?> 台电脑 / <?=(int)$plan['mobile_limit']?> 台手机</option><?php endforeach ?><option value="custom">自定义授权额度</option></select><span class="footnote">切换套餐会按新套餐设置电脑和手机额度；原套餐未变时保留当前额度，也可单独调整。套餐不影响其他平台、AI 权限、到期时间或费用。</span></div>
<div class="field"><label>客户账号</label><input name="username" required minlength="3" maxlength="64"></div>
<div class="field" id="customer-create-password-field"><label for="customer-create-password">初始密码（仅创建客户时）</label>
<input id="customer-create-password" name="password" type="password" autocomplete="new-password"
  minlength="12" maxlength="128" placeholder="留空自动生成安全密码，或输入 12–128 字节密码">
<span class="footnote">可自行指定初始密码；留空则自动生成。已有客户修改密码请在客户列表使用“重置密码”。密码不会显示在编辑界面。</span></div>
<div class="field"><label>客户分组</label><select name="group_id"><option value="0">未分组</option><?php foreach($groups as $g): ?><option value="<?=(int)$g['id']?>"><?=h($g['name'])?></option><?php endforeach ?></select></div>
<div class="field"><label>授权截止时间（北京时间，留空永久）</label><input name="license_until" type="datetime-local" step="1"></div>
<div class="field"><label>电脑授权名额（1–100）</label><input name="device_limit" type="number" min="1" max="100" value="3"></div>
<div class="field"><label>安卓手机名额（0 表示禁止绑定）</label><input name="mobile_limit" type="number" min="0" max="1000" value="1"></div>
<div class="field span2"><label>平台与扩展权限</label><div class="check-row"><label><input type="checkbox" name="entitlements[]" value="douyin" checked> 抖音</label><label><input type="checkbox" name="entitlements[]" value="xiaohongshu"> 小红书</label><label><input type="checkbox" name="entitlements[]" value="mcp" <?=$adminRole==='admin'?'disabled':''?>> MCP</label><label><input type="checkbox" name="entitlements[]" value="mcp-codex" <?=$adminRole==='admin'?'disabled':''?>> Codex MCP</label><label><input type="checkbox" name="entitlements[]" value="mcp-harness" <?=$adminRole==='admin'?'disabled':''?>> DeepSeek Harness MCP</label><label><input type="checkbox" name="entitlements[]" value="skill" <?=$adminRole==='admin'?'disabled':''?>> Skill</label></div><span class="footnote">MCP/Skill 还需在「客户端能力控制」打开全局开关；新客户默认不授权。</span></div>
<div class="field"><label>账号状态</label><label class="check-row"><input type="checkbox" name="enabled" checked> 启用账号</label></div>
<div class="field"><label>AI 功能</label><label class="check-row"><input type="checkbox" name="ai_enabled" checked> 允许使用 AI</label></div>
<div class="field"><label>AI 每日请求额度（0–5000）</label><input name="ai_daily_limit" type="number" min="0" max="5000" value="100"></div>
<div class="field span2"><label>客户端自带 API Key</label><label class="check-row"><input type="checkbox" name="allow_client_ai_key" <?=$adminRole==='admin'?'disabled':''?>> 允许该客户自带 Key（还需全局开关）</label></div>
<div class="field span2"><label>内部备注</label><input name="notes" maxlength="500" placeholder="可填写客户联系方式、购买产品等"></div>
</div><div class="editor-actions"><button class="btn primary">保存授权</button></div></form></div>
<?php endif ?>
<div class="card">
<form method="get" action="index.php" class="account-filter-form" aria-label="筛选客户">
<input type="hidden" name="view" value="accounts">
<div class="field"><label for="account-filter-q">客户账号</label><input id="account-filter-q" name="q" maxlength="64" value="<?=h($accountFilters['q'])?>" placeholder="按账号搜索"></div>
<div class="field"><label for="account-filter-group">分组</label><select id="account-filter-group" name="group">
<option value="all">全部分组</option><option value="none" <?=$accountFilters['group']==='none'?'selected':''?>>未分组</option>
<?php foreach($groups as $g): ?><option value="<?=(int)$g['id']?>" <?=$accountFilters['group']===(string)$g['id']?'selected':''?>><?=h($g['name'])?></option><?php endforeach ?>
</select></div>
<div class="field"><label for="account-filter-status">状态</label><select id="account-filter-status" name="status">
<?php foreach(['all'=>'全部状态','enabled'=>'已启用','disabled'=>'已停用'] as $value=>$label): ?><option value="<?=h($value)?>" <?=$accountFilters['status']===$value?'selected':''?>><?=h($label)?></option><?php endforeach ?>
</select></div>
<div class="field"><label for="account-filter-expiry">到期情况</label><select id="account-filter-expiry" name="expiry">
<?php foreach(['all'=>'全部期限','expired'=>'已过期','due7'=>'未来 7 天到期','due30'=>'未来 30 天到期','permanent'=>'永久','valid'=>'未过期（含永久）'] as $value=>$label): ?><option value="<?=h($value)?>" <?=$accountFilters['expiry']===$value?'selected':''?>><?=h($label)?></option><?php endforeach ?>
</select></div>
<div class="field"><label for="account-filter-plan">客户套餐</label><select id="account-filter-plan" name="plan">
<option value="all">全部套餐</option><option value="legacy" <?=$accountFilters['plan']==='legacy'?'selected':''?>>旧授权（无套餐）</option><option value="custom" <?=$accountFilters['plan']==='custom'?'selected':''?>>自定义授权</option>
<?php foreach(phonehub_opening_plans(false) as $code=>$p): ?><option value="<?=h($code)?>" <?=$accountFilters['plan']===$code?'selected':''?>><?=h($p['label'])?><?=$p['enabled']?'':'（已停用）'?></option><?php endforeach ?>
</select></div>
<div class="account-filter-actions"><button class="btn primary" type="submit">查询</button><a class="btn" href="?view=accounts">重置</a></div>
</form></div>
<?php
$accountPageLink=static function(int $page) use($accountFilters): string {
    return 'index.php?'.http_build_query(['view'=>'accounts','q'=>$accountFilters['q'],
      'group'=>$accountFilters['group'],'status'=>$accountFilters['status'],
      'expiry'=>$accountFilters['expiry'],'plan'=>$accountFilters['plan'],'page'=>$page],
      '', '&', PHP_QUERY_RFC3986);
};
?>
<div class="card"><div class="card-head"><h2>客户列表</h2><span class="count">匹配 <?=$accountTotal?> 位 · 第 <?=$accountPage?> / <?=$accountPages?> 页（每页 30 位）</span></div>
<div class="table-scroll"><table><thead><tr><th>客户账号</th><th>客户套餐</th><th>分组</th><th>电脑名额</th><th>手机额度</th><th>授权截止（北京时间）</th><th>平台权限</th><th>状态</th><?php if(phonehub_role_can_action($adminRole,'account_save')): ?><th>操作</th><?php endif ?></tr></thead><tbody>
<?php foreach($accounts as $a): $payload=['id'=>(int)$a['id'],'username'=>$a['username'],'group_id'=>(int)$a['group_id'],'device_limit'=>(int)$a['device_limit'],'mobile_limit'=>(int)$a['mobile_limit'],'opening_plan_code'=>$a['opening_plan_code']??null,'license_until'=>utc_to_input($a['license_until']),'entitlements'=>json_decode((string)$a['entitlements'],true)?:[],'notes'=>$a['notes'],'enabled'=>(bool)$a['enabled'],'ai_enabled'=>(bool)$a['ai_enabled'],'allow_client_ai_key'=>(bool)$a['allow_client_ai_key'],'ai_daily_limit'=>(int)$a['ai_daily_limit']]; ?>
<tr><td><b><?=h($a['username'])?></b></td><td><?=h(phonehub_plan_label($a['opening_plan_code']??null))?></td><td><?=h($a['group_name']??'未分组')?></td><td><?= (int)$a['active_devices']?> / <?= (int)$a['device_limit']?></td><td><?= (int)$a['mobile_limit']?></td><td><?=h(utc_to_cn($a['license_until']))?></td><td><?=h(implode('、',array_map(static fn($x)=>['douyin'=>'抖音','xiaohongshu'=>'小红书','mcp'=>'MCP','skill'=>'Skill','mcp-codex'=>'Codex MCP','mcp-harness'=>'DeepSeek Harness MCP'][$x]??$x,json_decode((string)$a['entitlements'],true)?:[])))?></td>
<td><span class="pill <?= (int)$a['enabled']?'ok':'off'?>"><?= (int)$a['enabled']?'启用':'停用'?></span></td><?php if(phonehub_role_can_action($adminRole,'account_save')): ?><td class="actions">
<button class="small-link" data-edit="<?=h(json_encode($payload,JSON_UNESCAPED_UNICODE|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP|JSON_HEX_TAG))?>">编辑</button>
<button class="small-link" data-action="reset-account-password" data-id="<?=(int)$a['id']?>">重置密码</button>
<button class="small-link" data-action="revoke-account" data-id="<?=(int)$a['id']?>">踢下线</button>
<?php if(in_array($adminRole,['owner','global'],true)): ?><a class="small-link" href="<?=h('index.php?'.http_build_query(['view'=>'audit','audit_q'=>$a['username']]))?>">授权记录</a><?php endif ?>
</td><?php endif ?></tr><?php endforeach ?>
<?php if (!$accounts): ?><tr><td colspan="<?=phonehub_role_can_action($adminRole,'account_save')?9:8?>" class="empty-result">没有符合条件的客户，请调整筛选条件。</td></tr><?php endif ?>
</tbody></table></div>
<nav class="account-pagination" aria-label="客户列表分页">
<?php if($accountPage>1): ?><a class="btn" href="<?=h($accountPageLink($accountPage-1))?>">上一页</a><?php endif ?>
<span>第 <?=$accountPage?> 页 / 共 <?=$accountPages?> 页</span>
<?php if($accountPage<$accountPages): ?><a class="btn" href="<?=h($accountPageLink($accountPage+1))?>">下一页</a><?php endif ?>
</nav></div>
<?php elseif($view==='groups'): ?>
<div class="page-title"><div><h1>客户分组与批量配置</h1><p>创建、查看客户分组，并在同一页面批量调整组内授权。</p></div><?php if(phonehub_role_can_view($adminRole,'group_bulk')): ?><a class="btn primary" href="#group-bulk">批量配置授权</a><?php endif ?></div><?php if(phonehub_role_can_action($adminRole,'group_create')): ?><div class="card"><div class="card-head"><h2>新建分组</h2></div><form class="inline-form" data-ajax="group_create"><input type="hidden" name="action" value="group_create"><input name="name" placeholder="例如：代理商A / 企业客户" maxlength="100" required><button class="btn primary">创建分组</button></form></div><?php endif ?>
<div class="card" id="group-list"><div class="card-head"><h2>已创建分组</h2></div><div class="table-scroll"><table><thead><tr><th>分组名称</th><th>客户数</th><th>操作</th></tr></thead><tbody><?php foreach($groups as $g): ?><tr><td><b><?=h($g['name'])?></b></td><td><?=(int)$g['users']?></td><td><?php if(phonehub_role_can_action($adminRole,'group_delete')): ?><button class="small-link" data-action="delete-group" data-id="<?=(int)$g['id']?>">删除</button><?php else: ?>只读<?php endif ?></td></tr><?php endforeach ?></tbody></table></div></div>
<?php if(phonehub_role_can_view($adminRole,'group_bulk')): require_once __DIR__.'/app/features.php'; feature_view('group_bulk',true); endif; ?>
<?php elseif($view==='plans'): require_once __DIR__.'/app/features.php'; plan_admin_view(); ?>
<?php elseif($view==='packages'): require_once __DIR__.'/app/release_admin.php'; ?>
<div class="page-title"><div><h1>历史操作包</h1><p>只读兼容入口；主管理员请使用「版本发布与操作包」页面</p></div></div>
<?php release_package_overview(); ?>
<?php elseif($view==='update'): ?>
<div class="page-title"><div><h1>系统维护</h1><p>统一管理程序在线更新、运行环境自检、签名信任和独立加密备份密钥。</p></div></div>
<div class="update-actions maintenance-nav"><a class="btn" href="#maintenance-update">系统更新与自检</a><?php if($adminRole==='owner'): ?><a class="btn" href="#maintenance-backup">备份密钥管理</a><?php endif ?></div>
<div class="card update-card" id="maintenance-update"><div class="update-icon">⟳</div><h2>当前版本 v<?=h(app_version())?></h2><p class="muted">更新源：<code>https://git.wksite.cn/popowk/data</code></p><p class="muted">仅更新管理程序文件，自动跳过 storage 内的数据库配置和运行数据。</p>
<div class="update-actions"><button class="btn" data-action="check-update">检查更新</button><button class="btn" data-action="diagnose-update">运行环境自检</button><?php if($adminRole==='owner'): ?><a class="btn" href="#maintenance-backup">备份密钥</a><button class="btn primary" id="apply-update" data-action="apply-update" disabled>下载并安装更新</button><?php endif ?></div><p id="update-status" class="update-status">正在等待检查…</p><div id="update-diagnostics" class="update-status" role="status" aria-live="polite"></div></div>
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
 <?php if($adminRole!=='owner'): ?>
 <p class="muted">全局管理员可查看更新与签名状态；更换信任密钥及安装服务器更新仅主账号可操作。</p>
 <?php elseif($signing['state']==='unconfigured'): ?>
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
<?php
require_once __DIR__.'/app/features.php';
history_cleanup_admin_view();
if($adminRole==='owner') backup_admin_view(true);
?>
<?php elseif($view==='audit'):
$before=max(0,(int)($_GET['before']??0));
$auditQ=trim((string)($_GET['audit_q']??''));
if(utf8_length($auditQ)>80) $auditQ=utf8_limit($auditQ,80);
$auditWhere=[];$auditParams=[];
if($auditQ!=='') {
    $auditLike='%'.str_replace(['\\','%','_'],['\\\\','\\%','\\_'],$auditQ).'%';
    $auditWhere[]='(a.target LIKE ? OR a.action LIKE ?)';
    $auditParams[]=$auditLike;$auditParams[]=$auditLike;
}
if($before>0) {$auditWhere[]='a.id < ?';$auditParams[]=$before;}
$auditSql="SELECT a.id,a.action,a.target,a.ip,a.created_at,m.username
    FROM phonehub_admin_audit a LEFT JOIN phonehub_admins m ON m.id=a.admin_id".
    ($auditWhere?' WHERE '.implode(' AND ',$auditWhere):'')." ORDER BY a.id DESC LIMIT 51";
$audits=sql($auditSql,$auditParams)->fetchAll();
$hasOlder=count($audits)>50;if($hasOlder)array_pop($audits);
$nextBefore=$audits?(int)$audits[count($audits)-1]['id']:0;
$auditPageLink=static fn(int $id):string=>'index.php?'.http_build_query([
    'view'=>'audit','audit_q'=>$auditQ,'before'=>$id]);
?>
<div class="page-title"><div><h1>管理员操作记录</h1><p>按时间倒序，每页 50 条；可按操作类型和历史目标文本检索</p></div><?php if($before>0): ?><a class="btn" href="<?=h($auditPageLink(0))?>">返回最新记录</a><?php endif ?></div>
<div class="card">
<form class="device-search-form" method="get" action="index.php"><input type="hidden" name="view" value="audit">
<label for="admin-audit-q">客户账号、操作名称或目标摘要</label>
<input id="admin-audit-q" name="audit_q" maxlength="80" value="<?=h($auditQ)?>" placeholder="请输入关键词">
<button type="submit" class="btn">查询审计记录</button>
<?php if($auditQ!==''): ?><a class="btn" href="?view=audit">清除筛选</a><?php endif ?>
</form>
<p class="footnote">历史记录按原审计目标文本搜索。部分旧操作只保存了记录 ID 或摘要，无法还原未记录的字段差异。</p>
<div class="table-scroll"><table><thead><tr><th>时间（北京时间）</th><th>管理员</th><th>操作</th><th>目标</th><th>IP</th></tr></thead><tbody><?php foreach($audits as $a): ?><tr><td><?=h(utc_to_cn($a['created_at']))?></td><td><?=h($a['username'])?></td><td><?=h($a['action'])?></td><td><?=h($a['target'])?></td><td><?=h($a['ip'])?></td></tr><?php endforeach ?></tbody></table></div><?php if($hasOlder && $nextBefore>0): ?><div class="editor-actions"><a class="btn" href="<?=h($auditPageLink($nextBefore))?>">更早记录</a></div><?php endif ?></div>
<?php elseif ($view==='releases'): require __DIR__.'/app/release_admin.php'; release_admin_view(); ?>
<?php elseif (in_array($view,['admins','devices','client_logs','cloud_features','performance'],true)): require __DIR__.'/app/features.php'; feature_view($view); ?>
<?php endif ?>
</main></div></div><div class="toast" id="toast" role="status" aria-live="polite"></div><script src="assets/app.js?v=<?=rawurlencode(app_version())?>" defer></script></body></html>
