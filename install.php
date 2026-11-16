<?php
declare(strict_types=1);
require __DIR__.'/app/core.php';
if (installed()) { header('Location: index.php'); exit; }
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        check_csrf();
        if (!extension_loaded('pdo_mysql')) throw new RuntimeException('PHP 未安装 pdo_mysql 扩展');
        $host = trim((string)($_POST['db_host'] ?? '127.0.0.1'));
        $port = (int)($_POST['db_port'] ?? 3306);
        $name = trim((string)($_POST['db_name'] ?? ''));
        $user = trim((string)($_POST['db_user'] ?? ''));
        $pass = (string)($_POST['db_pass'] ?? '');
        $admin = trim((string)($_POST['admin_user'] ?? 'admin'));
        $adminPass = (string)($_POST['admin_pass'] ?? '');
        if (!preg_match('/^[a-zA-Z0-9_.-]{1,128}$/D', $host) || $port < 1 || $port > 65535) throw new RuntimeException('数据库地址或端口不正确');
        if (!preg_match('/^[a-zA-Z0-9_]{1,64}$/D', $name) || $user === '') throw new RuntimeException('请检查数据库名称与用户名');
        validate_user($admin);
        $hash = password_hash_safe($adminPass);
        $pdo = new PDO('mysql:host='.$host.';port='.$port.';dbname='.$name.';charset=utf8mb4', $user, $pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false
        ]);
        $pdo->exec("SET time_zone = '+00:00'");
        migrate($pdo);
        $count = (int)$pdo->query('SELECT COUNT(*) FROM phonehub_admins')->fetchColumn();
        if ($count !== 0) throw new RuntimeException('数据库已有管理员。为防止覆盖，请使用原有安装配置恢复访问');
        $stmt = $pdo->prepare("INSERT INTO phonehub_admins(username,password_hash,role,enabled) VALUES(?,?,'owner',1)");
        $stmt->execute([$admin,$hash]);
        if (!is_dir(APP_STORE) && !mkdir(APP_STORE, 0700, true) && !is_dir(APP_STORE)) throw new RuntimeException('无法创建 storage 目录，请赋予网站目录写入权限');
        $cfg = ['db_host'=>$host,'db_port'=>$port,'db_name'=>$name,'db_user'=>$user,'db_pass'=>$pass];
        $path = APP_STORE.'/config.php';
        $content = "<?php\n// PhoneHub 管理后台私有配置。禁止公开下载。\nreturn ".var_export($cfg,true).";\n";
        if (file_put_contents($path.'.tmp', $content, LOCK_EX) === false || !rename($path.'.tmp', $path)) throw new RuntimeException('配置保存失败，请确认 storage 可写');
        @chmod($path, 0600);
        session_regenerate_id(true);
        $_SESSION['admin_id'] = (int)$pdo->lastInsertId();
        header('Location: index.php'); exit;
    } catch (Throwable $e) {
        error_log('PhoneHub install: '.get_class($e));
        $error = $e instanceof PDOException ? '无法连接或初始化数据库，请检查账号权限及 MySQL 版本' : $e->getMessage();
    }
}
?>
<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>安装 · PhoneHub</title><link rel="stylesheet" href="assets/app.css"></head>
<body class="auth-body"><main class="auth-card"><div class="brand"><span class="brand-mark">P</span><div><strong>PhoneHub</strong><small>授权管理 · 初始安装</small></div></div>
<h1>欢迎使用 PhoneHub</h1><p class="muted">只需填写数据库连接与管理员账号，网页自动建表，不会删除现有 PhoneHub 客户数据。</p>
<?php if ($error): ?><p class="alert"><?=h($error)?></p><?php endif ?>
<form method="post"><input type="hidden" name="csrf" value="<?=h(csrf())?>">
<div class="field"><label>数据库主机</label><input required name="db_host" value="127.0.0.1"></div>
<div class="two"><div class="field"><label>端口</label><input required name="db_port" type="number" value="3306"></div><div class="field"><label>数据库名</label><input required name="db_name" placeholder="data_tmd_pet"></div></div>
<div class="two"><div class="field"><label>数据库用户</label><input required name="db_user"></div><div class="field"><label>数据库密码</label><input name="db_pass" type="password"></div></div>
<hr><div class="field"><label>管理员账号</label><input required name="admin_user" value="admin"></div>
<div class="field"><label>管理员密码（至少 12 字节）</label><input required name="admin_pass" type="password" minlength="12" autocomplete="new-password"></div>
<button class="btn primary full" type="submit">连接数据库并完成安装</button></form>
<p class="footnote">需要 PHP 8.2+、PDO MySQL、MySQL 5.7.8+；升级功能另需 cURL 与 ZipArchive。</p></main></body></html>
