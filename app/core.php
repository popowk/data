<?php
declare(strict_types=1);

const APP_ROOT = __DIR__ . '/..';
const APP_STORE = APP_ROOT . '/storage';

ini_set('display_errors', '0');
date_default_timezone_set('UTC');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Content-Security-Policy: default-src \'self\'; script-src \'self\'; style-src \'self\'; img-src \'self\' data:; form-action \'self\'; frame-ancestors \'none\'');
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_name('phadmin');
    session_set_cookie_params([
        'lifetime' => 0, 'path' => '/', 'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'httponly' => true, 'samesite' => 'Strict'
    ]);
    session_start();
}

function installed(): bool { return is_file(APP_STORE . '/config.php'); }
function config(): array {
    if (!installed()) throw new RuntimeException('请先完成网页安装');
    $value = require APP_STORE . '/config.php';
    if (!is_array($value)) throw new RuntimeException('配置文件无效');
    return $value;
}
function db(): PDO {
    static $conn = null;
    if ($conn instanceof PDO) return $conn;
    $cfg = config();
    $conn = new PDO(
        'mysql:host=' . $cfg['db_host'] . ';port=' . (int)$cfg['db_port'] . ';dbname=' . $cfg['db_name'] . ';charset=utf8mb4',
        $cfg['db_user'], $cfg['db_pass'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]
    );
    $conn->exec("SET time_zone = '+00:00'");
    return $conn;
}
function schema(PDO $db): void {
    $statements = [
        "CREATE TABLE IF NOT EXISTS phonehub_users (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, username VARCHAR(64) NOT NULL UNIQUE, password_hash VARCHAR(255) NOT NULL, enabled TINYINT NOT NULL DEFAULT 1, device_limit INT NOT NULL DEFAULT 3, license_until DATETIME NULL, entitlements JSON NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
        "CREATE TABLE IF NOT EXISTS phonehub_sessions (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, user_id BIGINT UNSIGNED NOT NULL, device_id CHAR(64) NOT NULL, token_hash CHAR(64) NOT NULL UNIQUE, expires_at DATETIME NOT NULL, INDEX user_device(user_id, device_id), INDEX expiry(expires_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
        "CREATE TABLE IF NOT EXISTS phonehub_login_attempts (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, bucket CHAR(64) NOT NULL, attempted_at DATETIME NOT NULL, INDEX throttle(bucket, attempted_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
        "CREATE TABLE IF NOT EXISTS phonehub_packages (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, package_id VARCHAR(32) NOT NULL, version BIGINT NOT NULL, envelope MEDIUMTEXT NOT NULL, content_key VARCHAR(64) NOT NULL, enabled TINYINT NOT NULL DEFAULT 1, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE package_version(package_id, version)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
        "CREATE TABLE IF NOT EXISTS phonehub_admins (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, username VARCHAR(64) NOT NULL UNIQUE, password_hash VARCHAR(255) NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
        "CREATE TABLE IF NOT EXISTS phonehub_groups (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL UNIQUE, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
        "CREATE TABLE IF NOT EXISTS phonehub_user_meta (user_id BIGINT UNSIGNED NOT NULL PRIMARY KEY, group_id BIGINT UNSIGNED NULL, mobile_limit INT NOT NULL DEFAULT 0, notes VARCHAR(500) NOT NULL DEFAULT '', INDEX idx_group(group_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
        "CREATE TABLE IF NOT EXISTS phonehub_admin_audit (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, admin_id BIGINT UNSIGNED NOT NULL, action VARCHAR(64) NOT NULL, target VARCHAR(150) NOT NULL, ip VARCHAR(45) NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, INDEX idx_when(created_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
        "CREATE TABLE IF NOT EXISTS phonehub_admin_attempts (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, bucket CHAR(64) NOT NULL, attempted_at DATETIME NOT NULL, INDEX idx_attempts(bucket,attempted_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
    ];
    foreach ($statements as $sql) $db->exec($sql);
}
function sql(string $statement, array $params = []): PDOStatement {
    $s = db()->prepare($statement); $s->execute($params); return $s;
}
function utf8_length(string $value): int { return preg_match_all('/./us', $value) ?: 0; }
function utf8_limit(string $value,int $limit): string { return implode('',array_slice(preg_split('//u',$value,-1,PREG_SPLIT_NO_EMPTY) ?: [],0,$limit)); }
function h(mixed $text): string { return htmlspecialchars((string)$text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function csrf(): string {
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
}
function check_csrf(): void {
    $sent = (string)($_POST['csrf'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
    if (!hash_equals(csrf(), $sent)) throw new RuntimeException('请求已过期，请刷新页面后重试');
}
function admin_id(): int { return (int)($_SESSION['admin_id'] ?? 0); }
function require_admin(): void {
    if (!admin_id()) throw new RuntimeException('登录已失效，请重新登录');
}
function audit(string $action, string $target): void {
    sql('INSERT INTO phonehub_admin_audit(admin_id,action,target,ip) VALUES(?,?,?,?)',
        [admin_id(), $action, utf8_limit($target,150), (string)($_SERVER['REMOTE_ADDR'] ?? '')]);
}
function json_response(array $data, int $status=200): never {
    http_response_code($status); header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES); exit;
}
function utc_to_cn(?string $utc): string {
    if (!$utc) return '永久';
    return (new DateTimeImmutable($utc, new DateTimeZone('UTC')))->setTimezone(new DateTimeZone('Asia/Shanghai'))->format('Y-m-d H:i');
}
function input_to_utc(string $local): ?string {
    if ($local === '') return null;
    $t = DateTimeImmutable::createFromFormat('!Y-m-d\TH:i', $local, new DateTimeZone('Asia/Shanghai'));
    if (!$t || $t->format('Y-m-d\TH:i') !== $local) throw new RuntimeException('授权截止时间格式错误');
    return $t->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s');
}
function utc_to_input(?string $utc): string {
    if (!$utc) return '';
    return (new DateTimeImmutable($utc, new DateTimeZone('UTC')))->setTimezone(new DateTimeZone('Asia/Shanghai'))->format('Y-m-d\TH:i');
}
function validate_user(string $name): void {
    if (!preg_match('/^[A-Za-z0-9_-]{3,64}$/D', $name)) throw new RuntimeException('账号名需为 3–64 位字母、数字、下划线或短横线');
}
function password_hash_safe(string $password): string {
    if (strlen($password) < 12 || strlen($password) > 128) throw new RuntimeException('密码长度必须为 12–128 字节');
    return password_hash($password, PASSWORD_ARGON2ID);
}
function app_version(): string {
    $data = json_decode((string)file_get_contents(APP_ROOT.'/version.json'), true);
    return (string)($data['version'] ?? '0.0.0');
}
