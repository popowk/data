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
    migrate($conn);
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
/**
 * 数据结构版本化迁移：新版本可在此加入版本 2、3 等迁移，不需手动运行 SQL。
 * 迁移记录只在执行成功后写入；不重建、不删除已有授权数据。
 */
function migrate(PDO $conn): void {
    // Fast path: once the current schema is recorded, normal page/API requests do not
    // acquire a MySQL named lock or repeatedly query information_schema.
    try {
        $ready=(int)$conn->query("SELECT COALESCE(MAX(version),0) FROM phonehub_admin_migrations")->fetchColumn();
        if ($ready>=5) return;
    } catch (PDOException $e) {
        if ($e->getCode()!=='42S02') throw $e;
    }
    // A shared lock serializes first-install and pending migrations.
    if ((int)$conn->query("SELECT GET_LOCK('phonehub_admin_schema_v1',15)")->fetchColumn()!==1)
        throw new RuntimeException('数据库迁移繁忙，请稍后刷新');
    try {
    $conn->exec("CREATE TABLE IF NOT EXISTS phonehub_admin_migrations (version INT NOT NULL PRIMARY KEY, applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $version=(int)$conn->query("SELECT COALESCE(MAX(version),0) FROM phonehub_admin_migrations")->fetchColumn();
    if ($version < 1) {
        schema($conn);
        $conn->exec("INSERT IGNORE INTO phonehub_admin_migrations(version,applied_at) VALUES(1,UTC_TIMESTAMP())");
    }
    if ($version < 2) {
        // MySQL 5.7 compatible migrations; DDL is idempotent to recover from interrupted updates.
        $hasColumn = static function(string $name) use ($conn): bool {
            $stmt=$conn->prepare("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='phonehub_admins' AND COLUMN_NAME=?");
            $stmt->execute([$name]); return (int)$stmt->fetchColumn() > 0;
        };
        if (!$hasColumn('role')) $conn->exec("ALTER TABLE phonehub_admins ADD COLUMN role VARCHAR(16) NOT NULL DEFAULT 'admin'");
        if (!$hasColumn('enabled')) $conn->exec("ALTER TABLE phonehub_admins ADD COLUMN enabled TINYINT NOT NULL DEFAULT 1");
        if (!$hasColumn('auth_version')) $conn->exec("ALTER TABLE phonehub_admins ADD COLUMN auth_version INT NOT NULL DEFAULT 1");
        // The earliest existing administrator becomes the immutable primary administrator.
        $conn->exec("UPDATE phonehub_admins SET role='owner',enabled=1 WHERE id=(SELECT id FROM (SELECT MIN(id) AS id FROM phonehub_admins) AS first_admin)");
        $conn->exec("CREATE TABLE IF NOT EXISTS phonehub_mobile_devices (
          id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          user_id BIGINT UNSIGNED NOT NULL, phone_id CHAR(64) NOT NULL,
          display_name VARCHAR(120) NOT NULL DEFAULT '',
          enabled TINYINT NOT NULL DEFAULT 1,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          last_seen DATETIME NULL,
          UNIQUE KEY uniq_user_phone(user_id,phone_id),
          INDEX idx_user_enabled(user_id,enabled)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->exec("CREATE TABLE IF NOT EXISTS phonehub_package_downloads (
          id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          user_id BIGINT UNSIGNED NOT NULL, package_id VARCHAR(32) NOT NULL,
          device_id CHAR(64) NOT NULL, downloaded_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          INDEX idx_user_date(user_id,downloaded_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->exec("CREATE TABLE IF NOT EXISTS phonehub_client_logs (
          id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          user_id BIGINT UNSIGNED NOT NULL,device_id CHAR(64) NOT NULL,
          level VARCHAR(12) NOT NULL,event VARCHAR(64) NOT NULL,
          message VARCHAR(2000) NOT NULL,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          INDEX idx_user_date(user_id,created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->exec("INSERT IGNORE INTO phonehub_admin_migrations(version,applied_at) VALUES(2,UTC_TIMESTAMP())");
    }
    if ($version < 3) {
        $conn->exec("CREATE TABLE IF NOT EXISTS phonehub_releases (
          id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          platform VARCHAR(32) NOT NULL DEFAULT 'core',
          channel VARCHAR(16) NOT NULL DEFAULT 'stable',
          version VARCHAR(48) NOT NULL,
          min_client VARCHAR(48) NOT NULL DEFAULT '0.0.0',
          notes VARCHAR(1000) NOT NULL DEFAULT '',
          filename VARCHAR(255) NOT NULL,
          storage_name VARCHAR(90) NOT NULL,
          size_bytes BIGINT UNSIGNED NOT NULL,
          sha256 CHAR(64) NOT NULL,
          manifest MEDIUMTEXT NOT NULL,
          signature VARCHAR(128) NOT NULL,
          enabled TINYINT NOT NULL DEFAULT 1,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE KEY uq_release(platform,channel,version),
          INDEX idx_lookup(platform,channel,enabled)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->exec("INSERT IGNORE INTO phonehub_admin_migrations(version,applied_at) VALUES(3,UTC_TIMESTAMP())");
    }
    if ($version < 4) {
        $hasUserColumn = static function(string $name) use ($conn): bool {
            $stmt=$conn->prepare("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='phonehub_users' AND COLUMN_NAME=?");
            $stmt->execute([$name]); return (int)$stmt->fetchColumn()>0;
        };
        if (!$hasUserColumn('ai_enabled')) $conn->exec("ALTER TABLE phonehub_users ADD COLUMN ai_enabled TINYINT NOT NULL DEFAULT 1");
        if (!$hasUserColumn('allow_client_ai_key')) $conn->exec("ALTER TABLE phonehub_users ADD COLUMN allow_client_ai_key TINYINT NOT NULL DEFAULT 0");
        if (!$hasUserColumn('ai_daily_limit')) $conn->exec("ALTER TABLE phonehub_users ADD COLUMN ai_daily_limit INT NOT NULL DEFAULT 100");
        $conn->exec("CREATE TABLE IF NOT EXISTS phonehub_ai_settings (
          setting_key VARCHAR(64) NOT NULL PRIMARY KEY,
          setting_value MEDIUMTEXT NOT NULL,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->exec("CREATE TABLE IF NOT EXISTS phonehub_ai_usage (
          id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          request_id CHAR(32) NOT NULL UNIQUE,
          user_id BIGINT UNSIGNED NOT NULL,
          device_id CHAR(64) NOT NULL,
          mode VARCHAR(12) NOT NULL,
          model VARCHAR(48) NOT NULL,
          status VARCHAR(16) NOT NULL DEFAULT 'pending',
          http_status SMALLINT UNSIGNED NOT NULL DEFAULT 0,
          prompt_tokens INT UNSIGNED NOT NULL DEFAULT 0,
          completion_tokens INT UNSIGNED NOT NULL DEFAULT 0,
          elapsed_ms INT UNSIGNED NOT NULL DEFAULT 0,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          INDEX idx_user_time(user_id,created_at),
          INDEX idx_global_time(created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->exec("INSERT IGNORE INTO phonehub_ai_settings(setting_key,setting_value) VALUES
          ('enabled','1'),('provider','deepseek'),('model','deepseek-flash'),
          ('client_key_enabled','0'),('max_tokens','4096'),('requests_per_minute','10')");
        $conn->exec("INSERT IGNORE INTO phonehub_admin_migrations(version,applied_at) VALUES(4,UTC_TIMESTAMP())");
    }
    if ($version < 5) {
        // Repair AI objects even for installations that recorded v4 before all DDL completed.
        $hasColumn=static function(string $table,string $name) use ($conn): bool {
            $stmt=$conn->prepare("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND COLUMN_NAME=?");
            $stmt->execute([$table,$name]); return (int)$stmt->fetchColumn()>0;
        };
        foreach (['ai_enabled'=>"TINYINT NOT NULL DEFAULT 1",'allow_client_ai_key'=>"TINYINT NOT NULL DEFAULT 0",'ai_daily_limit'=>"INT NOT NULL DEFAULT 100"] as $column=>$definition) {
            if (!$hasColumn('phonehub_users',$column)) $conn->exec("ALTER TABLE phonehub_users ADD COLUMN ".$column." ".$definition);
        }
        $conn->exec("CREATE TABLE IF NOT EXISTS phonehub_ai_settings (
          setting_key VARCHAR(64) NOT NULL PRIMARY KEY,
          setting_value MEDIUMTEXT NOT NULL,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->exec("CREATE TABLE IF NOT EXISTS phonehub_ai_usage (
          id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          request_id CHAR(32) NOT NULL UNIQUE,
          user_id BIGINT UNSIGNED NOT NULL,
          device_id CHAR(64) NOT NULL,
          mode VARCHAR(12) NOT NULL,
          model VARCHAR(48) NOT NULL,
          status VARCHAR(16) NOT NULL DEFAULT 'pending',
          http_status SMALLINT UNSIGNED NOT NULL DEFAULT 0,
          prompt_tokens INT UNSIGNED NOT NULL DEFAULT 0,
          completion_tokens INT UNSIGNED NOT NULL DEFAULT 0,
          elapsed_ms INT UNSIGNED NOT NULL DEFAULT 0,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          INDEX idx_user_time(user_id,created_at),
          INDEX idx_global_time(created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->exec("INSERT IGNORE INTO phonehub_ai_settings(setting_key,setting_value) VALUES
          ('enabled','1'),('provider','deepseek'),('model','deepseek-flash'),
          ('client_key_enabled','0'),('max_tokens','4096'),('requests_per_minute','10')");

        if (!$hasColumn('phonehub_mobile_devices','imei_hash'))
            $conn->exec("ALTER TABLE phonehub_mobile_devices ADD COLUMN imei_hash CHAR(64) NULL DEFAULT NULL");
        $hasIndex=static function(string $table,string $name) use ($conn): bool {
            $stmt=$conn->prepare("SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND INDEX_NAME=?");
            $stmt->execute([$table,$name]); return (int)$stmt->fetchColumn()>0;
        };
        if (!$hasIndex('phonehub_mobile_devices','idx_imei_hash'))
            $conn->exec("ALTER TABLE phonehub_mobile_devices ADD INDEX idx_imei_hash(imei_hash)");
        $conn->exec("CREATE TABLE IF NOT EXISTS phonehub_mobile_blacklist (
          id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          identifier_type VARCHAR(16) NOT NULL,
          identifier_hash CHAR(64) NOT NULL,
          reason VARCHAR(255) NOT NULL DEFAULT '',
          enabled TINYINT NOT NULL DEFAULT 1,
          created_by BIGINT UNSIGNED NOT NULL DEFAULT 0,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE KEY uq_mobile_identifier(identifier_type,identifier_hash),
          INDEX idx_mobile_blacklist_enabled(enabled,identifier_type)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->exec("CREATE TABLE IF NOT EXISTS phonehub_feature_settings (
          setting_key VARCHAR(64) NOT NULL PRIMARY KEY,
          setting_value VARCHAR(8) NOT NULL DEFAULT '0',
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        // MCP and Skill stay globally disabled until the owner explicitly enables them.
        $conn->exec("INSERT IGNORE INTO phonehub_feature_settings(setting_key,setting_value) VALUES
          ('mcp_enabled','0'),('skill_enabled','0')");
        $conn->exec("INSERT IGNORE INTO phonehub_admin_migrations(version,applied_at) VALUES(5,UTC_TIMESTAMP())");
    }
    } finally {
        $conn->query("SELECT RELEASE_LOCK('phonehub_admin_schema_v1')");
    }
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
    $s=db()->prepare('SELECT enabled,auth_version FROM phonehub_admins WHERE id=?');
    $s->execute([admin_id()]);
    $row=$s->fetch(PDO::FETCH_ASSOC);
    if (!$row || !(int)$row['enabled'] || (int)$row['auth_version'] !== (int)($_SESSION['auth_version'] ?? 0))
        throw new RuntimeException('管理员权限已变更，请重新登录');
}
function require_owner(): void {
    require_admin();
    $row=sql('SELECT role FROM phonehub_admins WHERE id=?',[admin_id()])->fetch();
    if (!$row || $row['role'] !== 'owner') throw new RuntimeException('仅主管理员可以执行此操作');
}
function random_password(int $length=20): string {
    $characters='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789@#%+-';
    $out='';
    for ($i=0;$i<$length;$i++) $out.=$characters[random_int(0,strlen($characters)-1)];
    return $out;
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
    foreach (['Y-m-d\TH:i:s','Y-m-d\TH:i'] as $format) {
        $t = DateTimeImmutable::createFromFormat('!'.$format, $local, new DateTimeZone('Asia/Shanghai'));
        if ($t && $t->format($format) === $local) return $t->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s');
    }
    throw new RuntimeException('授权截止时间格式错误');
}
function utc_to_input(?string $utc): string {
    if (!$utc) return '';
    return (new DateTimeImmutable($utc, new DateTimeZone('UTC')))->setTimezone(new DateTimeZone('Asia/Shanghai'))->format('Y-m-d\TH:i:s');
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
