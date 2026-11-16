<?php
declare(strict_types=1);
require dirname(__DIR__).'/app/core.php';
require dirname(__DIR__).'/app/ai.php';

$pdo=new PDO('mysql:host=127.0.0.1;port=3306;dbname=phonehub_ci;charset=utf8mb4','root','ci_password',[
    PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false
]);
$pdo->exec("SET time_zone = '+00:00'");
migrate($pdo);
migrate($pdo);
$count=(int)$pdo->query('SELECT COUNT(*) FROM phonehub_admin_migrations WHERE version=1')->fetchColumn();
if ($count!==1) throw new RuntimeException('schema migration not idempotent');
$aiColumns=$pdo->query("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='phonehub_users'")->fetchAll(PDO::FETCH_COLUMN);
foreach(['ai_enabled','allow_client_ai_key','ai_daily_limit'] as $column) if(!in_array($column,$aiColumns,true)) throw new RuntimeException('missing AI account column '.$column);
$aiTable=(int)$pdo->query("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='phonehub_ai_usage'")->fetchColumn();
if($aiTable!==1) throw new RuntimeException('AI usage table missing');
$value='test-encryption-value-123456';
$encrypted=ai_encrypt_secret($value);
if($encrypted===$value || ai_decrypt_secret($encrypted)!==$value) throw new RuntimeException('AI encryption round trip failed');

$hash=password_hash_safe('test-secret-123456');
if (!password_verify('test-secret-123456',$hash)) throw new RuntimeException('password hash failed');
$pdo->prepare('INSERT INTO phonehub_users(username,password_hash,entitlements) VALUES(?,?,?)')->execute(['phonehub_ci_user',$hash,'["douyin"]']);
$id=(int)$pdo->lastInsertId();
$pdo->prepare('INSERT INTO phonehub_user_meta(user_id,mobile_limit,notes) VALUES(?,?,?)')->execute([$id,8,'CI测试']);
$result=$pdo->prepare('SELECT u.username,m.mobile_limit,u.entitlements FROM phonehub_users u JOIN phonehub_user_meta m ON m.user_id=u.id WHERE u.id=?');
$result->execute([$id]);
$record=$result->fetch(PDO::FETCH_ASSOC);
if (!$record || $record['username']!=='phonehub_ci_user' || (int)$record['mobile_limit']!==8 || json_decode($record['entitlements'],true)!==['douyin']) throw new RuntimeException('account readback failed');
$pdo->prepare('INSERT INTO phonehub_packages(package_id,version,envelope,content_key) VALUES(?,?,?,?)')->execute(['douyin',1,'{"manifest":"test","signature":"test","nonce":"test","ciphertext":"test"}','test']);
$utc=input_to_utc('2026-12-31T23:59');
if ($utc!=='2026-12-31 15:59:00') throw new RuntimeException('timezone conversion failed');
echo "PASS: MySQL 5.7 compatible schema, migrations, password hashes, account readback, UTC conversion\n";
