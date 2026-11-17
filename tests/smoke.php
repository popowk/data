<?php
declare(strict_types=1);
require dirname(__DIR__).'/app/core.php';
require dirname(__DIR__).'/app/ai.php';
require dirname(__DIR__).'/app/mobile.php';
require dirname(__DIR__).'/app/releases.php';
require dirname(__DIR__).'/app/accounts.php';
require dirname(__DIR__).'/app/updater.php';

$pdo=new PDO('mysql:host=127.0.0.1;port=3306;dbname=phonehub_ci;charset=utf8mb4','root','ci_password',[
    PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false
]);
$pdo->exec("SET time_zone = '+00:00'");
migrate($pdo);
migrate($pdo);
$lockConn=new PDO('mysql:host=127.0.0.1;port=3306;dbname=phonehub_ci;charset=utf8mb4','root','ci_password');
$lockAcquired=(int)$lockConn->query("SELECT GET_LOCK('phonehub_admin_schema_v1',0)")->fetchColumn();
if($lockAcquired!==1) throw new RuntimeException('could not acquire migration lock for fast-path test');
migrate($pdo);
$lockConn->query("SELECT RELEASE_LOCK('phonehub_admin_schema_v1')");
$count=(int)$pdo->query('SELECT COUNT(*) FROM phonehub_admin_migrations WHERE version=1')->fetchColumn();
if ($count!==1) throw new RuntimeException('schema migration not idempotent');
$aiColumns=$pdo->query("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='phonehub_users'")->fetchAll(PDO::FETCH_COLUMN);
foreach(['ai_enabled','allow_client_ai_key','ai_daily_limit'] as $column) if(!in_array($column,$aiColumns,true)) throw new RuntimeException('missing AI account column '.$column);
$aiTable=(int)$pdo->query("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='phonehub_ai_usage'")->fetchColumn();
if($aiTable!==1) throw new RuntimeException('AI usage table missing');
// Simulate a partially upgraded v0.3 deployment whose migration marker exists but AI objects are missing.
$pdo->exec("DELETE FROM phonehub_admin_migrations WHERE version>4");
$pdo->exec("DROP TABLE phonehub_ai_usage");
$pdo->exec("DROP TABLE phonehub_ai_settings");
foreach(['ai_enabled','allow_client_ai_key','ai_daily_limit'] as $column) $pdo->exec("ALTER TABLE phonehub_users DROP COLUMN ".$column);
migrate($pdo);
$aiTable=(int)$pdo->query("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='phonehub_ai_usage'")->fetchColumn();
if($aiTable!==1) throw new RuntimeException('AI schema self-repair failed');
$aiColumns=$pdo->query("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='phonehub_users'")->fetchAll(PDO::FETCH_COLUMN);
foreach(['ai_enabled','allow_client_ai_key','ai_daily_limit'] as $column) if(!in_array($column,$aiColumns,true)) throw new RuntimeException('AI schema self-repair missed '.$column);
$metaColumns=$pdo->query("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='phonehub_user_meta'")->fetchAll(PDO::FETCH_COLUMN);
if (!in_array('opening_plan_code',$metaColumns,true))
    throw new RuntimeException('opening plan migration missing');
$openingPlans=phonehub_opening_plans();
if (count($openingPlans)!==3 || $openingPlans['personal']['device_limit']!==1 ||
    $openingPlans['standard']['mobile_limit']!==5 || $openingPlans['team']['device_limit']!==10 ||
    phonehub_plan_label(null)!=='原有授权')
    throw new RuntimeException('opening plan presets invalid');
$mobileColumns=$pdo->query("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='phonehub_mobile_devices'")->fetchAll(PDO::FETCH_COLUMN);
foreach (['imei_hash','imei_encrypted','phone_number_encrypted','phone_number_hash','phone_model'] as $column)
    if(!in_array($column,$mobileColumns,true)) throw new RuntimeException('mobile identity column missing: '.$column);
$blacklistTable=(int)$pdo->query("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='phonehub_mobile_blacklist'")->fetchColumn();
if($blacklistTable!==1) throw new RuntimeException('mobile blacklist table missing');
$identityMeta=(int)$pdo->query("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='phonehub_mobile_identity_meta'")->fetchColumn();
if($identityMeta!==1) throw new RuntimeException('mobile identity key metadata table missing');
$featureFlags=$pdo->query("SELECT setting_key,setting_value FROM phonehub_feature_settings")->fetchAll(PDO::FETCH_KEY_PAIR);
foreach (['mcp_enabled','skill_enabled','mcp_codex_enabled','mcp_harness_enabled'] as $key)
    if (($featureFlags[$key]??'1')!=='0') throw new RuntimeException('new cloud feature must default disabled: '.$key);
$imei='490154203237519';
$imeiHash=mobile_imei_hash($imei);
if(!preg_match('/^[a-f0-9]{64}$/D',(string)$imeiHash) || hash_equals(hash('sha256',$imei),(string)$imeiHash))
    throw new RuntimeException('IMEI must be stored as keyed HMAC, not raw or plain SHA-256');
$keyPath=APP_STORE.'/mobile-identity.key';
$keyBackup=file_get_contents($keyPath);
if (!is_string($keyBackup) || strlen($keyBackup)!==32 || !unlink($keyPath))
    throw new RuntimeException('could not prepare IMEI key-loss test');
$keyLossRejected=false;
try {mobile_imei_hash($imei);} catch(RuntimeException $e) {$keyLossRejected=str_contains($e->getMessage(),'密钥丢失');}
file_put_contents($keyPath,$keyBackup,LOCK_EX);
if (PHP_OS_FAMILY!=='Windows') chmod($keyPath,0600);
if (!$keyLossRejected) throw new RuntimeException('missing IMEI HMAC key must fail closed, not rotate');
$phoneId=str_repeat('c',64);
$pdo->prepare("INSERT INTO phonehub_mobile_blacklist(identifier_type,identifier_hash,reason,enabled,created_by) VALUES('imei_hash',?,?,1,0)")
    ->execute([$imeiHash,'CI blacklist test']);
if(!mobile_blacklist_match($pdo,$phoneId,$imeiHash)) throw new RuntimeException('IMEI blacklist lookup failed');
require dirname(__DIR__).'/app/devices.php';
$encryptedImei=device_encrypt('490154203237518');
$encryptedPhone=device_encrypt('+8613812345678');
if($encryptedImei==='490154203237518' || device_decrypt($encryptedImei)!=='490154203237518')
    throw new RuntimeException('IMEI encrypted roundtrip failed');
if(device_decrypt($encryptedPhone)!=='+8613812345678')
    throw new RuntimeException('phone number encrypted roundtrip failed');
$phoneHash=device_phone_hash(device_phone_normalize('13812345678'));
if(!is_string($phoneHash) || strlen($phoneHash)!==64 || hash_equals($phoneHash,hash('sha256','13812345678')))
    throw new RuntimeException('phone number HMAC validation failed');
$pdo->prepare("INSERT INTO phonehub_mobile_blacklist(identifier_type,identifier_hash,reason,enabled,created_by) VALUES('phone_hash',?,?,1,0)")
    ->execute([$phoneHash,'phone blacklist test']);
if(!mobile_blacklist_match($pdo,str_repeat('b',64),null,$phoneHash))
    throw new RuntimeException('phone number blacklist lookup failed');
$computerId=str_repeat('d',64);
if(device_blacklisted_computer($pdo,$computerId)) throw new RuntimeException('unknown computer incorrectly blacklisted');
device_insert_blacklist($pdo,'computer_id',$computerId,'CI computer blacklist',0);
if(!device_blacklisted_computer($pdo,$computerId)) throw new RuntimeException('computer blacklist lookup failed');
if(release_platform('mcp')!=='mcp' || release_platform('skill')!=='skill' ||
   release_platform('mcp-codex')!=='mcp-codex' || release_platform('mcp-harness')!=='mcp-harness')
    throw new RuntimeException('MCP/Skill subplatform release targets unavailable');
$value='test-encryption-value-123456';
$encrypted=ai_encrypt_secret($value);
if($encrypted===$value || ai_decrypt_secret($encrypted)!==$value) throw new RuntimeException('AI encryption round trip failed');
if (!is_dir(APP_STORE)) mkdir(APP_STORE,0700,true);
file_put_contents(APP_STORE.'/config.php',"<?php return ['db_host'=>'127.0.0.1','db_port'=>3306,'db_name'=>'phonehub_ci','db_user'=>'root','db_pass'=>'ci_password'];");
$pdo->prepare("INSERT INTO phonehub_admins(username,password_hash,role,enabled,auth_version) VALUES(?,?, 'owner',1,1)")
    ->execute(['ci_ai_owner',$hash??password_hash_safe('ci-owner-test-123456')]);
$ownerId=(int)$pdo->lastInsertId();
$_SESSION['admin_id']=$ownerId;$_SESSION['auth_version']=1;$_SESSION['admin_user']='ci_ai_owner';
$saved=ai_save_settings(['enabled'=>'1','model'=>'deepseek-flash','max_tokens'=>'4096','requests_per_minute'=>'10']);
if (!($saved['server_key_configured']===false)) throw new RuntimeException('AI settings save result incorrect');
$testKey='test-ai-key-value-123456789';
$savedWithKey=ai_save_settings(['enabled'=>'1','model'=>'deepseek-flash','max_tokens'=>'4096','requests_per_minute'=>'10','api_key'=>$testKey]);
$cipher=(string)$pdo->query("SELECT setting_value FROM phonehub_ai_settings WHERE setting_key='api_key_ciphertext'")->fetchColumn();
if (!$savedWithKey['server_key_configured'] || $cipher===$testKey || ai_server_secret()!==$testKey)
    throw new RuntimeException('AI provider key was not encrypted at rest');
ai_save_settings(['enabled'=>'1','model'=>'deepseek-flash','max_tokens'=>'4096','requests_per_minute'=>'10','remove_api_key'=>'1']);
$settings=ai_settings();
if (!$settings['enabled'] || $settings['model']!=='deepseek-flash' || $settings['client_key_enabled'] || $settings['server_key_configured'])
    throw new RuntimeException('AI default settings incorrect');
ob_start();ai_admin_view();$aiHtml=ob_get_clean();
if (strpos($aiHtml,'AI 接口管理')===false || strpos($aiHtml,'remove_api_key')===false)
    throw new RuntimeException('AI admin settings page render failed');
require dirname(__DIR__).'/app/features.php';
ob_start();feature_view('cloud_features');$cloudHtml=ob_get_clean();
if (strpos($cloudHtml,'MCP 连接能力')===false || strpos($cloudHtml,'Skill 技能能力')===false)
    throw new RuntimeException('cloud feature control page render failed');
if (strpos($cloudHtml,'cloud-feature-card')===false || strpos($cloudHtml,'cloud-savebar')===false)
    throw new RuntimeException('redesigned cloud feature controls missing');
if (strpos($cloudHtml,'name="mcp_codex_enabled"')===false ||
    strpos($cloudHtml,'name="mcp_harness_enabled"')===false)
    throw new RuntimeException('MCP subplatform switches missing');

$diagnostics=update_diagnostics();
if (($diagnostics['summary']['errors']??-1)!==0)
    throw new RuntimeException('runtime diagnostics returned errors in CI environment: '.json_encode($diagnostics,JSON_UNESCAPED_UNICODE));
if (!array_filter($diagnostics['checks'],static fn($check)=>($check['name']??'')==='MySQL 数据库' && ($check['status']??'')==='ok'))
    throw new RuntimeException('runtime diagnostics did not validate database connection');

ob_start();feature_view('group_bulk');$bulkHtml=ob_get_clean();
if (strpos($bulkHtml,'bulk-option-toggle')===false || strpos($bulkHtml,'bulk-member-count')===false)
    throw new RuntimeException('redesigned group bulk form render failed');
ob_start();feature_view('mobiles');$mobileHtml=ob_get_clean();
if (strpos($mobileHtml,'设备管理')===false || strpos($mobileHtml,'电脑设备')===false ||
    strpos($mobileHtml,'安卓手机')===false || strpos($mobileHtml,'禁止访问')===false ||
    strpos($mobileHtml,'IMEI')===false || strpos($mobileHtml,'手机号')===false)
    throw new RuntimeException('unified device management page render failed');

// Regression: resetting a customer password must commit the new hash, revoke sessions,
// audit the operation, and return the one-time secret even if the later UI refresh fails.
$resetPasswordHash=password_hash_safe('old-reset-password-123');
$pdo->prepare('INSERT INTO phonehub_users(username,password_hash,entitlements) VALUES(?,?,?)')
    ->execute(['phonehub_reset_ci_user',$resetPasswordHash,'["douyin"]']);
$resetUserId=(int)$pdo->lastInsertId();
$pdo->prepare('INSERT INTO phonehub_sessions(user_id,device_id,token_hash,expires_at) VALUES(?,?,?,DATE_ADD(UTC_TIMESTAMP(),INTERVAL 1 HOUR))')
    ->execute([$resetUserId,str_repeat('d',64),hash('sha256','ci-reset-session-token')]);
$resetResult=account_reset_password($resetUserId);
$storedResetHash=(string)$pdo->query("SELECT password_hash FROM phonehub_users WHERE id=".(int)$resetUserId)->fetchColumn();
$remainingSessions=(int)$pdo->query("SELECT COUNT(*) FROM phonehub_sessions WHERE user_id=".(int)$resetUserId)->fetchColumn();
$auditCount=(int)$pdo->query("SELECT COUNT(*) FROM phonehub_admin_audit WHERE action='account_password' AND target='phonehub_reset_ci_user'")->fetchColumn();
if ($resetResult['username']!=='phonehub_reset_ci_user' || !password_verify($resetResult['password'],$storedResetHash) || $remainingSessions!==0 || $auditCount<1)
    throw new RuntimeException('customer password reset regression: hash/session/audit mismatch');
unset($_SESSION['admin_id'],$_SESSION['auth_version'],$_SESSION['admin_user']);
@unlink(APP_STORE.'/config.php');

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
