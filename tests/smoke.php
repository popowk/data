<?php
declare(strict_types=1);
require dirname(__DIR__).'/app/core.php';
require dirname(__DIR__).'/app/ai.php';
require dirname(__DIR__).'/app/mobile.php';
require dirname(__DIR__).'/app/releases.php';
require_once dirname(__DIR__).'/app/release_admin.php';
require dirname(__DIR__).'/app/accounts.php';
require_once dirname(__DIR__).'/app/features.php';
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
$planTable=(int)$pdo->query("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='phonehub_plan_templates'")->fetchColumn();
if($planTable!==1) throw new RuntimeException('plan migration table missing');
if((int)$pdo->query("SELECT MAX(version) FROM phonehub_admin_migrations")->fetchColumn()!==15)
    throw new RuntimeException('performance sample migration version incorrect');
$defaultScrcpy=$pdo->query("SELECT download_url FROM phonehub_download_settings WHERE resource='scrcpy'")->fetchColumn();
if($defaultScrcpy!==SCRCPY_DEFAULT_DOWNLOAD_URL)
    throw new RuntimeException('scrcpy download default is missing');
$defaultMain=$pdo->query("SELECT download_url FROM phonehub_download_settings WHERE resource='main_program'")->fetchColumn();
if($defaultMain!==MAIN_PROGRAM_DEFAULT_DOWNLOAD_URL)
    throw new RuntimeException('main program URL placeholder is missing');
$pdo->exec("UPDATE phonehub_download_settings SET download_url='https://example.com/custom-scrcpy.zip' WHERE resource='scrcpy'");
$pdo->exec("DELETE FROM phonehub_admin_migrations WHERE version>=13");
migrate($pdo);
if($pdo->query("SELECT download_url FROM phonehub_download_settings WHERE resource='scrcpy'")->fetchColumn()!=='https://example.com/custom-scrcpy.zip')
    throw new RuntimeException('main program migration overwrote administrator scrcpy URL');
$pdo->exec("UPDATE phonehub_download_settings SET download_url='".SCRCPY_DEFAULT_DOWNLOAD_URL."' WHERE resource='scrcpy'");
migrate($pdo);
if((int)$pdo->query("SELECT COUNT(*) FROM phonehub_download_settings WHERE resource='scrcpy'")->fetchColumn()!==1)
    throw new RuntimeException('scrcpy migration seeded duplicate rows');
if((int)$pdo->query("SELECT COUNT(*) FROM phonehub_download_settings WHERE resource='main_program'")->fetchColumn()!==1)
    throw new RuntimeException('main program migration seeded duplicate rows');
if((int)$pdo->query("SELECT MAX(version) FROM phonehub_admin_migrations")->fetchColumn()!==15)
    throw new RuntimeException('performance sample migration failed');
$replacementColumns=$pdo->query("SELECT COLUMN_NAME FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='phonehub_computer_replacement_events'")->fetchAll(PDO::FETCH_COLUMN);
foreach (['id','user_id','replaced_count','created_at'] as $needed)
    if(!in_array($needed,$replacementColumns,true))
        throw new RuntimeException('missing replacement audit field '.$needed);
if(array_intersect($replacementColumns,['device_id','token_hash','ip_address','source_ip']))
    throw new RuntimeException('replacement event table contains private device or token fields');
migrate($pdo);
if((int)$pdo->query("SELECT COUNT(*) FROM phonehub_admin_migrations WHERE version=14")->fetchColumn()!==1)
    throw new RuntimeException('computer replacement audit migration is not idempotent');
$perfColumns=$pdo->query("SELECT COLUMN_NAME FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='phonehub_api_perf_samples'")->fetchAll(PDO::FETCH_COLUMN);
foreach (['id','action','http_status','total_ms','db_ms','query_count','created_at'] as $field)
    if(!in_array($field,$perfColumns,true))
        throw new RuntimeException('performance telemetry field missing: '.$field);
if(array_intersect($perfColumns,['device_id','user_id','ip','token','request_body']))
    throw new RuntimeException('performance telemetry table contains forbidden personal fields');
migrate($pdo);
if((int)$pdo->query("SELECT COUNT(*) FROM phonehub_admin_migrations WHERE version=15")->fetchColumn()!==1)
    throw new RuntimeException('performance telemetry migration is not idempotent');
foreach (['https://example.com/PhoneHub.exe','https://example.com/PhoneHub.msi',
          MAIN_PROGRAM_DEFAULT_DOWNLOAD_URL] as $validMain) {
    if(main_program_validate_download_url($validMain)!==$validMain)
        throw new RuntimeException('main program executable URL was rejected');
}
foreach (['http://example.com/PhoneHub.exe','https://127.0.0.1/PhoneHub.exe',
          'https://example.com/PhoneHub.bat','https://user:pass@example.com/PhoneHub.msi'] as $badMain) {
    try { main_program_validate_download_url($badMain); }
    catch (RuntimeException $e) { continue; }
    throw new RuntimeException('unsafe main program URL was accepted');
}
foreach ([
    'http://down.tmd.pet/scrcpy/download.zip',
    'https://127.0.0.1/scrcpy.zip',
    'https://localhost/scrcpy.zip',
    'https://user:pass@example.com/scrcpy.zip',
    'https://example.com/scrcpy.exe',
    'https://example.com/scrcpy.zip#unsafe',
    "https://example.com/scrcpy.zip\\r\\nInjected"
] as $bad) {
    try {scrcpy_validate_download_url($bad);}
    catch (RuntimeException $e) {continue;}
    throw new RuntimeException('unsafe download URL was accepted: '.$bad);
}
if(scrcpy_validate_download_url(SCRCPY_DEFAULT_DOWNLOAD_URL)!==SCRCPY_DEFAULT_DOWNLOAD_URL)
    throw new RuntimeException('default scrcpy URL failed validation');
foreach(['phonehub_automation_tokens','phonehub_automation_releases',
         'phonehub_automation_rate','phonehub_automation_audit'] as $table) {
    $q=$pdo->prepare('SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?');
    $q->execute([$table]);
    if ((int)$q->fetchColumn()!==1) throw new RuntimeException('automation schema missing: '.$table);
}
$openingPlans=phonehub_opening_plans(true,$pdo);
if (count($openingPlans)!==3 || $openingPlans['personal']['device_limit']!==1 ||
    $openingPlans['standard']['mobile_limit']!==5 || $openingPlans['team']['device_limit']!==10 ||
    phonehub_plan_label(null)!=='原有授权')
    throw new RuntimeException('opening plan presets invalid');
// Protected root owner and two selectable administrator roles, deny by default.
// Legacy viewer accounts retain readonly permissions until explicitly reassigned.
$allowedViews=[
    'owner'=>['dashboard','accounts','groups','group_bulk','devices','packages',
      'plans','backup_keys','client_logs','releases','ai','update',
      'admins','audit','cloud_features'],
    'global'=>['dashboard','accounts','groups','group_bulk','devices','packages',
      'plans','backup_keys','client_logs','releases','ai','update',
      'admins','audit','cloud_features'],
    'admin'=>['accounts','devices','plans','client_logs'],
    'viewer'=>['dashboard','accounts','groups','packages']
];
foreach ($allowedViews as $role=>$allowed)
    foreach ($allowedViews['owner'] as $page)
        if (phonehub_role_can_view($role,$page)!==in_array($page,$allowed,true))
            throw new RuntimeException('role page policy failed: '.$role.' / '.$page);
foreach (['owner','global','admin','viewer','not_a_role'] as $role)
    if (phonehub_role_can_view($role,'unregistered_view') ||
        phonehub_role_can_action($role,'unregistered_action'))
        throw new RuntimeException('unknown backend permission was granted');
foreach (['admin','viewer','not_a_role'] as $role)
    foreach (['group_create','group_bulk_preview','release_publish','backup_key_generate',
        'update_apply','admin_create','admin_role_change','automation_token_create',
        'cloud_features_save','main_program_url_save'] as $action)
        if (phonehub_role_can_action($role,$action))
            throw new RuntimeException('staff operator can use '.$action);
foreach (['global','admin','viewer','not_a_role'] as $role)
    foreach (['signing_generate','signing_activate','backup_key_generate','update_apply',
        'admin_create','admin_role_change','automation_token_rotate',
        'automation_release_approve','owner_password','device_reveal'] as $action)
        if (phonehub_role_can_action($role,$action))
            throw new RuntimeException('non-owner may change protected operation: '.$role.' / '.$action);
foreach (['account_save','plan_save','plan_toggle','mobile_revoke',
    'device_blacklist_add','mobile_blacklist','mobile_unblacklist'] as $action)
    if (!phonehub_role_can_action('admin',$action))
        throw new RuntimeException('ordinary admin missing '.$action);
foreach (['release_publish','cloud_features_save','update_check','update_diagnostics',
    'group_bulk','ai_settings_save','main_program_url_save'] as $action)
    if (!phonehub_role_can_action('global',$action))
        throw new RuntimeException('global admin missing '.$action);
if (!phonehub_role_can_action('viewer','logout') ||
    phonehub_role_can_action('viewer','account_save') ||
    !phonehub_role_can_action('owner','backup_key_generate') ||
    phonehub_role_label('owner')!=='全局管理员（主账号）' ||
    phonehub_role_label('viewer')!=='历史只读管理员')
    throw new RuntimeException('role action policy mismatch');
if (phonehub_role_can_view('owner','gateway') || phonehub_role_can_action('owner','gateway_install'))
    throw new RuntimeException('retired client API takeover route/action remains enabled');
if (function_exists('gateway_status') || function_exists('gateway_install'))
    throw new RuntimeException('retired client API gateway functions remain available');
// Apache-only fallback: updating this file does not configure Nginx.
$apacheRules=(string)file_get_contents(dirname(__DIR__).'/.htaccess');
if (!str_contains($apacheRules,'RewriteRule ^storage(/|$) - [F,L]') ||
    !str_contains($apacheRules,'Require all denied'))
    throw new RuntimeException('Apache storage route protection missing');
// Parameterized filters: input cannot turn into SQL clauses or LIKE wildcards.
$filter=phonehub_account_filters([
  'q'=>'ci_test_01','group'=>'none','status'=>'enabled',
  'expiry'=>'due7','plan'=>'personal','page'=>'999999999'
]);
if ($filter['page']!==1 || $filter['group']!=='none' ||
    $filter['params']!==['%ci!_test!_01%','personal'] ||
    !str_contains($filter['where'],"LIKE ? ESCAPE '!'") ||
    !str_contains($filter['where'],'m.group_id IS NULL') ||
    !str_contains($filter['where'],'m.opening_plan_code=?') ||
    !str_contains($filter['where'],'INTERVAL 7 DAY'))
    throw new RuntimeException('safe account filtering invalid');
$filter=phonehub_account_filters([
  'q'=>['bad'],'group'=>'0 OR 1=1','status'=>'bad',
  'expiry'=>'bad','plan'=>'untrusted!','page'=>'-1'
]);
if ($filter['params']!==[] || $filter['where']!=='' || $filter['page']!==1)
    throw new RuntimeException('invalid account filter accepted');
// Client log filtering must stay parameterized, bounded and literal for '%'
// and '_' in usernames / error messages. Only level=error is text-searched.
$logs=phonehub_client_log_filters([
    'q'=>'CI_log%!', 'search_by'=>'all','page'=>'2'
]);
if ($logs['page']!==2 || $logs['search_by']!=='all' ||
    $logs['params']!==array_fill(0,3,'%CI!_log!%!!%') ||
    !str_contains($logs['where'],"l.level='error'") ||
    !str_contains($logs['where'],"LIKE ? ESCAPE '!'"))
    throw new RuntimeException('client log combined search is not literal or safely parameterized');
$logs=phonehub_client_log_filters(['q'=>'my_error','search_by'=>'error','page'=>'999999999']);
if ($logs['page']!==1 || $logs['params']!==['%my!_error%','%my!_error%'] ||
    !str_starts_with($logs['where']," WHERE l.level='error' AND "))
    throw new RuntimeException('client error log scope or page validation invalid');
$logs=phonehub_client_log_filters(['search_by'=>'error']);
if ($logs['where']!==" WHERE l.level='error'" || $logs['params']!==[])
    throw new RuntimeException('error-only log filter must support a blank query');
$logs=phonehub_client_log_filters(['q'=>'abc','search_by'=>'username','page'=>'21']);
if ($logs['where']!==" WHERE u.username LIKE ? ESCAPE '!'" ||
    $logs['params']!==['%abc%'] || $logs['page']!==21)
    throw new RuntimeException('username-only client log filter invalid');
$logs=phonehub_client_log_filters(['q'=>['malicious'],'search_by'=>['error'],'page'=>['1']]);
if ($logs['q']!=='' || $logs['search_by']!=='all' || $logs['page']!==1 ||
    $logs['where']!=='' || $logs['params']!==[])
    throw new RuntimeException('malformed client log GET arrays must be ignored');
$logs=phonehub_client_log_filters(['q'=>str_repeat('a',400),'search_by'=>'username']);
if (utf8_length($logs['q'])!==160) throw new RuntimeException('client log search is not bounded');

// Regression: editing/stopping an opening template must not mutate an existing
// customer's stored quotas or opening label. Disabled plans must not be offered
// to newly created customers, but historical template lookup must still work.
$pdo->beginTransaction();
try {
    $pdo->exec("INSERT INTO phonehub_plan_templates(plan_code,name,device_limit,mobile_limit,enabled,sort_order)
        VALUES('ci_plan_fixture','测试套餐',2,4,1,15)");
    $active=phonehub_opening_plans(true,$pdo);
    if (count($active)!==4 || !isset($active['ci_plan_fixture']) ||
        array_keys($active)!==['personal','ci_plan_fixture','standard','team'])
        throw new RuntimeException('new plan template not available or plan sorting incorrect');

    $pdo->exec("INSERT INTO phonehub_users(username,password_hash,device_limit,entitlements)
        VALUES('ci_plan_fixture','test-hash',2,'[\"douyin\"]')");
    $userId=(int)$pdo->lastInsertId();
    $pdo->prepare('INSERT INTO phonehub_user_meta(user_id,mobile_limit,opening_plan_code) VALUES(?,?,?)')
        ->execute([$userId,4,'ci_plan_fixture']);

    $pdo->exec("UPDATE phonehub_plan_templates
        SET name='测试套餐（已修改）',device_limit=99,mobile_limit=88,enabled=0
        WHERE plan_code='ci_plan_fixture'");
    $active=phonehub_opening_plans(true,$pdo);
    $all=phonehub_opening_plans(false,$pdo);
    if (isset($active['ci_plan_fixture']) || ($all['ci_plan_fixture']['device_limit']??null)!==99 ||
        ($all['ci_plan_fixture']['mobile_limit']??null)!==88 ||
        ($all['ci_plan_fixture']['label']??null)!=='测试套餐（已修改）')
        throw new RuntimeException('disabled/edited plan template visibility incorrect');
    $snapshot=$pdo->query("SELECT u.device_limit,m.mobile_limit,m.opening_plan_code
        FROM phonehub_users u JOIN phonehub_user_meta m ON m.user_id=u.id
        WHERE u.username='ci_plan_fixture'")->fetch(PDO::FETCH_ASSOC);
    if ((int)($snapshot['device_limit']??0)!==2 ||
        (int)($snapshot['mobile_limit']??0)!==4 ||
        ($snapshot['opening_plan_code']??null)!=='ci_plan_fixture')
        throw new RuntimeException('editing/stopping a plan unexpectedly mutated prior account entitlements');
    $pdo->exec("UPDATE phonehub_plan_templates SET enabled=1 WHERE plan_code='ci_plan_fixture'");
    if (!isset(phonehub_opening_plans(true,$pdo)['ci_plan_fixture']))
        throw new RuntimeException('re-enabled plan template not visible');
} finally {
    if ($pdo->inTransaction()) $pdo->rollBack();
}
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
// Historical DB columns are left intact for rollback compatibility, but
// no new IMEI/SIM-number data is accepted or hashed anywhere in the API.
require_once dirname(__DIR__).'/app/devices.php';
$phoneId=str_repeat('c',64);
$legacyHash=hash('sha256','preexisting-hmac-fixture');
$pdo->prepare("INSERT INTO phonehub_mobile_blacklist(identifier_type,identifier_hash,reason,enabled,created_by) VALUES('imei_hash',?,?,1,0)")
    ->execute([$legacyHash,'historical device ban']);
if (!mobile_blacklist_match($pdo,$phoneId,$legacyHash))
    throw new RuntimeException('historical recorded bans must still protect existing devices');
$legacyNewRejected=false;
try {device_insert_blacklist($pdo,'imei_hash',$legacyHash,'forbidden new sensitive ban',0);}
catch(RuntimeException $e) {$legacyNewRejected=true;}
if (!$legacyNewRejected) throw new RuntimeException('new sensitive blacklist entry was accepted');
$phoneIdBan=str_repeat('e',64);
device_insert_blacklist($pdo,'phone_id',$phoneIdBan,'CI phone fingerprint block',0);
if(!mobile_blacklist_match($pdo,$phoneIdBan,null))
    throw new RuntimeException('phone fingerprint blacklist lookup failed');
if (function_exists('mobile_imei_hash') || function_exists('device_decrypt') ||
    function_exists('device_phone_hash'))
    throw new RuntimeException('retired sensitive identifier helpers remain callable');
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
require_once dirname(__DIR__).'/app/features.php';
if (phonehub_group_member_snapshot(['1','2'])!==phonehub_group_member_snapshot([1,2]) ||
    phonehub_group_member_snapshot([1,2])===phonehub_group_member_snapshot([1,3]))
    throw new RuntimeException('group bulk preview membership fingerprint invalid');
ob_start();feature_view('cloud_features');$cloudHtml=ob_get_clean();
if (strpos($cloudHtml,'MCP 连接能力')===false || strpos($cloudHtml,'Skill 技能能力')===false)
    throw new RuntimeException('cloud feature control page render failed');
if (strpos($cloudHtml,'cloud-feature-card')===false || strpos($cloudHtml,'cloud-savebar')===false)
    throw new RuntimeException('redesigned cloud feature controls missing');
if (strpos($cloudHtml,'name="mcp_codex_enabled"')===false ||
    strpos($cloudHtml,'name="mcp_harness_enabled"')===false)
    throw new RuntimeException('MCP subplatform switches missing');
if (strpos($cloudHtml,'AI 接口设置')===false ||
    strpos($cloudHtml,'data-ajax="ai_settings_save"')===false ||
    strpos($cloudHtml,'服务端 AI 中转')===false)
    throw new RuntimeException('AI settings were not embedded in client capability view');
// Encrypted package input is structurally checked; no content key may ever
// appear in management pages, audit or POST success responses.
$operationEnvelope=[
    'manifest'=>base64_encode('{"format":1,"platform":"ci-ops"}'),
    'signature'=>base64_encode(random_bytes(64)),
    'nonce'=>base64_encode(random_bytes(24)),
    'ciphertext'=>base64_encode(random_bytes(64))
];
$operationSecret=base64_encode(random_bytes(32));
$operationJson=json_encode(['package_id'=>'ci-ops','version'=>1,
    'envelope'=>$operationEnvelope,'content_key'=>$operationSecret],JSON_THROW_ON_ERROR);
$decodedOperation=operation_package_decode($operationJson,'ci-ops',1);
if (json_decode($decodedOperation['envelope'],true)!==$operationEnvelope ||
    $decodedOperation['content_key']!==$operationSecret)
    throw new RuntimeException('encrypted operation envelope did not round trip');
foreach ([
    ['envelope'=>['manifest'=>'bad!','signature'=>'a','nonce'=>'b','ciphertext'=>'c'],'content_key'=>$operationSecret],
    ['envelope'=>$operationEnvelope,'content_key'=>'invalid-key'],
    ['envelope'=>$operationEnvelope],
    ['envelope'=>$operationEnvelope,'content_key'=>$operationSecret,'unknown'=>'leak'],
] as $bad) {
    try {operation_package_decode(json_encode($bad,JSON_THROW_ON_ERROR),'ci-ops',1);
         throw new RuntimeException('invalid package unexpectedly accepted');}
    catch(RuntimeException $e) {
        if ($e->getMessage()==='invalid package unexpectedly accepted') throw $e;
    }
}
try {operation_package_decode($operationJson,'different-package',1);throw new RuntimeException('mismatched package ID accepted');}
catch(RuntimeException $e) {if ($e->getMessage()==='mismatched package ID accepted')throw $e;}
try {operation_package_decode($operationJson,'ci-ops',2);throw new RuntimeException('mismatched package version accepted');}
catch(RuntimeException $e) {if ($e->getMessage()==='mismatched package version accepted')throw $e;}
$publishedOperation=operation_package_publish_record('ci-ops',1,$operationJson);
if ($publishedOperation['version']!==1 || isset($publishedOperation['content_key']) ||
    isset($publishedOperation['envelope']))
    throw new RuntimeException('published operation response exposed secret');
try {operation_package_publish_record('ci-ops',1,$operationJson);throw new RuntimeException('duplicate package accepted');}
catch(RuntimeException $e) {if ($e->getMessage()==='duplicate package accepted')throw $e;}
$disabledOperation=operation_package_toggle($publishedOperation['id']);
if ($disabledOperation['enabled']!==0)throw new RuntimeException('package toggle did not disable');
$enabledOperation=operation_package_toggle($publishedOperation['id']);
if ($enabledOperation['enabled']!==1)throw new RuntimeException('package toggle did not restore');
$storedOperation=$pdo->query("SELECT envelope,content_key FROM phonehub_packages WHERE package_id='ci-ops' AND version=1")->fetch(PDO::FETCH_ASSOC);
if ($storedOperation['content_key']!==$operationSecret ||
    json_decode($storedOperation['envelope'],true)!==$operationEnvelope)
    throw new RuntimeException('encrypted operation package storage failed');
ob_start();release_package_overview();$packageHtml=ob_get_clean();
if (strpos($packageHtml,'操作包管理中心')===false ||
    strpos($packageHtml,'legacy-operation-packages')===false ||
    strpos($packageHtml,'data-ajax="package_publish"')===false)
    throw new RuntimeException('encrypted operation package manager missing from merged release module');
if (str_contains($packageHtml,$operationSecret) ||
    str_contains($packageHtml,$operationEnvelope['ciphertext']))
    throw new RuntimeException('operation package management leaked encrypted payload or key');

$diagnostics=update_diagnostics();
if (($diagnostics['summary']['errors']??-1)!==0)
    throw new RuntimeException('runtime diagnostics returned errors in CI environment: '.json_encode($diagnostics,JSON_UNESCAPED_UNICODE));
if (!array_filter($diagnostics['checks'],static fn($check)=>($check['name']??'')==='MySQL 数据库' && ($check['status']??'')==='ok'))
    throw new RuntimeException('runtime diagnostics did not validate database connection');
if (phonehub_role_can_view('owner','diagnostics') || phonehub_role_can_action('owner','diagnostic_report'))
    throw new RuntimeException('removed diagnostic page/action is still accessible');

ob_start();feature_view('group_bulk',true);$mergedBulkHtml=ob_get_clean();
if (!str_contains($mergedBulkHtml,'id="group-bulk"') ||
    !str_contains($mergedBulkHtml,'id="group-bulk-form"') ||
    str_contains($mergedBulkHtml,'<h1>分组批量配置</h1>'))
    throw new RuntimeException('embedded group batch management panel missing or duplicates page title');
ob_start();backup_admin_view(true);$embeddedBackupHtml=ob_get_clean();
if (!str_contains($embeddedBackupHtml,'id="maintenance-backup"') ||
    !str_contains($embeddedBackupHtml,'Curve25519') ||
    str_contains($embeddedBackupHtml,'<h1>备份密钥管理</h1>'))
    throw new RuntimeException('embedded backup key panel missing or duplicates page title');
ob_start();feature_view('group_bulk');$bulkHtml=ob_get_clean();
if (strpos($bulkHtml,'bulk-option-toggle')===false || strpos($bulkHtml,'bulk-member-count')===false ||
    strpos($bulkHtml,'先由服务器预检')===false)
    throw new RuntimeException('redesigned group bulk form render failed');
// Device lists now load only the selected category; check each page separately.
$_GET['device_tab']='computers';
ob_start();feature_view('mobiles');$computerHtml=ob_get_clean();
$_GET['device_tab']='mobiles';
ob_start();feature_view('mobiles');$mobileHtml=ob_get_clean();
$_GET['device_tab']='blacklist';
ob_start();feature_view('mobiles');$blacklistHtml=ob_get_clean();
unset($_GET['device_tab']);
if (strpos($computerHtml,'设备管理')===false || strpos($computerHtml,'电脑设备')===false ||
    strpos($computerHtml,'安卓手机')===false || strpos($computerHtml,'禁止访问')===false ||
    strpos($computerHtml,'device-search-form')===false ||
    strpos($computerHtml,'电脑设备与会话')===false ||
    strpos($mobileHtml,'<th>状态</th>')===false ||
    strpos($mobileHtml,'手机指纹')===false ||
    strpos($blacklistHtml,'有效禁止访问记录')===false)
    throw new RuntimeException('paginated device management category render failed');
if (strpos($mobileHtml,'<th>IMEI</th>')!==false || strpos($mobileHtml,'<th>手机号</th>')!==false ||
    strpos($mobileHtml,'name="imei"')!==false || strpos($mobileHtml,'name="phone_number"')!==false ||
    strpos($mobileHtml,'device-reveal')!==false || strpos($mobileHtml,'value="imei_hash"')!==false)
    throw new RuntimeException('removed sensitive device management controls still rendered');

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
