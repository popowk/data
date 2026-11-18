<?php
declare(strict_types=1);
const APP_ROOT = __DIR__ . '/..';
const APP_STORE = APP_ROOT . '/storage';
// PhoneHub API 1 compatible gateway. This replaces the old /phonehub/api.php only after opt-in.
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
date_default_timezone_set('UTC');
/**
 * Optional sanitized heartbeat performance sampling.
 * Sampling is disabled unless PHONEHUB_PERF_SAMPLE_PERCENT is set to 1..100.
 * The counters measure PHP-only phases, NOT client DNS/TLS or network delivery.
 */
$GLOBALS['phonehub_perf']=[
    'sample'=>false,'started_ns'=>hrtime(true),'connect_ms'=>0.0,
    'auth_ms'=>0.0,'db_ms'=>0.0,'package_ms'=>0.0,
    'response_ms'=>0.0,'queries'=>0
];
function api_perf_phase(string $phase,int $startedNs): void {
    if (empty($GLOBALS['phonehub_perf']['sample'])) return;
    $key=$phase.'_ms';
    if (array_key_exists($key,$GLOBALS['phonehub_perf']))
        $GLOBALS['phonehub_perf'][$key]=(hrtime(true)-$startedNs)/1000000;
}
function api_perf_report(int $status): void {
    $p=$GLOBALS['phonehub_perf']??[];
    if (empty($p['sample'])) return;
    $total=(hrtime(true)-$p['started_ns'])/1000000;
    // No account names, phone IDs, IPs, URLs, payload, tokens or secrets.
    error_log(sprintf(
        'PhoneHub heartbeat_perf status=%d total_ms=%.2f connect_ms=%.2f auth_ms=%.2f db_ms=%.2f package_ms=%.2f response_ms=%.2f queries=%d',
        $status,$total,$p['connect_ms'],$p['auth_ms'],$p['db_ms'],
        $p['package_ms'],$p['response_ms'],$p['queries']
    ));
}
function api_out(array $data,int $status=200): never {
    $started=hrtime(true);
    http_response_code($status);
    echo json_encode($data,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR|JSON_INVALID_UTF8_SUBSTITUTE);
    api_perf_phase('response',$started);
    api_perf_report($status);
    exit;
}
function api_error(string $message,int $code=400): never {api_out(['ok'=>false,'error'=>$message],$code);}
try {
    if (($_GET['action']??'health')==='health') api_out(['ok'=>true,'service'=>'phonehub','api'=>1,'mobile_binding'=>true]);
    $action=(string)($_GET['action']??'health');
    $sampleRate=max(0,min(100,(int)(getenv('PHONEHUB_PERF_SAMPLE_PERCENT')?:0)));
    if ($action==='client_heartbeat' && $sampleRate>0 && random_int(1,100)<=$sampleRate)
        $GLOBALS['phonehub_perf']['sample']=true;
    if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') api_error('仅支持 POST',405);
    if (isset($_SERVER['HTTP_ORIGIN'])) api_error('请通过 PhoneHub 客户端操作',403);
    $maxBody=$action==='ai_chat'?262144:65536;
    if ((int)($_SERVER['CONTENT_LENGTH']??0)>$maxBody) api_error('请求过大',413);
    $raw=file_get_contents('php://input',false,null,0,$maxBody+1);
    if (!is_string($raw) || strlen($raw)>$maxBody) api_error('请求过大',413);
    $input=json_decode($raw,true,32,JSON_THROW_ON_ERROR);
    if (!is_array($input)) api_error('请求格式不正确');
    $cfg=require dirname(__DIR__).'/storage/config.php';
    if (!is_array($cfg)) throw new RuntimeException('database configuration unavailable');
    $connectStarted=hrtime(true);
    $pdo=new PDO('mysql:host='.$cfg['db_host'].';port='.(int)$cfg['db_port'].';dbname='.$cfg['db_name'].';charset=utf8mb4',
        $cfg['db_user'],$cfg['db_pass'],
        [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC,PDO::ATTR_EMULATE_PREPARES=>false]);
    $pdo->exec("SET time_zone = '+00:00'");
    api_perf_phase('connect',$connectStarted);
    function client_sql(string $sql,array $params=[]): PDOStatement {
        global $pdo;
        $started=hrtime(true);
        try {
            $st=$pdo->prepare($sql);
            $st->execute($params);
            return $st;
        } finally {
            if (!empty($GLOBALS['phonehub_perf']['sample'])) {
                $GLOBALS['phonehub_perf']['db_ms']+=(hrtime(true)-$started)/1000000;
                $GLOBALS['phonehub_perf']['queries']++;
            }
        }
    }
    require_once __DIR__.'/extensions.php';
    // Fail closed with a clear recovery error if an old updater missed a
    // newly introduced security module. Never skip blacklist enforcement.
    if (!is_file(dirname(__DIR__).'/app/devices.php'))
        api_out(['ok'=>false,'error'=>'服务器升级不完整：缺少设备安全模块，请联系管理员补齐更新文件','error_code'=>'SERVER_MODULE_MISSING'],503);
    require_once dirname(__DIR__).'/app/devices.php';
    if ($action==='login') {
        $name=(string)($input['username']??'');
        $password=(string)($input['password']??'');
        $device=(string)($input['device_id']??'');
        if (!preg_match('/^[a-zA-Z0-9_-]{3,64}$/D',$name) || !preg_match('/^[a-f0-9]{64}$/D',$device) || strlen($password)>256)
            api_error('登录信息格式不正确');
        $bucket=hash('sha256',strtolower($name).'|'.($_SERVER['REMOTE_ADDR']??''));
        client_sql('DELETE FROM phonehub_login_attempts WHERE attempted_at < DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 HOUR)');
        $attempts=(int)client_sql('SELECT COUNT(*) FROM phonehub_login_attempts WHERE bucket=? AND attempted_at>DATE_SUB(UTC_TIMESTAMP(),INTERVAL 15 MINUTE)',[$bucket])->fetchColumn();
        if ($attempts>=10) api_error('登录尝试过多，请十五分钟后再试',429);
        client_sql('INSERT INTO phonehub_login_attempts(bucket,attempted_at) VALUES(?,UTC_TIMESTAMP())',[$bucket]);
        $account=client_sql('SELECT * FROM phonehub_users WHERE username=?',[$name])->fetch();
        $dummy='$2y$12$Opl.I2mSCM0yvkJqMD4I1eTUpr3Z1dPRqaY51Jcz9OqJRDCqTWX7i';
        if (!password_verify($password,$account['password_hash']??$dummy) || !$account || !(int)$account['enabled'])
            api_error('账号或密码错误，或账号已停用',401);
        if ($account['license_until'] && strtotime($account['license_until'].' UTC')<=time()) api_error('账号授权已到期',403);
        // Only authenticated customers may learn that this computer ID is blocked.
        // Keep login throttling and password verification ahead of the blacklist check.
        if (device_blacklisted_computer($pdo,$device))
            api_error('此电脑已被管理员禁止访问',403);
        $pdo->beginTransaction();
        client_sql('SELECT id FROM phonehub_users WHERE id=? FOR UPDATE',[$account['id']]);
        client_sql('DELETE FROM phonehub_sessions WHERE expires_at<UTC_TIMESTAMP()');
        $used=(int)client_sql('SELECT COUNT(DISTINCT device_id) FROM phonehub_sessions WHERE user_id=? AND device_id<>?',[$account['id'],$device])->fetchColumn();
        if ($used>=(int)$account['device_limit']) {
            // Optional explicit replacement of an existing computer using valid account credentials.
            $replace=(string)($input['replace_device_id']??'');
            if (preg_match('/^[a-f0-9]{64}$/D',$replace) && $replace!==$device) {
                client_sql('DELETE FROM phonehub_sessions WHERE user_id=? AND device_id=?',[$account['id'],$replace]);
                $used=(int)client_sql('SELECT COUNT(DISTINCT device_id) FROM phonehub_sessions WHERE user_id=? AND device_id<>?',[$account['id'],$device])->fetchColumn();
            }
            if ($used>=(int)$account['device_limit']) { $pdo->rollBack();api_error('已超过授权电脑数量，请先在其他电脑退出或指定 replace_device_id',403); }
        }
        client_sql('DELETE FROM phonehub_sessions WHERE user_id=? AND device_id=?',[$account['id'],$device]);
        $token=bin2hex(random_bytes(32));$expires=time()+28800;
        client_sql('INSERT INTO phonehub_sessions(user_id,device_id,token_hash,expires_at) VALUES(?,?,?,?)',
            [$account['id'],$device,hash('sha256',$token),gmdate('Y-m-d H:i:s',$expires)]);
        $pdo->commit();
        client_sql('DELETE FROM phonehub_login_attempts WHERE bucket=?',[$bucket]);
        api_out(['ok'=>true,'token'=>$token,'expires_at'=>$expires,'username'=>$account['username'],
            'license_until'=>$account['license_until'],'entitlements'=>json_decode($account['entitlements'],true)]);
    }
    $authStarted=hrtime(true);
    $header=$_SERVER['HTTP_AUTHORIZATION']??'';
    if (!preg_match('/^Bearer ([a-f0-9]{64})$/D',$header,$match)) api_error('请先登录',401);
    $tokenHash=hash('sha256',$match[1]);
    $session=client_sql('SELECT s.*,u.username,u.enabled,u.license_until,u.entitlements FROM phonehub_sessions s JOIN phonehub_users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>UTC_TIMESTAMP()',[$tokenHash])->fetch();
    if (!$session || !(int)$session['enabled'] || ($session['license_until'] && strtotime($session['license_until'].' UTC')<=time()))
        api_error('登录或授权已失效，请重新登录',401);
    if (!hash_equals($session['device_id'],(string)($input['device_id']??''))) api_error('登录设备不匹配',403);
    if (device_blacklisted_computer($pdo,(string)$session['device_id'])) {
        client_sql('DELETE FROM phonehub_sessions WHERE device_id=?',[$session['device_id']]);
        api_error('此电脑已被管理员禁止访问',403);
    }
    api_perf_phase('auth',$authStarted);
    $userId=(int)$session['user_id'];
    if ($action==='logout') { client_sql('DELETE FROM phonehub_sessions WHERE token_hash=?',[$tokenHash]);api_out(['ok'=>true]); }
    if ($action==='session') api_out(['ok'=>true,'username'=>$session['username'],
        'expires_at'=>strtotime($session['expires_at'].' UTC'),
        'license_until'=>$session['license_until'],'entitlements'=>json_decode($session['entitlements'],true)]);
    if ($action==='password') {
        $old=(string)($input['old_password']??'');$new=(string)($input['new_password']??'');
        if (strlen($new)<12 || strlen($new)>128) api_error('新密码应为 12–128 字节');
        $stored=client_sql('SELECT password_hash FROM phonehub_users WHERE id=?',[$userId])->fetchColumn();
        if (!password_verify($old,(string)$stored)) api_error('原密码错误',403);
        client_sql('UPDATE phonehub_users SET password_hash=? WHERE id=?',[password_hash($new,PASSWORD_ARGON2ID),$userId]);
        client_sql('DELETE FROM phonehub_sessions WHERE user_id=? AND token_hash<>?',[$userId,$tokenHash]);
        api_out(['ok'=>true]);
    }
    if ($action==='mobile_bind') {
        $phone=strtolower((string)($input['phone_id']??''));
        $name=trim((string)($input['display_name']??''));
        $model=trim((string)($input['phone_model']??''));
        if (!preg_match('/^[a-f0-9]{64}$/D',$phone) || strlen($name)>120 ||
            preg_match('/[\x00-\x1F]/',$name) || strlen($model)>120 ||
            preg_match('/[\x00-\x1F]/',$model))
            api_error('手机指纹、备注或型号格式不正确');
        // Legacy clients may still send IMEI/SIM-number keys; ignore them
        // without storing, validating, hashing or echoing any raw values.
        $pdo->beginTransaction();
        $meta=client_sql('SELECT u.id,COALESCE(m.mobile_limit,0) AS mobile_limit FROM phonehub_users u LEFT JOIN phonehub_user_meta m ON m.user_id=u.id WHERE u.id=? FOR UPDATE',[$userId])->fetch();
        $limit=(int)($meta['mobile_limit']??0);
        if ($limit<1) { $pdo->rollBack();api_error('当前授权未启用安卓手机名额',403); }
        $existing=client_sql('SELECT enabled,imei_hash,phone_number_hash FROM phonehub_mobile_devices WHERE user_id=? AND phone_id=? FOR UPDATE',[$userId,$phone])->fetch();
        // Historical bans remain in force for already registered fingerprints,
        // without accepting any new sensitive identifier information.
        if (mobile_blacklist_match($pdo,$phone,$existing['imei_hash']??null,$existing['phone_number_hash']??null)) {
            $pdo->rollBack();api_problem('DEVICE_BLACKLISTED','该手机已被管理员拉黑',403);
        }
        $count=(int)client_sql('SELECT COUNT(*) FROM phonehub_mobile_devices WHERE user_id=? AND enabled=1',[$userId])->fetchColumn();
        if ((!$existing || !(int)$existing['enabled']) && $count >= $limit) {
            $pdo->rollBack();api_error('安卓手机绑定数量已达上限，请联系管理员解绑',403);
        }
        client_sql("INSERT INTO phonehub_mobile_devices(user_id,phone_id,display_name,phone_model,enabled,last_seen)
            VALUES(?,?,?,?,1,UTC_TIMESTAMP()) ON DUPLICATE KEY UPDATE
            display_name=VALUES(display_name),
            phone_model=COALESCE(NULLIF(VALUES(phone_model),''),phone_model),
            enabled=1,last_seen=UTC_TIMESTAMP()",[$userId,$phone,$name,$model]);
        $pdo->commit();
        $active=(int)client_sql('SELECT COUNT(*) FROM phonehub_mobile_devices WHERE user_id=? AND enabled=1',[$userId])->fetchColumn();
        api_out(['ok'=>true,'phone_id'=>$phone,'bound'=>true,'mobile_limit'=>$limit,'active_count'=>$active]);
    }
    if ($action==='mobile_list') {
        $devices=client_sql("SELECT d.phone_id,d.display_name,d.created_at,d.last_seen
            FROM phonehub_mobile_devices d WHERE d.user_id=? AND d.enabled=1
            AND NOT EXISTS (SELECT 1 FROM phonehub_mobile_blacklist b WHERE b.enabled=1 AND
              ((b.identifier_type='phone_id' AND b.identifier_hash=d.phone_id) OR
               (b.identifier_type='imei_hash' AND d.imei_hash IS NOT NULL AND b.identifier_hash=d.imei_hash) OR
               (b.identifier_type='phone_hash' AND d.phone_number_hash IS NOT NULL AND b.identifier_hash=d.phone_number_hash)))
            ORDER BY d.id",[$userId])->fetchAll();
        $limit=(int)client_sql('SELECT COALESCE(m.mobile_limit,0) FROM phonehub_user_meta m WHERE m.user_id=?',[$userId])->fetchColumn();
        api_out(['ok'=>true,'mobile_limit'=>$limit,'active_count'=>count($devices),'devices'=>$devices]);
    }
    require_once __DIR__.'/extensions.php';
    api_extra($action,$input,$session,$userId);
    if ($action==='package') {
        $id=(string)($input['package_id']??'douyin');
        if (!preg_match('/^[a-z0-9-]{1,32}$/D',$id) ||
            !in_array($id,(array)json_decode((string)$session['entitlements'],true),true)) api_error('没有此操作包的授权',403);
        if (in_array($id,['mcp','skill','mcp-codex','mcp-harness'],true)) {
            require_once __DIR__.'/extensions.php';
            api_require_cloud_feature($id,$session);
        }
        $pdo->beginTransaction();
        try {
            client_sql('SELECT id FROM phonehub_users WHERE id=? FOR UPDATE',[$userId])->fetch();
            $meta=client_sql('SELECT COALESCE(m.mobile_limit,0) AS mobile_limit FROM phonehub_user_meta m WHERE m.user_id=?',[$userId])->fetch();
            $bound=api_mobile_quota($userId)['active_count'];
            if ((int)($meta['mobile_limit']??0)<1 || $bound<1) {
                $pdo->rollBack();
                api_error('请先绑定已授权的安卓手机，再下载操作包',403);
            }
            $package=client_sql('SELECT envelope,content_key FROM phonehub_packages WHERE package_id=? AND enabled=1 ORDER BY version DESC LIMIT 1',[$id])->fetch();
            if (!$package) {
                $pdo->rollBack();
                api_error('此平台操作包尚未上架',404);
            }
            client_sql('INSERT INTO phonehub_package_downloads(user_id,package_id,device_id,downloaded_at) VALUES(?,?,?,UTC_TIMESTAMP())',
                [$userId,$id,$session['device_id']]);
            $pdo->commit();
        } catch(Throwable $e) {
            if ($pdo->inTransaction()) $pdo->rollBack();
            throw $e;
        }
        api_out(['ok'=>true,'envelope'=>json_decode((string)$package['envelope'],true),'content_key'=>$package['content_key']]);
    }
    api_error('未知接口',404);
} catch (JsonException $e) {api_error('请求格式不正确');}
catch (Throwable $e) {
    if (isset($pdo) && $pdo instanceof PDO && $pdo->inTransaction()) $pdo->rollBack();
    error_log('PhoneHub API failure: '.get_class($e));
    api_error('服务暂时不可用，请稍后重试',503);
}

function mb_check_encoding_safe(string $value): bool {
    return preg_match('//u',$value)===1;
}
