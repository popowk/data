<?php
declare(strict_types=1);
require_once dirname(__DIR__).'/app/releases.php';
require_once dirname(__DIR__).'/app/ai.php';
require_once dirname(__DIR__).'/app/mobile.php';

function api_problem(string $code,string $message,int $status=400): never {
    api_out(['ok'=>false,'error'=>$message,'error_code'=>$code],$status);
}
function api_int(mixed $value,int $minimum=1): int {
    if (is_int($value) && $value>=$minimum) return $value;
    if (is_string($value) && preg_match('/^[0-9]{1,16}$/D',$value) && (int)$value>=$minimum) return (int)$value;
    api_problem('INVALID_PARAMETER','整数参数不正确');
}
function api_phone(string $value): string {
    $id=strtolower($value);
    if (!preg_match('/^[0-9a-f]{64}$/D',$id)) api_problem('INVALID_PHONE_ID','手机标识必须为 SHA-256 小写十六进制文本');
    return $id;
}
function api_mobile_quota(int $userId): array {
    $meta=client_sql('SELECT COALESCE(m.mobile_limit,0) AS lim FROM phonehub_user_meta m WHERE m.user_id=?',[$userId])->fetch();
    $count=(int)client_sql("SELECT COUNT(*) FROM phonehub_mobile_devices d WHERE d.user_id=? AND d.enabled=1
        AND NOT EXISTS (SELECT 1 FROM phonehub_mobile_blacklist b WHERE b.enabled=1 AND
          ((b.identifier_type='phone_id' AND b.identifier_hash=d.phone_id) OR
           (b.identifier_type='imei_hash' AND d.imei_hash IS NOT NULL AND b.identifier_hash=d.imei_hash) OR
           (b.identifier_type='phone_hash' AND d.phone_number_hash IS NOT NULL AND b.identifier_hash=d.phone_number_hash)))",[$userId])->fetchColumn();
    return ['mobile_limit'=>(int)($meta['lim']??0),'active_count'=>$count];
}
/**
 * Read the four current global feature gates in one DB query per heartbeat.
 * This is request-local only: never cache a revoked privilege across checks.
 */
function api_cloud_feature_flags(): array {
    $rows=client_sql("SELECT setting_key,setting_value FROM phonehub_feature_settings
        WHERE setting_key IN ('mcp_enabled','skill_enabled','mcp_codex_enabled','mcp_harness_enabled')")->fetchAll();
    $settings=[];
    foreach ($rows as $row) $settings[(string)$row['setting_key']]=(string)$row['setting_value']==='1';
    $mcp=!empty($settings['mcp_enabled']);
    return [
        'mcp'=>$mcp,
        'skill'=>!empty($settings['skill_enabled']),
        'mcp-codex'=>$mcp && !empty($settings['mcp_codex_enabled']),
        'mcp-harness'=>$mcp && !empty($settings['mcp_harness_enabled'])
    ];
}
function api_cloud_feature_enabled(string $feature): bool {
    if (!in_array($feature,['mcp','skill','mcp-codex','mcp-harness'],true)) return false;
    if (in_array($feature,['mcp-codex','mcp-harness'],true) &&
        client_sql('SELECT setting_value FROM phonehub_feature_settings WHERE setting_key=?',['mcp_enabled'])->fetchColumn()!=='1')
        return false;
    $flag=['mcp-codex'=>'mcp_codex_enabled','mcp-harness'=>'mcp_harness_enabled'][$feature]??($feature.'_enabled');
    return client_sql('SELECT setting_value FROM phonehub_feature_settings WHERE setting_key=?',[$flag])->fetchColumn()==='1';
}
function api_true_features(array $flags): array {
    // Capability discovery is positive-only. Absence means no usable capability.
    // Do not apply this to protocol booleans such as ok/bound/available:
    // callers rely on their explicit states and the server always enforces policy.
    return array_filter($flags,static fn($allowed): bool => $allowed === true);
}
function api_require_cloud_feature(string $feature,array $session): void {
    if (!api_cloud_feature_enabled($feature))
        api_problem('FEATURE_DISABLED',strtoupper($feature).' 当前由管理员在云端禁用',403);
    $allowed=json_decode((string)$session['entitlements'],true);
    if (!in_array($feature,is_array($allowed)?$allowed:[],true) ||
        (in_array($feature,['mcp-codex','mcp-harness'],true) && !in_array('mcp',is_array($allowed)?$allowed:[],true)))
        api_problem('NOT_ENTITLED','当前客户未获授权使用 '.strtoupper($feature),403);
}
function api_redact(string $message): string {
    $message=preg_replace('/Bearer\s+[a-f0-9]{64}/i','Bearer [REDACTED]',$message) ?? $message;
    $message=preg_replace('/\b(password|passwd|token|secret|authorization|api[_-]?key)\s*[:=]\s*[^\s,;]+/i','$1=[REDACTED]',$message) ?? $message;
    return $message;
}
function api_clean_log_entry(array $entry): array {
    $level=(string)($entry['level']??'info');
    $event=(string)($entry['event']??'general');
    $message=(string)($entry['message']??'');
    if (!in_array($level,['debug','info','warn','error'],true) || !preg_match('/^[A-Za-z0-9_.-]{1,64}$/D',$event)
        || strlen($message)>2000 || $message==='' || preg_match('//u',$message)!==1)
        api_problem('INVALID_LOG','日志级别、事件名称或内容不正确');
    return [$level,$event,api_redact($message)];
}
function api_store_logs(array $records,int $userId,string $device): never {
    if (count($records)<1 || count($records)>50) api_problem('INVALID_LOG_BATCH','每批次需上传 1–50 条日志');
    $clean=[];
    foreach($records as $entry) {
        if (!is_array($entry)) api_problem('INVALID_LOG','日志项目结构不正确');
        $clean[]=api_clean_log_entry($entry);
    }
    global $pdo;
    $pdo->beginTransaction();
    try {
        client_sql('SELECT id FROM phonehub_users WHERE id=? FOR UPDATE',[$userId])->fetch();
        $used=(int)client_sql('SELECT COUNT(*) FROM phonehub_client_logs WHERE user_id=? AND created_at>DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 HOUR)',[$userId])->fetchColumn();
        if ($used+count($clean)>1000) {
            $pdo->rollBack();
            api_problem('LOG_RATE_LIMIT','日志已达到每小时 1000 条上限',429);
        }
        foreach($clean as [$level,$event,$message]) {
            client_sql('INSERT INTO phonehub_client_logs(user_id,device_id,level,event,message,created_at) VALUES(?,?,?,?,?,UTC_TIMESTAMP())',
                [$userId,$device,$level,$event,$message]);
        }
        $pdo->commit();
    } catch(Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        throw $e;
    }
    api_out(['ok'=>true,'received'=>count($clean)]);
}
function api_require_release_permission(array $release,array $session): void {
    if (in_array($release['platform'],['mcp','skill','mcp-codex','mcp-harness'],true))
        api_require_cloud_feature($release['platform'],$session);
    $allowed=json_decode((string)$session['entitlements'],true);
    if ($release['platform']!=='core' && !in_array($release['platform'],is_array($allowed)?$allowed:[],true))
        api_problem('NOT_ENTITLED','当前客户没有此更新包的权限',403);
}
function api_latest_release(string $platform,string $channel): ?array {
    $rows=client_sql('SELECT * FROM phonehub_releases WHERE platform=? AND channel=? AND enabled=1 ORDER BY id DESC LIMIT 500',[$platform,$channel])->fetchAll();
    usort($rows,static fn($a,$b)=>version_compare($b['version'],$a['version']));
    return $rows[0]??null;
}
/**
 * Optional heartbeat aggregation. Input is advisory only: every identity,
 * entitlement, package and quota decision comes from current database state.
 * This never returns a package envelope, content key, upstream API key, or
 * mobile identity HMAC/encrypted original.
 */
function api_heartbeat_batch(array $batch,array $session,int $userId,array $quota,array $cloudFlags=[]): array {
    global $pdo;
    if (array_diff(array_keys($batch),['phones','package_versions']))
        api_problem('INVALID_HEARTBEAT_BATCH','批量心跳包含未知字段');
    $phones=$batch['phones']??[];
    $versions=$batch['package_versions']??[];
    if (!is_array($phones) || !array_is_list($phones) || count($phones)>8)
        api_problem('HEARTBEAT_BATCH_LIMIT','单次最多检查 8 台手机');
    if (!is_array($versions) || count($versions)>16 ||
        ($versions!==[] && array_is_list($versions)))
        api_problem('HEARTBEAT_BATCH_LIMIT','单次最多提交 16 个包版本');
    foreach ($versions as $packageId=>$version) {
        if (!is_string($packageId) || !preg_match('/^[a-z0-9-]{1,32}$/D',$packageId) ||
            !(is_int($version) && $version>=0 && $version<=2147483647))
            api_problem('INVALID_PACKAGE_VERSION','客户端包版本格式错误');
    }
    $requests=[];$ids=[];
    foreach ($phones as $phone) {
        if (!is_array($phone) || array_is_list($phone) ||
            array_diff(array_keys($phone),['phone_id','imei','phone_number']) ||
            !is_string($phone['phone_id']??null))
            api_problem('INVALID_HEARTBEAT_PHONE','手机检查项结构不正确');
        $id=api_phone($phone['phone_id']);
        if (isset($requests[$id])) api_problem('DUPLICATE_PHONE_ID','不能重复检查同一手机');
        // Legacy identity fields are deliberately ignored for old clients.
        // They are no longer validated, hashed, stored, or returned.
        $requests[$id]=true;
        $ids[]=$id;
    }

    $records=[];
    if ($ids) {
        $placeholders=implode(',',array_fill(0,count($ids),'?'));
        $rows=client_sql('SELECT id,phone_id,enabled,imei_hash,phone_number_hash
            FROM phonehub_mobile_devices WHERE user_id=? AND phone_id IN ('.$placeholders.')',
            array_merge([$userId],$ids))->fetchAll();
        foreach ($rows as $row) $records[(string)$row['phone_id']]=$row;
    }
    // Preserve the exact oldest-eligible-device rule of mobile_check:
    // disabled/blacklisted entries consume no quota; newer excess entries are
    // not authorized even when an earlier valid binding exists.
    $eligibleRows=$ids?client_sql("SELECT d.id FROM phonehub_mobile_devices d
        WHERE d.user_id=? AND d.enabled=1 AND NOT EXISTS (
          SELECT 1 FROM phonehub_mobile_blacklist b WHERE b.enabled=1 AND (
            (b.identifier_type='phone_id' AND b.identifier_hash=d.phone_id) OR
            (b.identifier_type='imei_hash' AND d.imei_hash IS NOT NULL AND b.identifier_hash=d.imei_hash) OR
            (b.identifier_type='phone_hash' AND d.phone_number_hash IS NOT NULL AND b.identifier_hash=d.phone_number_hash)
          )
        ) ORDER BY d.id LIMIT 1000",[$userId])->fetchAll(PDO::FETCH_COLUMN):[];
    $withinQuota=[];
    foreach (array_slice($eligibleRows,0,max(0,min(1000,(int)$quota['mobile_limit']))) as $dbId)
        $withinQuota[(int)$dbId]=true;
    $results=[];$refreshIds=[];
    foreach ($requests as $phoneId=>$ignored) {
        $record=$records[$phoneId]??null;
        // Legacy hashes are consulted only to avoid accidentally lifting
        // previously enforced bans; no new sensitive value is collected.
        $storedImei=$record['imei_hash']??null;
        $storedPhone=$record['phone_number_hash']??null;
        $blocked=mobile_blacklist_match($pdo,$phoneId,$storedImei,$storedPhone)!==null;
        if ($blocked) $status='blacklisted';
        elseif (!$record || (int)$record['enabled']!==1) $status='not_bound';
        elseif ((int)$quota['mobile_limit']<1) $status='quota_disabled';
        elseif (!isset($withinQuota[(int)$record['id']])) $status='quota_exceeded';
        else $status='bound';
        $bound=$status==='bound';
        if ($bound) $refreshIds[]=(int)$record['id'];
        $results[]=['phone_id'=>$phoneId,'bound'=>$bound,'status'=>$status];
    }
    if ($refreshIds) {
        $slots=implode(',',array_fill(0,count($refreshIds),'?'));
        client_sql('UPDATE phonehub_mobile_devices SET last_seen=UTC_TIMESTAMP()
            WHERE user_id=? AND enabled=1 AND id IN ('.$slots.')',
            array_merge([$userId],$refreshIds));
    }

    $packageStarted=hrtime(true);
    $allowed=json_decode((string)$session['entitlements'],true);
    $permitted=array_values(array_unique(array_filter(is_array($allowed)?$allowed:[],
        static fn($id)=>is_string($id) && preg_match('/^[a-z0-9-]{1,32}$/D',$id))));
    if (count($permitted)>16) api_problem('HEARTBEAT_BATCH_LIMIT','客户操作包授权数量超过批量上限');
    $packageRows=[];
    if ($permitted) {
        $slots=implode(',',array_fill(0,count($permitted),'?'));
        $packageRows=client_sql('SELECT package_id,MAX(version) AS latest_version
            FROM phonehub_packages WHERE enabled=1 AND package_id IN ('.$slots.')
            GROUP BY package_id ORDER BY package_id',$permitted)->fetchAll();
    }
    $packageResults=[];
    $mobileReady=(int)$quota['mobile_limit']>0 && (int)$quota['active_count']>0 && count($refreshIds)>0;
    foreach ($packageRows as $p) {
        $id=(string)$p['package_id'];
        if (in_array($id,['mcp','skill','mcp-codex','mcp-harness'],true) &&
            (!($cloudFlags[$id]??false) ||
             (in_array($id,['mcp-codex','mcp-harness'],true) && !in_array('mcp',$permitted,true))))
            continue;
        $latest=(int)$p['latest_version'];
        $clientVersion=$versions[$id]??null;
        $packageResults[]=['package_id'=>$id,'version'=>$latest,
            'download_allowed'=>$mobileReady,
            'update_available'=>$clientVersion===null?null:$latest>$clientVersion];
    }

    api_perf_phase('package',$packageStarted);
    // Reuse the established AI policy; no upstream key or decryptable value is
    // returned. Server mode is available only while a usable key exists.
    $globalAi=ai_settings();
    $userAi=ai_user_policy($userId);
    $aiEnabled=$globalAi['enabled'] && $userAi['enabled'];
    $remaining=max(0,$userAi['daily_limit']-ai_daily_usage($userId));
    $aiHasQuota=$remaining>0;
    return [
        'phones'=>$results,'packages'=>$packageResults,
        'ai'=>['enabled'=>$aiEnabled,
          'server_mode_available'=>$aiEnabled && $globalAi['server_key_configured'] && $aiHasQuota,
          'client_key_allowed'=>$aiEnabled && $globalAi['client_key_enabled'] &&
              $userAi['allow_client_key'] && $aiHasQuota],
        'limits'=>['phones'=>8,'package_versions'=>16],
    ];
}

function api_extra(string $action,array $input,array $session,int $userId): void {
    global $pdo;
    $device=(string)$session['device_id'];
    if ($action==='log_upload') api_store_logs([$input],$userId,$device);
    if ($action==='log_batch') {
        $records=$input['logs']??null;
        if (!is_array($records) || !array_is_list($records)) api_problem('INVALID_LOG_BATCH','logs 必须为数组');
        api_store_logs($records,$userId,$device);
    }
    if ($action==='ai_status') api_ai_status($userId);
    if ($action==='ai_chat') api_ai_chat($input,$session,$userId);
    if (in_array($action,['license_status','capabilities','client_config','client_heartbeat'],true)) {
        $quota=api_mobile_quota($userId);
        $cloudFlags=api_cloud_feature_flags();
        $permitted=json_decode((string)$session['entitlements'],true)?:[];
        $account=client_sql('SELECT device_limit FROM phonehub_users WHERE id=?',[$userId])->fetch();
        $pcUsed=(int)client_sql('SELECT COUNT(DISTINCT device_id) FROM phonehub_sessions WHERE user_id=? AND expires_at>UTC_TIMESTAMP()',[$userId])->fetchColumn();
        $features=api_true_features([
                'mobile_bind'=>true,'mobile_unbind'=>true,'package_requires_mobile_binding'=>true,
                'update_check'=>true,'update_download'=>true,'log_batch'=>true,'device_list'=>true,'device_revoke'=>true,
                'mcp_available'=>($cloudFlags['mcp']??false) && in_array('mcp',$permitted,true),
                'skill_available'=>($cloudFlags['skill']??false) && in_array('skill',$permitted,true),
                'mcp_codex_available'=>($cloudFlags['mcp-codex']??false) && in_array('mcp',$permitted,true) && in_array('mcp-codex',$permitted,true),
                'mcp_harness_available'=>($cloudFlags['mcp-harness']??false) && in_array('mcp',$permitted,true) && in_array('mcp-harness',$permitted,true)
        ]);
        $response=[
            'ok'=>true,'username'=>$session['username'],'server_time'=>time(),
            'session_expires_at'=>strtotime($session['expires_at'].' UTC'),
            'license_until'=>$session['license_until'],'entitlements'=>$permitted,
            'mobile'=>$quota,
            'computer'=>['device_limit'=>(int)($account['device_limit']??0),'used'=>$pcUsed],
            'features'=>$features,
            'settings'=>['session_check_seconds'=>120,'mobile_heartbeat_seconds'=>300,'log_batch_max'=>50]
        ];
        // Only an opt-in client_heartbeat changes shape. All old callers and
        // license_status/capabilities/client_config keep their prior schema.
        if ($action==='client_heartbeat' && array_key_exists('batch',$input)) {
            if (!is_array($input['batch']) ||
                ($input['batch']!==[] && array_is_list($input['batch'])))
                api_problem('INVALID_HEARTBEAT_BATCH','batch 必须为 JSON 对象');
            $response['batch']=api_heartbeat_batch($input['batch'],$session,$userId,$quota,$cloudFlags);
        }
        api_out($response);
    }
    if ($action==='device_list') {
        $rows=client_sql('SELECT device_id,MAX(expires_at) AS expires_at FROM phonehub_sessions WHERE user_id=? AND expires_at>UTC_TIMESTAMP() GROUP BY device_id ORDER BY expires_at DESC',[$userId])->fetchAll();
        $devices=array_map(static fn($r)=>['device_id'=>$r['device_id'],'expires_at'=>strtotime($r['expires_at'].' UTC'),'current'=>$r['device_id']===$device],$rows);
        api_out(['ok'=>true,'devices'=>$devices]);
    }
    if ($action==='device_revoke') {
        $target=(string)($input['target_device_id']??'');
        if (!preg_match('/^[a-f0-9]{64}$/D',$target)) api_problem('INVALID_DEVICE','目标电脑标识无效');
        $affected=client_sql('DELETE FROM phonehub_sessions WHERE user_id=? AND device_id=?',[$userId,$target])->rowCount();
        api_out(['ok'=>true,'revoked'=>$affected>0,'current_session_revoked'=>$target===$device]);
    }
    if ($action==='mobile_check' || $action==='mobile_heartbeat') {
        $phone=api_phone((string)($input['phone_id']??''));
        $found=client_sql('SELECT id,enabled,display_name,imei_hash,phone_number_hash,phone_model
            FROM phonehub_mobile_devices WHERE user_id=? AND phone_id=?',[$userId,$phone])->fetch();
        $quota=api_mobile_quota($userId);
        // Preserve pre-existing device bans, without receiving or calculating
        // new IMEI / SIM-number values from API callers.
        $blocked=mobile_blacklist_match($pdo,$phone,$found['imei_hash']??null,$found['phone_number_hash']??null);
        if ($blocked) api_problem('DEVICE_BLACKLISTED','该手机已被管理员拉黑',403);
        $withinQuota=false;
        if ($found && (int)$found['enabled']===1 && $quota['mobile_limit']>0) {
            $position=(int)client_sql("SELECT COUNT(*) FROM phonehub_mobile_devices d
                WHERE d.user_id=? AND d.enabled=1 AND d.id<=?
                AND NOT EXISTS (SELECT 1 FROM phonehub_mobile_blacklist b WHERE b.enabled=1 AND
                  ((b.identifier_type='phone_id' AND b.identifier_hash=d.phone_id) OR
                   (b.identifier_type='imei_hash' AND d.imei_hash IS NOT NULL AND b.identifier_hash=d.imei_hash) OR
                   (b.identifier_type='phone_hash' AND d.phone_number_hash IS NOT NULL AND b.identifier_hash=d.phone_number_hash)))",
                [$userId,(int)$found['id']])->fetchColumn();
            $withinQuota=$position>0 && $position<=$quota['mobile_limit'];
        }
        $bound=(bool)$withinQuota;
        if ($bound && $action==='mobile_heartbeat') {
            $model=is_string($input['phone_model']??null)?trim($input['phone_model']):'';
            if (strlen($model)>120 || preg_match('/[\x00-\x1F]/',$model))
                api_problem('INVALID_PHONE_MODEL','手机型号格式不正确');
            client_sql("UPDATE phonehub_mobile_devices
                SET last_seen=UTC_TIMESTAMP(), phone_model=COALESCE(NULLIF(phone_model,''),NULLIF(?,'')) WHERE id=? AND user_id=?",
                [$model,(int)$found['id'],$userId]);
        }
        api_out(['ok'=>true,'phone_id'=>$phone,'bound'=>$bound,
            'display_name'=>$found['display_name']??null]+$quota);
    }
    if ($action==='mobile_unbind') {
        $phone=api_phone((string)($input['phone_id']??''));
        global $pdo;
        $pdo->beginTransaction();
        try {
            client_sql('SELECT id FROM phonehub_users WHERE id=? FOR UPDATE',[$userId])->fetch();
            $count=client_sql('UPDATE phonehub_mobile_devices SET enabled=0 WHERE user_id=? AND phone_id=? AND enabled=1',[$userId,$phone])->rowCount();
            $pdo->commit();
        } catch(Throwable $e) {
            if ($pdo->inTransaction()) $pdo->rollBack();
            throw $e;
        }
        api_out(['ok'=>true,'phone_id'=>$phone,'unbound'=>$count>0]);
    }
    if ($action==='package_list') {
        $allowed=json_decode((string)$session['entitlements'],true)?:[];
        $quota=api_mobile_quota($userId);
        $ready=$quota['mobile_limit']>0 && $quota['active_count']>0;
        $rows=client_sql('SELECT package_id,version FROM phonehub_packages WHERE enabled=1 ORDER BY version DESC')->fetchAll();
        $result=[];
        foreach($rows as $row) {
            $pid=(string)$row['package_id'];
            if (!in_array($pid,$allowed,true) || isset($result[$pid])) continue;
            if (in_array($pid,['mcp','skill','mcp-codex','mcp-harness'],true) && !api_cloud_feature_enabled($pid)) continue;
            $result[$pid]=['package_id'=>$pid,'version'=>(int)$row['version'],'download_allowed'=>$ready];
        }
        api_out(['ok'=>true,'mobile_required'=>true,'mobile_ready'=>$ready,'packages'=>array_values($result)]);
    }
    if ($action==='package_check') {
        $id=(string)($input['package_id']??'douyin');
        if (!preg_match('/^[a-z0-9-]{1,32}$/D',$id)) api_problem('INVALID_PACKAGE','操作包 ID 无效');
        $allowed=json_decode((string)$session['entitlements'],true)?:[];
        if (in_array($id,['mcp','skill','mcp-codex','mcp-harness'],true)) api_require_cloud_feature($id,$session);
        if (!in_array($id,$allowed,true)) api_problem('NOT_ENTITLED','未授权此操作包',403);
        $row=client_sql('SELECT version FROM phonehub_packages WHERE package_id=? AND enabled=1 ORDER BY version DESC LIMIT 1',[$id])->fetch();
        if (!$row) api_problem('NOT_FOUND','未发布此操作包',404);
        $quota=api_mobile_quota($userId);
        api_out(['ok'=>true,'package_id'=>$id,'version'=>(int)$row['version'],
            'mobile_required'=>true,'download_allowed'=>$quota['mobile_limit']>0 && $quota['active_count']>0]+$quota);
    }
    if ($action==='update_list') {
        try {
            $platform=release_platform((string)($input['platform']??'core'));
            $channel=release_channel((string)($input['channel']??'stable'));
        } catch(Throwable $e) {api_problem('INVALID_PARAMETER',$e->getMessage());}
        $allowed=json_decode((string)$session['entitlements'],true)?:[];
        if (in_array($platform,['mcp','skill','mcp-codex','mcp-harness'],true)) api_require_cloud_feature($platform,$session);
        if ($platform!=='core' && !in_array($platform,$allowed,true)) api_problem('NOT_ENTITLED','未授权此更新目标',403);
        $rows=client_sql('SELECT * FROM phonehub_releases WHERE platform=? AND channel=? AND enabled=1 ORDER BY id DESC LIMIT 30',[$platform,$channel])->fetchAll();
        usort($rows,static fn($a,$b)=>version_compare($b['version'],$a['version']));
        api_out(['ok'=>true,'releases'=>array_map('public_release',$rows)]);
    }
        if ($action==='update_check' || $action==='update_manifest') {
        try {
            $platform=release_platform((string)($input['platform']??'core'));
            $channel=release_channel((string)($input['channel']??'stable'));
        } catch(Throwable $e) {api_problem('INVALID_PARAMETER',$e->getMessage());}
        $current=(string)($input['current_version']??'0.0.0');
        if (!valid_version($current)) api_problem('INVALID_VERSION','当前版本号不正确');
        $allowed=json_decode((string)$session['entitlements'],true)?:[];
        if (in_array($platform,['mcp','skill','mcp-codex','mcp-harness'],true)) api_require_cloud_feature($platform,$session);
        if ($platform!=='core' && !in_array($platform,$allowed,true)) api_problem('NOT_ENTITLED','未授权此更新目标',403);
        $release=api_latest_release($platform,$channel);
        $available=$release && version_compare($release['version'],$current,'>');
        api_out(['ok'=>true,'available'=>(bool)$available,'current_version'=>$current,
            'latest_version'=>$release['version']??null,
            'release'=>$release?public_release($release):null,
            'download_action'=>'update_download']);
    }
    if ($action==='update_download') {
        $id=api_int($input['release_id']??null);
        $release=client_sql('SELECT * FROM phonehub_releases WHERE id=? AND enabled=1',[$id])->fetch();
        if (!$release) api_problem('RELEASE_NOT_FOUND','更新包不存在或已停用',404);
        api_require_release_permission($release,$session);
        $path=release_store().'/'.$release['storage_name'];
        if (!preg_match('/^[0-9a-f]{40}\.zip$/D',(string)$release['storage_name']) || is_link($path) || !is_file($path)
            || (int)filesize($path)!==(int)$release['size_bytes'])
            api_problem('FILE_UNAVAILABLE','更新文件暂不可用',503);
        // Hash file again before sending to protect against local file corruption.
        if (!hash_equals((string)$release['sha256'],(string)hash_file('sha256',$path)))
            api_problem('FILE_CORRUPT','服务器更新包完整性校验失败',503);
        header_remove('Content-Type');
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="'.str_replace('"','',(string)$release['filename']).'"');
        $total=(int)$release['size_bytes'];
        $from=0;$to=$total-1;$range=(string)($_SERVER['HTTP_RANGE']??'');
        if ($range!=='') {
            if (!preg_match('/^bytes=([0-9]+)-([0-9]*)$/D',$range,$matches))
                api_problem('INVALID_RANGE','只支持单段 bytes=start-end 下载',416);
            $from=(int)$matches[1];
            $to=$matches[2]===''?$total-1:(int)$matches[2];
            if ($from>=$total || $to>=$total || $to<$from) {
                header('Content-Range: bytes */'.$total);
                api_problem('INVALID_RANGE','下载范围超过文件长度',416);
            }
            http_response_code(206);
            header('Content-Range: bytes '.$from.'-'.$to.'/'.$total);
        }
        header('Content-Length: '.($to-$from+1));
        header('Cache-Control: no-store');
        header('Accept-Ranges: bytes');
        $fp=fopen($path,'rb');
        if (!$fp) api_problem('FILE_UNAVAILABLE','更新文件无法打开',503);
        if ($from>0 && fseek($fp,$from)!==0) {fclose($fp);exit;}
        $remaining=$to-$from+1;
        while($remaining>0 && !feof($fp)) {
            $buffer=fread($fp,min(65536,$remaining));
            if ($buffer===false || $buffer==='') break;
            echo $buffer;
            $remaining-=strlen($buffer);
            if (connection_aborted()) break;
        }
        fclose($fp);exit;
    }

}
