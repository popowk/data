<?php
declare(strict_types=1);
require_once dirname(__DIR__).'/app/releases.php';
require_once dirname(__DIR__).'/app/ai.php';

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
    $count=(int)client_sql('SELECT COUNT(*) FROM phonehub_mobile_devices WHERE user_id=? AND enabled=1',[$userId])->fetchColumn();
    return ['mobile_limit'=>(int)($meta['lim']??0),'active_count'=>$count];
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
    $allowed=json_decode((string)$session['entitlements'],true);
    if ($release['platform']!=='core' && !in_array($release['platform'],is_array($allowed)?$allowed:[],true))
        api_problem('NOT_ENTITLED','当前客户没有此更新包的权限',403);
}
function api_latest_release(string $platform,string $channel): ?array {
    $rows=client_sql('SELECT * FROM phonehub_releases WHERE platform=? AND channel=? AND enabled=1 ORDER BY id DESC LIMIT 500',[$platform,$channel])->fetchAll();
    usort($rows,static fn($a,$b)=>version_compare($b['version'],$a['version']));
    return $rows[0]??null;
}
function api_extra(string $action,array $input,array $session,int $userId): void {
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
        $permitted=json_decode((string)$session['entitlements'],true)?:[];
        $account=client_sql('SELECT device_limit FROM phonehub_users WHERE id=?',[$userId])->fetch();
        $pcUsed=(int)client_sql('SELECT COUNT(DISTINCT device_id) FROM phonehub_sessions WHERE user_id=? AND expires_at>UTC_TIMESTAMP()',[$userId])->fetchColumn();
        api_out([
            'ok'=>true,'username'=>$session['username'],'server_time'=>time(),
            'session_expires_at'=>strtotime($session['expires_at'].' UTC'),
            'license_until'=>$session['license_until'],'entitlements'=>$permitted,
            'mobile'=>$quota,
            'computer'=>['device_limit'=>(int)($account['device_limit']??0),'used'=>$pcUsed],
            'features'=>[
                'mobile_bind'=>true,'mobile_unbind'=>true,'package_requires_mobile_binding'=>true,
                'update_check'=>true,'update_download'=>true,'log_batch'=>true,'device_list'=>true,'device_revoke'=>true
            ],
            'settings'=>['session_check_seconds'=>120,'mobile_heartbeat_seconds'=>300,'log_batch_max'=>50]
        ]);
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
        $found=client_sql('SELECT id,enabled,display_name FROM phonehub_mobile_devices WHERE user_id=? AND phone_id=?',[$userId,$phone])->fetch();
        $quota=api_mobile_quota($userId);
        $bound=$found && (int)$found['enabled']===1 && $quota['mobile_limit']>0;
        if ($bound && $action==='mobile_heartbeat') client_sql('UPDATE phonehub_mobile_devices SET last_seen=UTC_TIMESTAMP() WHERE id=?',[$found['id']]);
        api_out(['ok'=>true,'phone_id'=>$phone,'bound'=>(bool)$bound,'display_name'=>$found['display_name']??null]+$quota);
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
            $result[$pid]=['package_id'=>$pid,'version'=>(int)$row['version'],'download_allowed'=>$ready];
        }
        api_out(['ok'=>true,'mobile_required'=>true,'mobile_ready'=>$ready,'packages'=>array_values($result)]);
    }
    if ($action==='package_check') {
        $id=(string)($input['package_id']??'douyin');
        if (!preg_match('/^[a-z0-9-]{1,32}$/D',$id)) api_problem('INVALID_PACKAGE','操作包 ID 无效');
        $allowed=json_decode((string)$session['entitlements'],true)?:[];
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
