<?php
declare(strict_types=1);
require_once __DIR__.'/mobile.php';
// When upgrading from an older updater, newly introduced modules may not yet
// be copied. Keep unrelated admin pages usable for module repair.
if (is_file(__DIR__.'/devices.php') && is_file(__DIR__.'/device_admin.php'))
    require_once __DIR__.'/device_admin.php';

/**
 * Bounded client-log search. All text is bound to PDO parameters, including
 * escaped LIKE wildcards; LIMIT/OFFSET are derived only from validated ints.
 * "all" means username OR error-level event/message, not arbitrary info logs.
 */
function phonehub_client_log_filters(array $query): array {
    $rawQ=is_string($query['q']??null)?trim($query['q']):'';
    $q=preg_match('//u',$rawQ)===1?utf8_limit($rawQ,160):'';
    $mode=is_string($query['search_by']??null)?$query['search_by']:'all';
    if (!in_array($mode,['all','username','error'],true)) $mode='all';
    $rawPage=$query['page']??'1';
    $page=is_string($rawPage)||is_int($rawPage)?(string)$rawPage:'1';
    $page=(ctype_digit($page) && strlen($page)<=6 && (int)$page>=1)
        ?min((int)$page,100000):1;

    $conditions=[];$params=[];
    if ($mode==='error') $conditions[]="l.level='error'";
    if ($q!=='') {
        $like='%'.str_replace(['!','%','_'],['!!','!%','!_'],$q).'%';
        if ($mode==='username') {
            $conditions[]="u.username LIKE ? ESCAPE '!'";
            $params[]=$like;
        } elseif ($mode==='error') {
            $conditions[]="(l.message LIKE ? ESCAPE '!' OR l.event LIKE ? ESCAPE '!')";
            array_push($params,$like,$like);
        } else {
            $conditions[]="(u.username LIKE ? ESCAPE '!' OR (l.level='error' AND (l.message LIKE ? ESCAPE '!' OR l.event LIKE ? ESCAPE '!')))";
            array_push($params,$like,$like,$like);
        }
    }
    return ['q'=>$q,'search_by'=>$mode,'page'=>$page,
        'where'=>$conditions?' WHERE '.implode(' AND ',$conditions):'',
        'params'=>$params];
}

function phonehub_group_member_snapshot(array $ids): string {
    // Legacy helper retained for old smoke tests, not the new value-bound
    // preview. New group_bulk uses phonehub_bulk_snapshot().
    return hash('sha256',implode(',',array_map(static fn($id)=>(string)(int)$id,$ids)));
}
/** A preview is bound to member IDs, their normalized authorization state
 * and the requested changes. No notes, passwords or sessions in the digest. */
function phonehub_bulk_snapshot(array $ids,array $snapshots,array $targets): string {
    ksort($targets);
    $fields=array_keys(phonehub_account_history_fields());
    $rows=[];
    foreach ($ids as $id) {
        $id=(int)$id;
        $state=[];
        foreach ($fields as $field) $state[$field]=$snapshots[$id][$field]??null;
        $rows[]=['id'=>$id,'state'=>$state];
    }
    return hash('sha256',json_encode(['members'=>$rows,'targets'=>$targets],
        JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR));
}
function phonehub_bulk_impact(array $ids,array $before,array $targets): array {
    $sessionCounts=[];
    foreach(array_chunk($ids,200) as $chunk) {
        if(!$chunk) continue;
        $slots=implode(',',array_fill(0,count($chunk),'?'));
        $rows=sql('SELECT user_id,COUNT(*) AS sessions,COUNT(DISTINCT device_id) AS computers
            FROM phonehub_sessions WHERE expires_at>UTC_TIMESTAMP() AND user_id IN ('.$slots.')
            GROUP BY user_id',$chunk)->fetchAll();
        foreach($rows as $row) $sessionCounts[(int)$row['user_id']]=[
            'sessions'=>(int)$row['sessions'],'computers'=>(int)$row['computers']];
    }
    $counts=[];$changed=0;$revokeIds=[];$revokeSessions=0;$examples=[];$utcNow=gmdate('Y-m-d H:i:s');
    foreach($ids as $id) {
        $id=(int)$id;$state=$before[$id]??[];
        if(!$state) throw new RuntimeException('预览期间客户授权数据不完整，请刷新重试');
        $diff=[];
        foreach($targets as $field=>$target) {
            $old=$state[$field]??null;
            $same=$old===$target;
            if(!$same) {
                $diff[]=$field;$counts[$field]=($counts[$field]??0)+1;
            }
        }
        if(!$diff) continue;
        $changed++;
        $usage=$sessionCounts[$id]??['sessions'=>0,'computers'=>0];
        $revoke=false;
        if(in_array('enabled',$diff,true) && (int)$targets['enabled']===0)$revoke=true;
        if(in_array('device_limit',$diff,true) &&
           (int)$targets['device_limit']<(int)$state['device_limit'] &&
           $usage['computers']>(int)$targets['device_limit']) $revoke=true;
        if(in_array('license_until',$diff,true) && $targets['license_until']!==null &&
           (string)$targets['license_until']<=$utcNow &&
           ($state['license_until']===null || (string)$state['license_until']>$utcNow))$revoke=true;
        if(in_array('entitlements',$diff,true) &&
           array_diff((array)$state['entitlements'],(array)$targets['entitlements']))$revoke=true;
        if($revoke && $usage['sessions']>0) {
            $revokeIds[]=$id;$revokeSessions+=$usage['sessions'];
        }
        if(count($examples)<8) {
            $changes=[];
            foreach($diff as $field) $changes[]=[
                'field'=>$field,
                'before'=>phonehub_account_history_value($field,$state[$field]??null),
                'after'=>phonehub_account_history_value($field,$targets[$field])
            ];
            $examples[]=['username'=>$state['username'],'changes'=>$changes,
                'revoke_sessions'=>$revoke && $usage['sessions']>0];
        }
    }
    return ['changed'=>$changed,'field_changes'=>$counts,'revoke_ids'=>$revokeIds,
        'revoke_users'=>count($revokeIds),'revoke_sessions'=>$revokeSessions,'examples'=>$examples];
}

/**
 * v0.5.35 durable bulk runner: no background daemon is assumed. Every HTTP
 * step commits at most 40 customers and their audit+session changes in one
 * transaction; a closed browser can resume the remaining rows later.
 */
function phonehub_bulk_job_expected(array $row): array {
    $out=[];
    foreach(array_keys(phonehub_account_history_fields()) as $field)
        $out[$field]=$row[$field]??null;
    return $out;
}
function phonehub_bulk_job_authorize(array $job): void {
    require_global_admin();
    if (admin_role()!=='owner' && (int)$job['actor_id']!==admin_id())
        throw new PhoneHubPermissionException('只能继续自己创建的批量任务；主账号可以接管');
}
function phonehub_bulk_job_status_data(array $job): array {
    $completed=(int)$job['processed_count']+(int)$job['conflict_count'];
    return [
        'job_id'=>(int)$job['id'],'group_id'=>(int)$job['group_id'],
        'actor_name'=>(string)$job['actor_name'],
        'status'=>(string)$job['status'],'total'=>(int)$job['total_count'],
        'processed'=>(int)$job['processed_count'],'changed'=>(int)$job['changed_count'],
        'conflicts'=>(int)$job['conflict_count'],'revoked_users'=>(int)$job['revoked_users'],
        'revoked_sessions'=>(int)$job['revoked_sessions'],
        'remaining'=>max(0,(int)$job['total_count']-$completed),
        'last_error'=>(string)$job['last_error'],
        'terminal'=>in_array((string)$job['status'],['completed','partial','cancelled'],true)
    ];
}
function phonehub_bulk_job_start(int $group,array $targets,string $preview): array {
    require_global_admin();
    $ids=sql('SELECT u.id FROM phonehub_users u
        JOIN phonehub_user_meta m ON m.user_id=u.id
        WHERE m.group_id=? ORDER BY u.id',[$group])->fetchAll(PDO::FETCH_COLUMN);
    if(count($ids)<=100)throw new RuntimeException('少于或等于 100 位客户，请使用常规批量保存');
    if(count($ids)>5000)throw new RuntimeException('当前分组超过 5000 位客户，为防止建单超时，请先拆分分组');
    $before=phonehub_account_history_snapshots($ids);
    if(count($before)!==count($ids) ||
       !hash_equals($preview,phonehub_bulk_snapshot($ids,$before,$targets)))
        throw new RuntimeException('预览后分组成员或授权配置发生变化，未创建批量任务；请重新预览');
    ksort($targets);
    $targetJson=json_encode($targets,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
    $actorName=(string)sql('SELECT username FROM phonehub_admins WHERE id=?',[admin_id()])->fetchColumn();
    if($actorName==='')throw new RuntimeException('当前管理员身份无效');
    $pdo=db();$pdo->beginTransaction();
    try {
        // UNIQUE(active_group_id) rejects concurrent open jobs for one group.
        try {
            sql('INSERT INTO phonehub_bulk_jobs
                (group_id,active_group_id,actor_id,actor_name,targets_json,snapshot_hash,status,total_count)
                VALUES(?,?,?,?,?,?,"pending",?)',
                [$group,$group,admin_id(),$actorName,$targetJson,$preview,count($ids)]);
        } catch(PDOException $e) {
            if($e->getCode()==='23000')
                throw new RuntimeException('该分组已有未完成的批量任务，请先继续或取消原任务');
            throw $e;
        }
        $jobId=(int)$pdo->lastInsertId();
        foreach(array_chunk($ids,100) as $part) {
            $values=[];$params=[];
            foreach($part as $userId) {
                $userId=(int)$userId;
                $expected=phonehub_bulk_job_expected($before[$userId]);
                $values[]='(?,?,?,"pending")';
                array_push($params,$jobId,$userId,
                    json_encode($expected,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR));
            }
            sql('INSERT INTO phonehub_bulk_job_items(job_id,user_id,expected_json,state)
                VALUES '.implode(',',$values),$params);
        }
        audit('group_bulk_job_start','job='.$jobId.' group='.$group.' count='.count($ids));
        $pdo->commit();
        return ['job_created'=>true,'job_id'=>$jobId,'status'=>'pending',
            'total'=>count($ids),'message'=>'已创建分批任务 #'.$jobId.'，每次至多处理 40 位客户'];
    } catch(Throwable $e) {
        if($pdo->inTransaction())$pdo->rollBack();
        throw $e;
    }
}
function phonehub_bulk_job_step(int $id): array {
    require_global_admin();
    if($id<1)throw new RuntimeException('批量任务 ID 无效');
    $pdo=db();$pdo->beginTransaction();
    try {
        $job=sql('SELECT * FROM phonehub_bulk_jobs WHERE id=? FOR UPDATE',[$id])->fetch();
        if(!$job)throw new RuntimeException('批量任务不存在');
        phonehub_bulk_job_authorize($job);
        if(in_array($job['status'],['completed','partial','cancelled'],true)) {
            $pdo->commit();
            return phonehub_bulk_job_status_data($job);
        }
        $items=sql("SELECT user_id,expected_json FROM phonehub_bulk_job_items
            WHERE job_id=? AND state='pending' ORDER BY user_id LIMIT 40 FOR UPDATE",[$id])->fetchAll();
        if(!$items) {
            $status=(int)$job['conflict_count']>0?'partial':'completed';
            sql('UPDATE phonehub_bulk_jobs SET status=?,active_group_id=NULL,
                completed_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP(),last_error="" WHERE id=?',[$status,$id]);
            audit('group_bulk_job_finish','job='.$id.' status='.$status);
            $pdo->commit();
            $job['status']=$status;$job['last_error']='';
            return phonehub_bulk_job_status_data($job);
        }
        $memberIds=array_map(static fn($row)=>(int)$row['user_id'],$items);
        $slots=implode(',',array_fill(0,count($memberIds),'?'));
        $locked=sql('SELECT u.id FROM phonehub_users u
            JOIN phonehub_user_meta m ON m.user_id=u.id
            WHERE m.group_id=? AND u.id IN ('.$slots.') ORDER BY u.id FOR UPDATE',
            array_merge([(int)$job['group_id']],$memberIds))->fetchAll(PDO::FETCH_COLUMN);
        $states=phonehub_account_history_snapshots($locked);
        $okIds=[];$goodStates=[];$conflicts=0;
        foreach($items as $item) {
            $userId=(int)$item['user_id'];
            $expected=json_decode((string)$item['expected_json'],true);
            if(!is_array($expected))throw new RuntimeException('持久化任务快照无法解码');
            $current=$states[$userId]??null;
            $reason=$current===null?'left_group_or_missing':
                (phonehub_bulk_job_expected($current)===$expected?'':'authorization_changed');
            if($reason!=='') {
                sql("UPDATE phonehub_bulk_job_items SET state='conflict',reason_code=?
                     WHERE job_id=? AND user_id=?",[$reason,$id,$userId]);
                $conflicts++;continue;
            }
            $okIds[]=$userId;$goodStates[$userId]=$current;
        }
        $targets=json_decode((string)$job['targets_json'],true);
        if(!is_array($targets) || !$targets || array_diff(array_keys($targets),
            ['device_limit','mobile_limit','enabled','license_until','entitlements']))
            throw new RuntimeException('批量任务目标配置异常');
        $impact=phonehub_bulk_impact($okIds,$goodStates,$targets);
        $set=[];$values=[];
        foreach($targets as $key=>$value) {
            $column=match($key) {
                'device_limit'=>'u.device_limit','mobile_limit'=>'m.mobile_limit',
                'enabled'=>'u.enabled','license_until'=>'u.license_until',
                'entitlements'=>'u.entitlements',
                default=>throw new RuntimeException('批量任务包含未授权字段')
            };
            $set[]=$column.'=?';
            $values[]=$key==='entitlements'
                ?json_encode($value,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR):$value;
        }
        $revokeLookup=array_fill_keys($impact['revoke_ids'],true);
        foreach($okIds as $userId) {
            sql('UPDATE phonehub_users u INNER JOIN phonehub_user_meta m ON m.user_id=u.id
                SET '.implode(',',$set).' WHERE u.id=? AND m.group_id=?',
                array_merge($values,[$userId,(int)$job['group_id']]));
            if(isset($revokeLookup[$userId]))
                sql('DELETE FROM phonehub_sessions WHERE user_id=?',[$userId]);
            $after=phonehub_account_history_snapshots([$userId])[$userId]??[];
            phonehub_account_history_record($userId,'group_bulk',$goodStates[$userId],$after);
            sql("UPDATE phonehub_bulk_job_items SET state='done' WHERE job_id=? AND user_id=?",
                [$id,$userId]);
        }
        $processed=count($okIds);
        $doneTotal=(int)$job['processed_count']+$processed+(int)$job['conflict_count']+$conflicts;
        $final=$doneTotal>=(int)$job['total_count'];
        $status=$final?((int)$job['conflict_count']+$conflicts>0?'partial':'completed'):'running';
        sql('UPDATE phonehub_bulk_jobs SET
            processed_count=processed_count=?, changed_count=changed_count=?,
            conflict_count=conflict_count=?,revoked_users=revoked_users=?,
            revoked_sessions=revoked_sessions=?,status=?,last_error="",
            active_group_id='.($final?'NULL':'active_group_id').',
            completed_at='.($final?'UTC_TIMESTAMP()':'completed_at').',
            updated_at=UTC_TIMESTAMP() WHERE id=?',
            [$processed,$impact['changed'],$conflicts,$impact['revoke_users'],$impact['revoke_sessions'],$status,$id]);
        if($final) audit('group_bulk_job_finish','job='.$id.' status='.$status);
        $pdo->commit();
        $job['processed_count']=(int)$job['processed_count']+$processed;
        $job['changed_count']=(int)$job['changed_count']+$impact['changed'];
        $job['conflict_count']=(int)$job['conflict_count']+$conflicts;
        $job['revoked_users']=(int)$job['revoked_users']+$impact['revoke_users'];
        $job['revoked_sessions']=(int)$job['revoked_sessions']+$impact['revoke_sessions'];
        $job['status']=$status;$job['last_error']='';
        return phonehub_bulk_job_status_data($job);
    } catch(Throwable $e) {
        if($pdo->inTransaction())$pdo->rollBack();
        // A failed HTTP request never marks a batch done. The next click
        // retries the same 40 pending items without duplicating updates.
        try {
            sql("UPDATE phonehub_bulk_jobs SET last_error='最近一批执行失败，可重试',
                updated_at=UTC_TIMESTAMP() WHERE id=? AND status IN ('pending','running')",[$id]);
        } catch(Throwable $ignored) {}
        throw $e;
    }
}
function phonehub_bulk_job_action(string $action): never {
    require_global_admin();
    $id=filter_var($_POST['job_id']??null,FILTER_VALIDATE_INT);
    if(!is_int($id) || $id<1) throw new RuntimeException('请选择有效的批量任务');
    if($action==='group_bulk_job_step')
        json_response(['ok'=>true]+phonehub_bulk_job_step($id));
    $pdo=db();
    if($action==='group_bulk_job_status') {
        $job=sql('SELECT * FROM phonehub_bulk_jobs WHERE id=?',[$id])->fetch();
        if(!$job)throw new RuntimeException('批量任务不存在');
        phonehub_bulk_job_authorize($job);
        json_response(['ok'=>true]+phonehub_bulk_job_status_data($job));
    }
    if($action==='group_bulk_job_cancel') {
        $pdo->beginTransaction();
        try {
            $job=sql('SELECT * FROM phonehub_bulk_jobs WHERE id=? FOR UPDATE',[$id])->fetch();
            if(!$job)throw new RuntimeException('批量任务不存在');
            phonehub_bulk_job_authorize($job);
            if(!in_array($job['status'],['completed','partial','cancelled'],true)) {
                sql("UPDATE phonehub_bulk_jobs SET status='cancelled',active_group_id=NULL,
                    completed_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP()
                    WHERE id=?",[$id]);
                audit('group_bulk_job_cancel','job='.$id.' processed='.$job['processed_count']);
                $job['status']='cancelled';
            }
            $pdo->commit();
            json_response(['ok'=>true]+phonehub_bulk_job_status_data($job));
        } catch(Throwable $e) {
            if($pdo->inTransaction())$pdo->rollBack();
            throw $e;
        }
    }
    throw new RuntimeException('未知分批任务操作');
}
/**
 * Bounded, explicit history cleanup. Core license/device/keys are never
 * eligible for deletion. MySQL table and date-column names are static code,
 * while durations are range checked and passed as bound values.
 */
function phonehub_history_cleanup_targets(): array {
    return [
      'client_logs'=>['label'=>'客户端运行日志','table'=>'phonehub_client_logs','date'=>'created_at','min'=>7,'default'=>30],
      'ai_usage'=>['label'=>'AI 请求统计','table'=>'phonehub_ai_usage','date'=>'created_at','min'=>30,'default'=>180],
      'replacement_events'=>['label'=>'自动换机统计','table'=>'phonehub_computer_replacement_events','date'=>'created_at','min'=>30,'default'=>180],
      'package_downloads'=>['label'=>'操作包下载历史','table'=>'phonehub_package_downloads','date'=>'downloaded_at','min'=>90,'default'=>365],
      'admin_audit'=>['label'=>'管理员操作审计（仅主账号）','table'=>'phonehub_admin_audit','date'=>'created_at','min'=>365,'default'=>730],
      'api_perf'=>['label'=>'接口性能采样','table'=>'phonehub_api_perf_samples','date'=>'created_at','min'=>7,'default'=>30]
    ];
}
function phonehub_history_cleanup_action(string $action): never {
    require_global_admin();
    $targets=phonehub_history_cleanup_targets();
    $kind=(string)($_POST['kind']??'');
    if (!isset($targets[$kind])) throw new RuntimeException('历史记录类型无效');
    if ($kind==='admin_audit') require_owner();
    $days=filter_var($_POST['days']??null,FILTER_VALIDATE_INT);
    $policy=$targets[$kind];
    if ($days===false || $days===null || $days<$policy['min'] || $days>3650)
        throw new RuntimeException('保留天数不符合该类型的安全下限（'.$policy['min'].'–3650 天）');
    $created=time();
    $cutoff=gmdate('Y-m-d H:i:s',$created-$days*86400);
    $table=$policy['table'];$date=$policy['date'];
    if ($action==='history_cleanup_preview') {
        $count=(int)sql("SELECT COUNT(*) FROM $table WHERE $date < ?",[$cutoff])->fetchColumn();
        $secret=hash_hmac('sha256',"$kind|$days|$cutoff|$count|$created",csrf());
        json_response(['ok'=>true,'kind'=>$kind,'label'=>$policy['label'],'days'=>$days,
            'eligible'=>$count,'batch_limit'=>500,'preview_at'=>$created,'preview_count'=>$count,
            'preview_token'=>$secret,
            'message'=>'仅预览，不会删除任何记录']);
    }
    if ($action==='history_cleanup_apply') {
        $issued=filter_var($_POST['preview_at']??null,FILTER_VALIDATE_INT);
        $count=filter_var($_POST['preview_count']??null,FILTER_VALIDATE_INT);
        $token=(string)($_POST['preview_token']??'');
        if (!is_int($issued) || $issued>time()+30 || $issued<time()-300 ||
            !is_int($count) || $count<0 || !preg_match('/^[a-f0-9]{64}$/D',$token))
            throw new RuntimeException('历史清理预览已失效，请重新预览');
        // Reconstruct the same UTC cutoff from the verified snapshot time.
        $confirmedCutoff=gmdate('Y-m-d H:i:s',$issued-$days*86400);
        $expected=hash_hmac('sha256',"$kind|$days|$confirmedCutoff|$count|$issued",csrf());
        if (!hash_equals($expected,$token)) throw new RuntimeException('历史清理预览校验失败');
        $current=(int)sql("SELECT COUNT(*) FROM $table WHERE $date < ?",[$confirmedCutoff])->fetchColumn();
        if ($current!==$count) throw new RuntimeException('待清理数量已变化，请重新预览');
        // This deliberately processes 500 rows per confirmed action rather
        // than a table-wide DELETE that can lock production for a long time.
        $removed=$current>0 ? sql("DELETE FROM $table WHERE $date < ? ORDER BY id ASC LIMIT 500",
            [$confirmedCutoff])->rowCount() : 0;
        audit('history_cleanup',"$kind days=$days removed=$removed");
        json_response(['ok'=>true,'removed'=>$removed,'remaining'=>max(0,$current-$removed),
            'message'=>'本次清理 '.$removed.' 条；剩余约 '.max(0,$current-$removed).' 条，请重新预览后再清理']);
    }
    throw new RuntimeException('未知历史清理操作');
}
function history_cleanup_admin_view(): void {
    require_global_admin();
    $targets=phonehub_history_cleanup_targets();
    $owner=admin_role()==='owner';
    ?>
    <div class="card" id="maintenance-history">
      <div class="card-head"><h2>历史记录保留与分批清理</h2><span class="count">先预览，每次最多 500 条</span></div>
      <p class="muted">仅清理明确选择的历史统计，不处理客户授权、电脑会话、设备绑定、操作包文件、签名或密钥。默认不执行自动删除。</p>
      <form data-ajax="history_cleanup_apply">
        <input type="hidden" name="action" value="history_cleanup_apply">
        <div class="form-grid">
          <div class="field"><label>历史记录类型</label><select name="kind" id="history-cleanup-kind">
            <?php foreach($targets as $key=>$config): if ($key==='admin_audit' && !$owner) continue; ?>
            <option value="<?=h($key)?>" data-default="<?=(int)$config['default']?>" data-min="<?=(int)$config['min']?>"><?=h($config['label'])?>（至少保留 <?=(int)$config['min']?> 天）</option>
            <?php endforeach ?>
          </select></div>
          <div class="field"><label>保留最近天数</label><input name="days" id="history-cleanup-days" type="number" min="7" max="3650" value="30" required></div>
        </div>
        <p class="footnote">预览确认后本次最多清理 500 条旧记录；还剩数据时可重复操作。管理审计仅主管理员可操作，并至少保留一年。</p>
        <div class="editor-actions"><button type="submit" class="btn">预览并确认清理</button></div>
      </form>
    </div>
    <?php
}
function feature_action(string $action): never {
    phonehub_require_action($action);
    if (in_array($action,['history_cleanup_preview','history_cleanup_apply'],true))
        phonehub_history_cleanup_action($action);
    $id=(int)($_POST['id'] ?? 0);
    if ($action==='admin_create') {
        require_owner();
        $name=trim((string)($_POST['username'] ?? ''));validate_user($name);
        $role=(string)($_POST['role']??'admin');
        if (!in_array($role,['global','admin'],true)) throw new RuntimeException('管理员角色无效');
        $password=random_password();
        sql('INSERT INTO phonehub_admins(username,password_hash,role,enabled) VALUES(?,?,?,1)',
            [$name,password_hash_safe($password),$role]);
        audit('admin_create',$name);
        json_response(['ok'=>true,'message'=>'管理员已创建','password'=>$password,'username'=>$name]);
    }
    if ($action==='admin_role_change') {
        require_owner();
        $role=(string)($_POST['role']??'');
        if (!in_array($role,['global','admin'],true)) throw new RuntimeException('目标管理员角色无效');
        $target=sql('SELECT id,username,role FROM phonehub_admins WHERE id=?',[$id])->fetch();
        if (!$target || $target['role']==='owner' || $id===admin_id())
            throw new PhoneHubPermissionException('受保护的主账号不允许更改角色');
        if (!in_array($target['role'],['global','admin','viewer'],true))
            throw new RuntimeException('此管理员角色不支持转换');
        sql("UPDATE phonehub_admins SET role=?,auth_version=auth_version+1 WHERE id=? AND role IN ('global','admin','viewer')",[$role,$id]);
        audit('admin_role_change',(string)$target['username'].' '.$target['role'].' -> '.$role);
        json_response(['ok'=>true,'message'=>'管理员角色已更新，相关登录会话将失效']);
    }
    if (in_array($action,['admin_toggle','admin_reset','admin_delete'],true)) {
        require_owner();
        $target=sql('SELECT id,username,role,enabled FROM phonehub_admins WHERE id=?',[$id])->fetch();
        if (!$target || !in_array($target['role'],['global','admin','viewer'],true) || (int)$target['id']===admin_id())
            throw new RuntimeException('主管理员受到保护，禁止修改、重置或删除');
        if ($action==='admin_toggle') {
            $next=(int)$target['enabled'] ? 0 : 1;
            sql("UPDATE phonehub_admins SET enabled=?,auth_version=auth_version+1 WHERE id=? AND role IN ('global','admin','viewer')",[$next,$id]);
            audit('admin_toggle',(string)$target['username']);
            json_response(['ok'=>true,'message'=>$next?'管理员已启用':'管理员已停用']);
        }
        if ($action==='admin_reset') {
            $password=random_password();
            sql("UPDATE phonehub_admins SET password_hash=?,auth_version=auth_version+1 WHERE id=? AND role IN ('global','admin','viewer')",
                [password_hash_safe($password),$id]);
            audit('admin_reset',(string)$target['username']);
            json_response(['ok'=>true,'message'=>'管理员密码已重置','username'=>$target['username'],'password'=>$password]);
        }
        sql("DELETE FROM phonehub_admins WHERE id=? AND role IN ('global','admin','viewer')",[$id]);
        audit('admin_delete',(string)$target['username']);
        json_response(['ok'=>true,'message'=>'管理员已删除']);
    }
    if ($action==='owner_password') {
        require_owner();
        $old=(string)($_POST['old_password']??'');
        $new=(string)($_POST['new_password']??'');
        $hash=sql('SELECT password_hash FROM phonehub_admins WHERE id=?',[admin_id()])->fetchColumn();
        if (!$hash || !password_verify($old,(string)$hash)) throw new RuntimeException('当前密码错误');
        $newHash=password_hash_safe($new);
        sql('UPDATE phonehub_admins SET password_hash=?,auth_version=auth_version+1 WHERE id=? AND role=?',[$newHash,admin_id(),'owner']);
        $_SESSION['auth_version']=(int)sql('SELECT auth_version FROM phonehub_admins WHERE id=?',[admin_id()])->fetchColumn();
        audit('owner_password','self');
        json_response(['ok'=>true,'message'=>'主管理员密码已修改']);
    }
    if (in_array($action,['group_bulk','group_bulk_preview'],true)) {
        $group=(int)($_POST['group_id']??0);
        if ($group<1 || !(int)sql('SELECT COUNT(*) FROM phonehub_groups WHERE id=?',[$group])->fetchColumn())
            throw new RuntimeException('请选择有效分组');
        $fields=[];
        $allowed=['device_limit','mobile_limit','enabled','license_until','entitlements'];
        foreach($allowed as $f) if(isset($_POST['apply_'.$f])) $fields[]=$f;
        if (!$fields) throw new RuntimeException('请至少勾选一项需要批量修改的配置');
        $set=[];$params=[];$targets=[];
        foreach($fields as $f) {
            if ($f==='device_limit' || $f==='mobile_limit') {
                $v=filter_var($_POST[$f]??null,FILTER_VALIDATE_INT);
                if ($v===false || $v<($f==='device_limit'?1:0) || $v>($f==='device_limit'?100:1000))
                    throw new RuntimeException('设备名额无效');
                $set[]=$f==='device_limit'?'u.device_limit=?':'m.mobile_limit=?';
                $params[]=$v;$targets[$f]=$v;
            } elseif ($f==='enabled') {
                $v=(string)($_POST['enabled']??'');
                if (!in_array($v,['0','1'],true)) throw new RuntimeException('账号状态无效');
                $set[]='u.enabled=?';$params[]=(int)$v;$targets[$f]=(int)$v;
            } elseif ($f==='license_until') {
                $until=input_to_utc(trim((string)($_POST['license_until']??'')));
                $set[]='u.license_until=?';$params[]=$until;$targets[$f]=$until;
            } elseif ($f==='entitlements') {
                $v=(array)($_POST['entitlements']??[]);
                if (array_diff($v,['douyin','xiaohongshu','mcp','skill','mcp-codex','mcp-harness'])) throw new RuntimeException('未知平台或扩展授权');
                if (array_intersect($v,['mcp','skill','mcp-codex','mcp-harness'])) require_global_admin();
                if (array_intersect($v,['mcp-codex','mcp-harness']) && !in_array('mcp',$v,true))
                    throw new RuntimeException('Codex 与 DeepSeek Harness MCP 必须同时授权上级 MCP 权限');
                $v=array_values(array_unique($v));sort($v,SORT_STRING);
                $set[]='u.entitlements=?';$params[]=json_encode($v,JSON_UNESCAPED_UNICODE);$targets[$f]=$v;
            }
        }
        $labels=['device_limit'=>'电脑名额','mobile_limit'=>'安卓手机名额',
            'enabled'=>'账号状态','license_until'=>'授权期限','entitlements'=>'平台与扩展权限'];
        if ($action==='group_bulk_preview') {
            $ids=sql('SELECT u.id FROM phonehub_users u
              JOIN phonehub_user_meta m ON m.user_id=u.id
              WHERE m.group_id=? ORDER BY u.id',[$group])->fetchAll(PDO::FETCH_COLUMN);
            if (!$ids) throw new RuntimeException('该分组没有客户');
            $before=phonehub_account_history_snapshots($ids);
            $impact=phonehub_bulk_impact($ids,$before,$targets);
            $fieldChanges=[];
            foreach($impact['field_changes'] as $field=>$count)
                $fieldChanges[]=['field'=>$labels[$field],'count'=>$count];
            $samples=[];
            foreach($impact['examples'] as $ex) {
                $displayChanges=[];
                foreach($ex['changes'] as $change) $displayChanges[]=[
                    'field'=>$labels[$change['field']],'before'=>$change['before'],
                    'after'=>$change['after']];
                $samples[]=['username'=>$ex['username'],'changes'=>$displayChanges,
                    'revoke_sessions'=>$ex['revoke_sessions']];
            }
            json_response(['ok'=>true,'members'=>count($ids),
              'fields'=>array_map(static fn($field)=>$labels[$field],$fields),
              'changed'=>$impact['changed'],'field_changes'=>$fieldChanges,'examples'=>$samples,
              'revoke_users'=>$impact['revoke_users'],'revoke_session_count'=>$impact['revoke_sessions'],
              'revoke_sessions'=>$impact['revoke_sessions']>0,
              'snapshot'=>phonehub_bulk_snapshot($ids,$before,$targets)]);
        }
        $preview=(string)($_POST['preview_snapshot']??'');
        if (!preg_match('/^[a-f0-9]{64}$/D',$preview))
            throw new RuntimeException('批量修改需要先在当前页面完成服务端预览');
        db()->beginTransaction();
        try {
            $memberIds=sql('SELECT u.id FROM phonehub_users u
              JOIN phonehub_user_meta m ON m.user_id=u.id
              WHERE m.group_id=? ORDER BY u.id FOR UPDATE',[$group])->fetchAll(PDO::FETCH_COLUMN);
            if (!$memberIds) throw new RuntimeException('该分组没有客户');
            $beforeSnapshots=phonehub_account_history_snapshots($memberIds);
            if (!hash_equals($preview,phonehub_bulk_snapshot($memberIds,$beforeSnapshots,$targets)))
                throw new RuntimeException('预览后分组成员或授权配置发生变化，未执行修改；请重新预览确认');
            $impact=phonehub_bulk_impact($memberIds,$beforeSnapshots,$targets);
            $placeholders=implode(',',array_fill(0,count($memberIds),'?'));
            // Target only the previewed members even if another request joins
            // the group while this transaction is in progress.
            $updateParams=array_merge($params,[$group],$memberIds);
            sql('UPDATE phonehub_users u INNER JOIN phonehub_user_meta m ON m.user_id=u.id
              SET '.implode(',',$set).' WHERE m.group_id=? AND u.id IN ('.$placeholders.')',$updateParams);
            // Only invalidate sessions whose authorization was actually
            // restricted. No-op/increased quota/granted scopes remain online.
            foreach(array_chunk($impact['revoke_ids'],200) as $chunk) {
                $revokeSlots=implode(',',array_fill(0,count($chunk),'?'));
                sql('DELETE FROM phonehub_sessions WHERE user_id IN ('.$revokeSlots.')',$chunk);
            }
            $afterSnapshots=phonehub_account_history_snapshots($memberIds);
            foreach ($memberIds as $memberId) {
                $memberId=(int)$memberId;
                phonehub_account_history_record($memberId,'group_bulk',
                    $beforeSnapshots[$memberId]??[],$afterSnapshots[$memberId]??[]);
            }
            audit('group_bulk','group='.$group.' members='.count($memberIds).
                ' changed='.$impact['changed'].' revoked='.$impact['revoke_users'].
                ' fields='.implode(',',$fields));
            db()->commit();
        } catch (Throwable $e) {
            if (db()->inTransaction()) db()->rollBack();
            throw $e;
        }
        json_response(['ok'=>true,'members'=>count($memberIds),'changed'=>$impact['changed'],
            'revoke_users'=>$impact['revoke_users'],'revoke_session_count'=>$impact['revoke_sessions'],
            'message'=>'已检查 '.count($memberIds).' 个客户，实际变更 '.$impact['changed'].
            ' 位；撤销 '.$impact['revoke_users'].' 位客户的受影响电脑会话']);
    }
    if (in_array($action,['device_blacklist_add'],true)) {
        if (!function_exists('device_admin_action'))
            throw new RuntimeException('设备管理模块缺失；请通过系统更新补齐必要文件');
        device_admin_action($action);
    }
    if ($action==='mobile_add') {
        $user=(int)($_POST['user_id']??0);
        $fingerprint=strtolower(trim((string)($_POST['phone_id']??'')));
        $name=trim((string)($_POST['display_name']??''));
        $model=trim((string)($_POST['phone_model']??''));
        if ($user<1 || !preg_match('/^[a-f0-9]{64}$/D',$fingerprint))
            throw new RuntimeException('请选择客户并输入 64 位手机设备指纹');
        if (utf8_length($name)>120 || preg_match('/[\x00-\x1F]/',$name) ||
            strlen($model)>120 || preg_match('/[\x00-\x1F]/',$model))
            throw new RuntimeException('手机备注或型号格式错误');
        // Obsolete IMEI/SIM-number form fields are ignored. Never call the
        // retired encryption or HMAC helpers or write sensitive identifiers.
        db()->beginTransaction();
        try {
            $u=sql('SELECT u.id,u.enabled,COALESCE(m.mobile_limit,0) AS mobile_limit FROM phonehub_users u LEFT JOIN phonehub_user_meta m ON m.user_id=u.id WHERE u.id=? FOR UPDATE',[$user])->fetch();
            if (!$u || !(int)$u['enabled']) throw new RuntimeException('客户不存在或已停用');
            $existing=sql('SELECT id,enabled,imei_hash,phone_number_hash FROM phonehub_mobile_devices WHERE user_id=? AND phone_id=? FOR UPDATE',[$user,$fingerprint])->fetch();
            if (mobile_blacklist_match(db(),$fingerprint,$existing['imei_hash']??null,$existing['phone_number_hash']??null))
                throw new RuntimeException('该手机指纹已在设备黑名单中');
            $active=(int)sql('SELECT COUNT(*) FROM phonehub_mobile_devices WHERE user_id=? AND enabled=1',[$user])->fetchColumn();
            if ((!$existing || !(int)$existing['enabled']) && $active>=(int)$u['mobile_limit'])
                throw new RuntimeException('已达到客户安卓手机授权上限');
            sql("INSERT INTO phonehub_mobile_devices(user_id,phone_id,display_name,phone_model,enabled,last_seen)
                VALUES(?,?,?,?,1,UTC_TIMESTAMP()) ON DUPLICATE KEY UPDATE
                display_name=VALUES(display_name),phone_model=COALESCE(NULLIF(VALUES(phone_model),''),phone_model),
                enabled=1,last_seen=UTC_TIMESTAMP()",[$user,$fingerprint,$name,$model]);
            audit('mobile_add','user='.$user.' id='.substr($fingerprint,0,10));
            db()->commit();
        } catch (Throwable $e) {
            if (db()->inTransaction()) db()->rollBack();
            throw $e;
        }
        json_response(['ok'=>true,'message'=>'安卓手机已绑定']);
    }
    if ($action==='mobile_blacklist') {
        if ($id<1) throw new RuntimeException('手机记录无效');
        $reason=trim((string)($_POST['reason']??'管理员手动拉黑'));
        if (utf8_length($reason)>255) throw new RuntimeException('拉黑原因不能超过 255 字');
        db()->beginTransaction();
        try {
            $record=sql('SELECT id,phone_id FROM phonehub_mobile_devices WHERE id=? FOR UPDATE',[$id])->fetch();
            if (!$record) throw new RuntimeException('绑定记录不存在');
            device_insert_blacklist(db(),'phone_id',(string)$record['phone_id'],$reason,admin_id());
            sql('UPDATE phonehub_mobile_devices SET enabled=0 WHERE phone_id=?',[(string)$record['phone_id']]);
            audit('mobile_blacklist','record='.$id.' phone_id');
            db()->commit();
        } catch(Throwable $e) {
            if(db()->inTransaction()) db()->rollBack();
            throw $e;
        }
        json_response(['ok'=>true,'message'=>'手机指纹已拉黑，匹配绑定已停用']);
    }
    if ($action==='mobile_unblacklist') {
        if ($id<1) throw new RuntimeException('黑名单记录无效');
        $record=sql("SELECT id,identifier_type,identifier_hash FROM phonehub_mobile_blacklist WHERE id=? AND enabled=1 AND identifier_type IN ('computer_id','phone_id')",[$id])->fetch();
        if (!$record) throw new RuntimeException('黑名单记录不存在或已解除');
        sql('UPDATE phonehub_mobile_blacklist SET enabled=0 WHERE id=?',[$id]);
        audit('mobile_unblacklist',$record['identifier_type'].'='.substr($record['identifier_hash'],0,12));
        json_response(['ok'=>true,'message'=>'已解除该条黑名单；设备绑定不会自动恢复']);
    }
    if ($action==='cloud_features_save') {
        require_global_admin();
        $values=[
            'mcp_enabled'=>isset($_POST['mcp_enabled'])?'1':'0',
            'mcp_codex_enabled'=>isset($_POST['mcp_codex_enabled'])?'1':'0',
            'mcp_harness_enabled'=>isset($_POST['mcp_harness_enabled'])?'1':'0',
            'skill_enabled'=>isset($_POST['skill_enabled'])?'1':'0'
        ];
        foreach($values as $key=>$value) sql('INSERT INTO phonehub_feature_settings(setting_key,setting_value) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)',[$key,$value]);
        audit('cloud_features_save','mcp='.$values['mcp_enabled'].', codex='.$values['mcp_codex_enabled'].', harness='.$values['mcp_harness_enabled'].', skill='.$values['skill_enabled']);
        json_response(['ok'=>true,'message'=>'客户端扩展总开关已保存']);
    }
    if ($action==='mobile_revoke') {
        if ($id<1) throw new RuntimeException('手机记录无效');
        db()->beginTransaction();
        $record=sql('SELECT user_id FROM phonehub_mobile_devices WHERE id=?',[$id])->fetch();
        if(!$record)throw new RuntimeException('绑定记录不存在');
        sql('SELECT id FROM phonehub_users WHERE id=? FOR UPDATE',[(int)$record['user_id']])->fetch();
        sql('UPDATE phonehub_mobile_devices SET enabled=0 WHERE id=?',[$id]);
        audit('mobile_revoke',(string)$id);
        db()->commit();
        json_response(['ok'=>true,'message'=>'该手机绑定已撤销']);
    }
    throw new RuntimeException('未知管理操作');
}

/**
 * In-admin read-only performance telemetry. Approximate percentiles over the
 * latest at most 3000 sampled requests from the past 7 days, no identities.
 */
function phonehub_performance_view(): void {
    require_global_admin();
    $rows=sql("SELECT action,http_status,total_ms,db_ms,query_count,created_at
        FROM phonehub_api_perf_samples
        WHERE created_at>=DATE_SUB(UTC_TIMESTAMP(),INTERVAL 7 DAY)
        ORDER BY id DESC LIMIT 3000")->fetchAll();
    $stats=[];$days=[];
    foreach ($rows as $sample) {
        $action=(string)$sample['action'];
        if (!isset($stats[$action])) $stats[$action]=['count'=>0,'failed'=>0,'latency'=>[],'db'=>[],'queries'=>0];
        $stats[$action]['count']++;
        if ((int)$sample['http_status']>=400) $stats[$action]['failed']++;
        $stats[$action]['latency'][]=(int)$sample['total_ms'];
        $stats[$action]['db'][]=(int)$sample['db_ms'];
        $stats[$action]['queries']+=(int)$sample['query_count'];
        $day=substr((string)$sample['created_at'],0,10);
        if (!isset($days[$day]))$days[$day]=['count'=>0,'errors'=>0];
        $days[$day]['count']++;
        if ((int)$sample['http_status']>=400)$days[$day]['errors']++;
    }
    ksort($stats);ksort($days);
    $percentile=static function(array $values,float $p): int {
        if (!$values)return 0;
        sort($values,SORT_NUMERIC);
        return $values[max(0,min(count($values)-1,(int)ceil(count($values)*$p)-1))];
    };
    $sampleCount=count($rows);
    $failed=count(array_filter($rows,static fn(array $row)=>(int)$row['http_status']>=400));
    $sampling=(int)(getenv('PHONEHUB_PERF_SAMPLE_PERCENT')?:0);
    ?>
    <div class="page-title"><div><h1>接口性能监控</h1><p>授权查询的脱敏 PHP 服务端耗时，采样关闭时不会产生新记录</p></div></div>
    <div class="device-summary">
      <div class="device-summary-card"><span>近 7 天已加载采样</span><strong><?=$sampleCount?></strong><small>只展示最近最多 3000 条</small></div>
      <div class="device-summary-card"><span>采样中 4xx/5xx 比例</span><strong><?=$sampleCount?number_format($failed/$sampleCount*100,1).'%' : '—'?></strong><small>非全量请求成功率</small></div>
      <div class="device-summary-card"><span>PHP 总耗时 P95</span><strong><?=$sampleCount?$percentile(array_column($rows,'total_ms'),0.95).' ms':'—'?></strong><small>不包括 DNS、TLS 与代理耗时</small></div>
    </div>
    <div class="card"><div class="card-head"><h2>授权接口性能</h2><span class="count">最近 7 天，最多 3000 条</span></div>
      <p class="muted">启动采样：PHP-FPM 设置环境变量 <code>PHONEHUB_PERF_SAMPLE_PERCENT=10</code>，重启服务后生效；默认 0 为关闭。实际采样配置由 PHP-FPM 环境决定，后台页面不自动修改服务器配置。</p>
      <?php if(!$sampleCount): ?><p class="footnote">尚无采样数据。启用采样后请求授权接口，即可显示 P50/P95 与数据库耗时。</p><?php endif ?>
      <div class="table-scroll"><table><thead><tr><th>接口</th><th>采样数</th><th>4xx/5xx</th><th>PHP P50</th><th>PHP P95</th><th>数据库 P95</th><th>平均 SQL 次数</th></tr></thead><tbody>
        <?php foreach($stats as $action=>$entry): ?>
        <tr><td><?=h($action)?></td><td><?=(int)$entry['count']?></td><td><?=(int)$entry['failed']?></td>
          <td><?=$percentile($entry['latency'],0.50)?> ms</td><td><?=$percentile($entry['latency'],0.95)?> ms</td>
          <td><?=$percentile($entry['db'],0.95)?> ms</td>
          <td><?=number_format($entry['queries']/max(1,$entry['count']),1)?></td></tr>
        <?php endforeach ?>
      </tbody></table></div>
      <p class="footnote">采样仅包含 action、状态码、PHP 总耗时、数据库耗时、SQL 数和 UTC 时间；不记录客户账号、电脑 ID、Token、IP、请求正文。P95 是本页最近样本的近似分位数，低采样量或 3000 条截断时不等同于全站真实 P95。</p>
    </div>
    <div class="card"><div class="card-head"><h2>每日采样趋势（UTC）</h2></div>
      <div class="table-scroll"><table><thead><tr><th>日期</th><th>采样数</th><th>4xx/5xx</th><th>错误占比</th></tr></thead><tbody>
        <?php foreach($days as $day=>$entry): ?>
        <tr><td><?=h($day)?></td><td><?=(int)$entry['count']?></td><td><?=(int)$entry['errors']?></td>
        <td><?=number_format($entry['errors']/max(1,$entry['count'])*100,1)?>%</td></tr>
        <?php endforeach ?>
      </tbody></table></div>
    </div>
    <?php
}
function feature_view(string $view,bool $embedded=false): void {
    phonehub_require_view($view==='mobiles'?'devices':$view);
    if ($view==='performance') { phonehub_performance_view(); return; }
    if ($view==='admins') {
        require_global_admin();
        $canManageAdmins=admin_role()==='owner';
        $admins=sql('SELECT id,username,role,enabled,created_at FROM phonehub_admins ORDER BY CASE WHEN role=\'owner\' THEN 0 ELSE 1 END,id')->fetchAll();
        ?><div class="page-title"><div><h1>管理员管理</h1><p>可创建全局管理员和普通管理员；主账号权限受到保护</p></div></div>
        <?php if($canManageAdmins): ?>
        <div class="card"><div class="card-head"><h2>创建管理员</h2></div>
        <form data-ajax="admin_create" class="inline-form admin-create-form"><input name="action" type="hidden" value="admin_create"><input name="username" placeholder="管理员登录名（3–64 位英文字符）" required minlength="3"><select name="role" aria-label="管理员角色" required><option value="admin">普通管理员</option><option value="global">全局管理员</option></select><button class="btn primary">创建并生成密码</button></form>
        <p class="footnote">普通管理员：客户授权、设备管理、套餐管理、客户端日志。全局管理员：其他业务、日志与审计；程序安装、信任签名、备份密钥、自动化发布令牌与管理员权限变更仅主账号可以操作。历史只读管理员不会自动升级。</p></div>
        <?php endif ?>
        <div class="card"><div class="card-head"><h2>管理员列表</h2></div><div class="table-scroll"><table><thead><tr><th>管理员</th><th>权限</th><th>状态</th><th>创建时间</th><th>操作</th></tr></thead><tbody>
        <?php foreach($admins as $a): ?><tr><td><b><?=h($a['username'])?></b></td><td><?=h(phonehub_role_label((string)$a['role']))?><?= $a['role']==='owner'?'（受保护）':'' ?></td><td><span class="pill <?=(int)$a['enabled']?'ok':'off'?>"><?=(int)$a['enabled']?'正常':'已停用'?></span></td><td><?=h(utc_to_cn($a['created_at']))?></td><td>
        <?php if($a['role']==='owner'): ?><span class="muted">受保护的主账号</span><?php elseif($canManageAdmins): ?>
        <form data-ajax="admin_role_change" class="inline-form" style="display:inline-flex;vertical-align:middle;gap:6px;margin-right:12px">
          <input type="hidden" name="action" value="admin_role_change"><input type="hidden" name="id" value="<?=(int)$a['id']?>">
          <select name="role" aria-label="调整 <?=h($a['username'])?> 的角色"><option value="admin" <?=$a['role']==='admin'?'selected':''?>>普通管理员</option><option value="global" <?=$a['role']==='global'?'selected':''?>>全局管理员</option></select><button type="submit" class="small-link" data-confirm-submit="确认更改管理员权限？该管理员需要重新登录。">保存角色</button>
        </form>
        <button class="small-link" data-action="admin-reset" data-id="<?=(int)$a['id']?>">重置密码</button>
        <button class="small-link" data-action="admin-toggle" data-id="<?=(int)$a['id']?>"><?=(int)$a['enabled']?'停用':'启用'?></button>
        <button class="small-link" data-action="admin-delete" data-id="<?=(int)$a['id']?>">删除</button>
        <?php else: ?><span class="muted">仅主账号可管理</span>
        <?php endif ?></td></tr><?php endforeach ?></tbody></table></div></div>
        <?php if($canManageAdmins): ?><div class="card"><div class="card-head"><h2>修改自己的主管理员密码</h2></div>
        <form data-ajax="owner_password" class="inline-form"><input name="action" type="hidden" value="owner_password"><input type="password" name="old_password" required placeholder="当前密码"><input type="password" name="new_password" required minlength="12" placeholder="新密码（至少12字节）"><button class="btn primary">修改密码</button></form></div><?php endif; ?>
        <?php
    } elseif ($view==='group_bulk') {
        $groups=sql('SELECT id,name,(SELECT COUNT(*) FROM phonehub_user_meta WHERE group_id=g.id) AS cnt FROM phonehub_groups g ORDER BY name')->fetchAll();
        ?>
        <?php if (!$embedded): ?>
        <div class="page-title"><div><h1>分组批量配置</h1><p>先选择客户分组，再勾选需要覆盖的配置；未勾选的字段不会改变。</p></div><a class="btn" href="?view=groups">返回客户分组</a></div>
        <?php else: ?>
        <div class="page-title" id="group-bulk"><div><h2>分组批量配置</h2><p>选择目标分组与字段，先预览影响范围，再确认应用。</p></div><a class="btn" href="#group-list">返回分组列表</a></div>
        <?php endif ?>
        <div class="bulk-intro"><div class="bulk-intro-icon">≡</div><div><strong>安全批量修改</strong><p>仅影响所选分组中的客户。只有停用账号、收回权限、授权提前到期或电脑额度降到当前占用以下，才撤销受影响客户会话；增加额度或重复保存不会踢下线。</p></div></div>
        <form id="group-bulk-form" data-ajax="group_bulk">
        <input name="action" type="hidden" value="group_bulk">
        <section class="card bulk-target-card">
          <div class="bulk-section-head"><div><span class="bulk-step">01</span><div><h2>选择目标分组</h2><p>选择要统一调整授权的客户群组</p></div></div><span class="bulk-required">必选</span></div>
          <div class="field"><label for="bulk-group">目标客户分组</label><select id="bulk-group" name="group_id" required><option value="">请选择客户分组</option><?php foreach($groups as $g): ?><option value="<?=(int)$g['id']?>" data-members="<?=(int)$g['cnt']?>"><?=h($g['name'])?>（<?=(int)$g['cnt']?> 位客户）</option><?php endforeach ?></select><div class="bulk-group-meta"><span id="bulk-member-count">尚未选择分组</span><span>只会修改该分组内的客户</span></div></div>
        </section>
        <div class="bulk-section-title"><div><span class="bulk-step">02</span><div><h2>选择要修改的授权字段</h2><p>打开对应选项后，才会应用下面的配置</p></div></div><span class="bulk-tip">未勾选 = 保持原值</span></div>
        <div class="bulk-grid">
          <section class="bulk-option">
            <label class="bulk-option-head"><input class="bulk-option-toggle" type="checkbox" name="apply_device_limit"><span class="bulk-option-icon">PC</span><span><strong>电脑数量上限</strong><small>每个客户允许登录的电脑数量</small></span></label>
            <div class="bulk-option-body"><label for="bulk-device">新的电脑名额</label><input id="bulk-device" data-bulk-field type="number" name="device_limit" min="1" max="100" value="3" disabled><small>允许范围：1–100 台</small></div>
          </section>
          <section class="bulk-option">
            <label class="bulk-option-head"><input class="bulk-option-toggle" type="checkbox" name="apply_mobile_limit"><span class="bulk-option-icon">手机</span><span><strong>安卓手机数量上限</strong><small>每个客户允许绑定的手机数量</small></span></label>
            <div class="bulk-option-body"><label for="bulk-mobile">新的手机名额</label><input id="bulk-mobile" data-bulk-field type="number" name="mobile_limit" min="0" max="1000" value="1" disabled><small>设置为 0 将禁止绑定手机</small></div>
          </section>
          <section class="bulk-option">
            <label class="bulk-option-head"><input class="bulk-option-toggle" type="checkbox" name="apply_enabled"><span class="bulk-option-icon">状态</span><span><strong>客户账号状态</strong><small>统一启用或停用该分组客户</small></span></label>
            <div class="bulk-option-body"><label for="bulk-enabled">设置为</label><select id="bulk-enabled" data-bulk-field name="enabled" disabled><option value="1">启用账号</option><option value="0">停用账号</option></select><small>停用后客户无法继续登录</small></div>
          </section>
          <section class="bulk-option">
            <label class="bulk-option-head"><input class="bulk-option-toggle" type="checkbox" name="apply_license_until"><span class="bulk-option-icon">期限</span><span><strong>授权有效期</strong><small>统一修改客户授权截止时间</small></span></label>
            <div class="bulk-option-body"><label for="bulk-expiry">新的授权截止时间（北京时间）</label><input id="bulk-expiry" data-bulk-field type="datetime-local" name="license_until" step="1" disabled><small>勾选后留空代表永久授权</small></div>
          </section>
          <section class="bulk-option bulk-option-wide">
            <label class="bulk-option-head"><input class="bulk-option-toggle" type="checkbox" name="apply_entitlements"><span class="bulk-option-icon">权限</span><span><strong>平台与扩展权限</strong><small>勾选的权限将成为该分组客户的完整权限集合</small></span></label>
            <div class="bulk-option-body">
              <div class="bulk-entitlements">
                <label><input data-bulk-field type="checkbox" name="entitlements[]" value="douyin" checked disabled> 抖音</label>
                <label><input data-bulk-field type="checkbox" name="entitlements[]" value="xiaohongshu" disabled> 小红书</label>
                <label><input data-bulk-field type="checkbox" name="entitlements[]" value="mcp" disabled> MCP</label>
                <label><input data-bulk-field type="checkbox" name="entitlements[]" value="mcp-codex" disabled> Codex MCP</label>
                <label><input data-bulk-field type="checkbox" name="entitlements[]" value="mcp-harness" disabled> DeepSeek Harness MCP</label>
                <label><input data-bulk-field type="checkbox" name="entitlements[]" value="skill" disabled> Skill</label>
              </div><small>未勾选的平台将从客户授权中移除；MCP/Skill 还需要主管理员开启云端总开关。</small>
            </div>
          </section>
        </div>
        <div class="bulk-impact"><strong>生效提示</strong><p>预览会列出实际变化人数、字段和预计撤销会话数；增加额度、延长有效期及授予新权限不会导致电脑下线。手机额度调整不会主动解绑手机。</p></div>
        <div class="bulk-submit"><div><strong id="bulk-summary">尚未选择修改项</strong><small>提交前预览字段差异和下线人数；成员或原授权值变化时，要求重新预览</small></div><button class="btn primary" type="submit" data-confirm-submit="此操作将批量修改所选分组的指定授权字段，确认继续？">应用批量配置</button></div>
        </form>
        <?php
    } elseif ($view==='mobiles' || $view==='devices') {
        if (!function_exists('device_admin_view')) {
            ?><div class="card"><h2>设备管理模块尚未补齐</h2>
            <p class="muted">缺少 app/devices.php 或 app/device_admin.php。旧版升级器未包含新模块时会出现这种情况。请进入「系统更新」检查并补齐缺失模块，不要清空客户数据。</p>
            <a class="btn primary" href="?view=update">前往系统更新</a></div><?php
        } else {
            device_admin_view();
        }
    } elseif ($view==='cloud_features') {
        require_global_admin();
        $rows=sql("SELECT setting_key,setting_value FROM phonehub_feature_settings WHERE setting_key IN ('mcp_enabled','skill_enabled','mcp_codex_enabled','mcp_harness_enabled')")->fetchAll();
        $flags=[];foreach($rows as $row)$flags[$row['setting_key']]=$row['setting_value']==='1';
        $mcp=!empty($flags['mcp_enabled']);$skill=!empty($flags['skill_enabled']);
        $codex=!empty($flags['mcp_codex_enabled']);$harness=!empty($flags['mcp_harness_enabled']);
        ?><div class="page-title"><div><h1>客户端能力与 AI</h1><p>统一管理 MCP / Skill 能力、DeepSeek AI 接口以及调用策略</p></div><span class="cloud-live-indicator"><i></i> 云端策略生效中</span></div>
        <div class="cloud-summary"><div><span class="cloud-summary-label">全局开放能力</span><strong><?=((int)$mcp+(int)$skill)?> <small>/ 2</small></strong></div><p>只有全局开关、客户单独授权、已启用签名版本三项同时满足，客户端才可以使用对应能力。</p></div>
        <form data-ajax="cloud_features_save" class="cloud-feature-form"><input type="hidden" name="action" value="cloud_features_save">
          <div class="cloud-feature-grid">
            <section class="cloud-feature-card <?=$mcp?'is-enabled':'is-disabled'?>">
              <div class="cloud-feature-top"><div class="cloud-feature-icon">M</div><span class="cloud-state"><?=$mcp?'全局已开放':'默认禁用'?></span></div>
              <h2>MCP 连接能力</h2><p>允许已获授权的客户获取并使用 PhoneHub MCP 连接包。</p>
              <label class="cloud-switch"><input type="checkbox" name="mcp_enabled" <?=$mcp?'checked':''?>><span class="cloud-switch-ui"></span><span><?=$mcp?'已开启':'关闭 MCP'?></span></label>
              <ul><li>控制 MCP 版本查询与下载</li><li>客户还必须单独获得 MCP 授权</li><li>需要存在已启用的签名发布版本</li></ul>
            </section>
            <section class="cloud-feature-card <?=$skill?'is-enabled':'is-disabled'?>">
              <div class="cloud-feature-top"><div class="cloud-feature-icon skill">S</div><span class="cloud-state"><?=$skill?'全局已开放':'默认禁用'?></span></div>
              <h2>Skill 技能能力</h2><p>允许已获授权的客户获取并使用 PhoneHub Skill 技能包。</p>
              <label class="cloud-switch"><input type="checkbox" name="skill_enabled" <?=$skill?'checked':''?>><span class="cloud-switch-ui"></span><span><?=$skill?'已开启':'关闭 Skill'?></span></label>
              <ul><li>控制 Skill 版本查询与下载</li><li>客户还必须单独获得 Skill 授权</li><li>需要存在已启用的签名发布版本</li></ul>
            </section>
          </div>
          <div class="card" style="margin-top:14px">
          <div class="card-head"><h2>MCP 平台独立授权</h2></div>
          <p class="muted">Codex 和 DeepSeek Harness 默认关闭。实际开放还必须同时启用上方 MCP 总开关，并给客户同时授予 MCP 和对应平台权限。旧版 MCP 权限保持不变，不自动升级为新权限。</p>
          <div class="form-grid">
            <div class="field"><label class="check-row"><input type="checkbox" name="mcp_codex_enabled" <?=$codex?'checked':''?>> Codex MCP 全局开放</label></div>
            <div class="field"><label class="check-row"><input type="checkbox" name="mcp_harness_enabled" <?=$harness?'checked':''?>> DeepSeek Harness MCP 全局开放</label></div>
          </div>
        </div>
          <div class="cloud-savebar"><div><strong>修改云端开放策略</strong><small>保存后立即影响后续授权检查与下载请求</small></div><button class="btn primary" type="submit">保存设置</button></div>
        </form>
        <div class="cloud-warning"><strong>安全说明</strong><p>关闭总开关会立即阻止后续版本查询与下载，但不能远程删除客户已经下载的本地文件。桌面客户端必须定期查询 <code>license_status</code> / <code>capabilities</code>，在能力变为不可用时停止本地调用；离线设备在下次联网校验时收到撤销状态。</p></div>
        <?php
        if (is_file(__DIR__.'/ai.php')) {
            require_once __DIR__.'/ai.php';
            try { ai_admin_view(true); }
            catch (Throwable $e) {
                $errorRef=bin2hex(random_bytes(4));
                error_log('PhoneHub embedded AI settings ['.$errorRef.']: '.get_class($e));
                ?><div class="card"><h2>AI 接口配置暂不可用</h2><p>客户端能力开关仍可使用；请检查 PHP 错误日志。错误编号：<code><?=h($errorRef)?></code></p></div><?php
            }
        } else {
            ?><div class="card"><p>AI 接口模块缺失，请到「系统更新」补齐文件后再管理 AI。</p></div><?php
        }

    } elseif($view==='client_logs') {
        $filters=phonehub_client_log_filters($_GET);
        $from=' FROM phonehub_client_logs l JOIN phonehub_users u ON u.id=l.user_id';
        $where=$filters['where'];
        $params=$filters['params'];
        $total=(int)sql('SELECT COUNT(*)'.$from.$where,$params)->fetchColumn();
        $pages=max(1,(int)ceil($total/50));
        $page=min($filters['page'],$pages);
        $offset=($page-1)*50;
        $logs=sql('SELECT l.level,l.event,l.message,l.created_at,u.username'.
            $from.$where.' ORDER BY l.id DESC LIMIT 50 OFFSET '.$offset,$params)->fetchAll();
        $pageLink=static function(int $number) use ($filters): string {
            return 'index.php?'.http_build_query([
                'view'=>'client_logs','q'=>$filters['q'],'search_by'=>$filters['search_by'],
                'page'=>$number
            ],'','&',PHP_QUERY_RFC3986);
        };
        ?><div class="page-title"><div><h1>客户端运行日志</h1><p>按时间倒序展示客户端上传的运行日志，每页 50 条</p></div></div>
        <div class="card">
          <form method="get" action="index.php" class="client-log-filter-form" aria-label="搜索客户端运行日志">
            <input type="hidden" name="view" value="client_logs">
            <div class="field">
              <label for="client-log-search-by">搜索范围</label>
              <select id="client-log-search-by" name="search_by">
                <option value="all" <?=$filters['search_by']==='all'?'selected':''?>>用户名或错误日志</option>
                <option value="username" <?=$filters['search_by']==='username'?'selected':''?>>仅用户名</option>
                <option value="error" <?=$filters['search_by']==='error'?'selected':''?>>仅错误日志</option>
              </select>
            </div>
            <div class="field">
              <label for="client-log-keyword">搜索关键词</label>
              <input id="client-log-keyword" name="q" maxlength="160" value="<?=h($filters['q'])?>" placeholder="输入用户名、错误事件或错误内容">
            </div>
            <div class="client-log-filter-actions">
              <button class="btn primary" type="submit">搜索</button>
              <a class="btn" href="index.php?view=client_logs">重置</a>
            </div>
          </form>
        </div>
        <div class="card">
          <div class="card-head"><h2>日志列表</h2><span class="count">匹配 <?=number_format($total)?> 条 · 第 <?=$page?> / <?=$pages?> 页（每页 50 条）</span></div>
          <div class="table-scroll"><table><thead><tr>
          <th>时间（北京时间）</th><th>客户</th><th>级别</th><th>事件</th><th>内容（最多 2000 字）</th>
          </tr></thead><tbody>
          <?php foreach($logs as $l): ?><tr>
            <td><?=h(utc_to_cn($l['created_at']))?></td>
            <td><?=h($l['username'])?></td>
            <td><?=h($l['level'])?></td>
            <td><?=h($l['event'])?></td>
            <td style="white-space:normal;min-width:280px"><?=h($l['message'])?></td>
          </tr><?php endforeach ?>
          <?php if (!$logs): ?><tr><td colspan="5" class="empty-result">没有符合条件的日志，请调整关键词或搜索范围。</td></tr><?php endif ?>
          </tbody></table></div>
          <nav class="account-pagination" aria-label="客户端日志分页">
            <?php if($page>1): ?>
              <a class="btn" href="<?=h($pageLink(1))?>">首页</a>
              <a class="btn" href="<?=h($pageLink($page-1))?>">上一页</a>
            <?php endif ?>
            <span>第 <?=$page?> / <?=$pages?> 页</span>
            <?php if($page<$pages): ?>
              <a class="btn" href="<?=h($pageLink($page+1))?>">下一页</a>
              <a class="btn" href="<?=h($pageLink($pages))?>">末页</a>
            <?php endif ?>
          </nav>
        </div><?php
    }
}

// Embedded in this established signed module for updates from v0.5.4.
// Opening quota templates for ordinary and global administrators. No billing or privileges.
function plan_admin_action(string $action): never {
    phonehub_require_action($action);
    if ($action==='plan_save') {
        $id=(int)($_POST['id']??0);
        $name=trim((string)($_POST['name']??''));
        $pc=(int)($_POST['device_limit']??0);
        $mobile=(int)($_POST['mobile_limit']??-1);
        $sort=(int)($_POST['sort_order']??100);
        if ($name==='' || utf8_length($name)>64 || preg_match('/[\\x00-\\x1F\\x7F]/u',$name))
            throw new RuntimeException('套餐名称须为 1–64 个字符');
        if ($pc<1 || $pc>100 || $mobile<0 || $mobile>1000 || $sort<0 || $sort>9999)
            throw new RuntimeException('套餐额度或排序范围不正确');
        db()->beginTransaction();
        try {
            if ($id && !sql('SELECT id FROM phonehub_plan_templates WHERE id=? FOR UPDATE',[$id])->fetch())
                throw new RuntimeException('套餐不存在');
            if ((int)sql('SELECT COUNT(*) FROM phonehub_plan_templates WHERE name=? AND id<>?',[$name,$id])->fetchColumn())
                throw new RuntimeException('套餐名称已存在');
            if ($id) sql('UPDATE phonehub_plan_templates SET name=?,device_limit=?,mobile_limit=?,sort_order=? WHERE id=?',
                [$name,$pc,$mobile,$sort,$id]);
            else {
                $code='plan_'.bin2hex(random_bytes(6));
                sql('INSERT INTO phonehub_plan_templates(plan_code,name,device_limit,mobile_limit,enabled,sort_order) VALUES(?,?,?,?,1,?)',
                    [$code,$name,$pc,$mobile,$sort]);
                $id=(int)db()->lastInsertId();
            }
            audit('plan_save','plan_id='.$id);
            db()->commit();
        } catch(Throwable $e) {if(db()->inTransaction())db()->rollBack();throw $e;}
        json_response(['ok'=>true,'message'=>'套餐保存成功，现有客户额度保持不变','id'=>$id]);
    }
    if ($action==='plan_toggle') {
        $id=(int)($_POST['id']??0);
        if ($id<1) throw new RuntimeException('套餐不存在');
        db()->beginTransaction();
        try {
            $row=sql('SELECT enabled FROM phonehub_plan_templates WHERE id=? FOR UPDATE',[$id])->fetch();
            if (!$row) throw new RuntimeException('套餐不存在');
            $enabled=(int)$row['enabled']?0:1;
            sql('UPDATE phonehub_plan_templates SET enabled=? WHERE id=?',[$enabled,$id]);
            audit('plan_toggle','plan_id='.$id.',enabled='.$enabled);
            db()->commit();
        } catch(Throwable $e) {if(db()->inTransaction())db()->rollBack();throw $e;}
        json_response(['ok'=>true,'message'=>$enabled?'已启用套餐':'已停用套餐，已有客户保持不变']);
    }
    throw new RuntimeException('无效套餐操作');
}
function plan_admin_view(): void {
    phonehub_require_view('plans');
    $plans=sql('SELECT p.*,COALESCE(a.users,0) AS users,
        COALESCE(a.actual_computers,0) AS actual_computers,
        COALESCE(a.actual_mobiles,0) AS actual_mobiles
        FROM phonehub_plan_templates p LEFT JOIN (
          SELECT m.opening_plan_code,COUNT(*) AS users,
                 SUM(u.device_limit) AS actual_computers,SUM(m.mobile_limit) AS actual_mobiles
          FROM phonehub_user_meta m JOIN phonehub_users u ON u.id=m.user_id
          WHERE m.opening_plan_code IS NOT NULL
          GROUP BY m.opening_plan_code
        ) a ON a.opening_plan_code=p.plan_code
        ORDER BY p.sort_order,p.id')->fetchAll();
    $historical=sql("SELECT
      SUM(CASE WHEN opening_plan_code IS NULL THEN 1 ELSE 0 END) AS legacy,
      SUM(CASE WHEN opening_plan_code='custom' THEN 1 ELSE 0 END) AS custom
      FROM phonehub_user_meta")->fetch();
    $activePlans=count(array_filter($plans,static fn($p)=>(int)$p['enabled']===1));
    $assignedAccounts=array_sum(array_map(static fn($p)=>(int)$p['users'],$plans));
    ?>
    <div class="page-title"><div><h1>套餐管理</h1><p>用于新客户开户的电脑与手机额度；不包含价格、订单或支付</p></div><button class="btn primary" type="button" data-action="new-plan">+ 新增套餐</button></div>
    <div class="stats plan-stats">
      <div class="stat"><span>已启用模板</span><strong><?=$activePlans?></strong><small>共 <?=count($plans)?> 个模板</small></div>
      <div class="stat"><span>模板开户客户</span><strong><?=$assignedAccounts?></strong><small>仅统计目前仍可识别的模板代码</small></div>
      <div class="stat"><span>自定义开户</span><strong><?=(int)($historical['custom']??0)?></strong><small>客户当前额度独立管理</small></div>
      <div class="stat"><span>原有授权</span><strong><?=(int)($historical['legacy']??0)?></strong><small>历史创建且没有套餐标签</small></div>
    </div>
    <div class="card editor" id="plan-editor" hidden>
      <div class="card-head"><h2 id="plan-editor-title">新增套餐</h2><button class="text-button" type="button" data-action="close-plan-editor">关闭</button></div>
      <form data-ajax="plan_save"><input type="hidden" name="action" value="plan_save"><input type="hidden" name="id" value="0">
        <div class="form-grid">
          <div class="field span2"><label>套餐名称</label><input name="name" maxlength="64" required placeholder="例如：企业版"></div>
          <div class="field"><label>电脑名额</label><input name="device_limit" type="number" min="1" max="100" required value="3"></div>
          <div class="field"><label>安卓手机名额</label><input name="mobile_limit" type="number" min="0" max="1000" required value="5"></div>
          <div class="field"><label>排序</label><input name="sort_order" type="number" min="0" max="9999" required value="100"></div>
        </div>
        <p class="footnote">修改或停用套餐不影响已有客户，也不开放额外软件、AI 或 MCP 权限。</p>
        <button class="btn primary" type="submit">保存套餐</button>
      </form>
    </div>
    <div class="card"><div class="card-head"><h2>开户套餐</h2><span class="count"><?=count($plans)?> 个</span></div>
      <div class="table-scroll"><table><thead><tr><th>名称</th><th>模板电脑</th><th>模板手机</th><th>已开户客户</th><th>历史客户当前总额度</th><th>排序</th><th>状态</th><th>操作</th></tr></thead><tbody>
      <?php foreach($plans as $p):
        $edit=['id'=>(int)$p['id'],'name'=>$p['name'],'device_limit'=>(int)$p['device_limit'],
           'mobile_limit'=>(int)$p['mobile_limit'],'sort_order'=>(int)$p['sort_order']];
      ?>
        <tr><td><b><?=h($p['name'])?></b><small class="device-subline"><?=h($p['plan_code'])?></small></td>
          <td><?=(int)$p['device_limit']?></td><td><?=(int)$p['mobile_limit']?></td>
          <td><a class="small-link" href="?view=accounts&amp;plan=<?=rawurlencode($p['plan_code'])?>"><?=(int)$p['users']?> 位</a></td>
          <td><?=(int)$p['actual_computers']?> 台电脑 / <?=(int)$p['actual_mobiles']?> 部手机</td><td><?=(int)$p['sort_order']?></td>
          <td><span class="pill <?=(int)$p['enabled']?'ok':'off'?>"><?=(int)$p['enabled']?'启用':'停用'?></span></td>
          <td><button class="small-link" type="button" data-plan-edit="<?=h(json_encode($edit,JSON_UNESCAPED_UNICODE|JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_QUOT|JSON_HEX_APOS))?>">编辑</button>
          <button class="small-link <?=(int)$p['enabled']?'danger-action':''?>" type="button" data-action="plan-toggle" data-id="<?=(int)$p['id']?>"><?=(int)$p['enabled']?'停用':'启用'?></button></td>
        </tr>
      <?php endforeach ?></tbody></table></div>
    </div>
    <p class="footnote">“模板电脑/手机”是新开户采用的额度；“历史客户当前总额度”汇总实际客户名额，修改或停用模板不会改变历史客户。点击开户客户数可查看对应客户。</p>
    <?php
}

/**
 * Backup recipient key setup is separate from the pinned Ed25519 update key.
 * Generate exactly once; persist only Curve25519 public key, return the 32-byte
 * secret key in a one-time authenticated HTTPS download. NEVER log its contents.
 */
function backup_recipient_status(string $storage=APP_STORE): array {
    if (!extension_loaded('sodium')) throw new RuntimeException('备份密钥管理需要 PHP sodium 扩展');
    $path=rtrim($storage,'/').'/backup-recipient.pub';
    if (is_link($path)) throw new RuntimeException('备份接收公钥不能是符号链接');
    if (!file_exists($path)) return ['configured'=>false];
    if (!is_file($path)) throw new RuntimeException('备份公钥文件类型异常');
    $pub=file_get_contents($path);
    if (!is_string($pub) || strlen($pub)!==SODIUM_CRYPTO_BOX_PUBLICKEYBYTES)
        throw new RuntimeException('备份接收公钥无效，请检查原文件；不要随意覆盖');
    return ['configured'=>true,'fingerprint'=>hash('sha256',$pub)];
}
function backup_recipient_generate(string $storage): array {
    if (!extension_loaded('sodium')) throw new RuntimeException('需要 PHP sodium 扩展');
    $storage=rtrim($storage,'/');
    if (!is_dir($storage) || !is_writable($storage) || is_link($storage))
        throw new RuntimeException('备份公钥存储目录不存在或不可写');
    if (backup_recipient_status($storage)['configured'])
        throw new RuntimeException('备份密钥已经建立，禁止自动覆盖；如遗失私钥，请先处理既有加密备份');
    $pair=sodium_crypto_box_keypair();
    $secret=sodium_crypto_box_secretkey($pair);
    $public=sodium_crypto_box_publickey($pair);
    $path=$storage.'/backup-recipient.pub';
    $fp=@fopen($path,'x+b');
    if ($fp===false) {
        sodium_memzero($secret);sodium_memzero($pair);
        throw new RuntimeException('备份公钥已存在或无法安全创建，不会覆盖现有密钥');
    }
    $complete=false;
    try {
        @chmod($path,0600);
        $written=fwrite($fp,$public);
        $complete=$written===strlen($public) && fflush($fp);
    } finally {
        fclose($fp);
        if (!$complete) @unlink($path);
        sodium_memzero($pair);
    }
    if (!$complete) {
        sodium_memzero($secret);
        throw new RuntimeException('备份公钥写入失败');
    }
    return ['secret'=>$secret,'fingerprint'=>hash('sha256',$public)];
}
function backup_admin_download_once(): never {
    require_owner();
    if (!extension_loaded('sodium')) throw new RuntimeException('PHP sodium 不可用');
    audit('backup_recipient_generate_requested','initialization');
    $generated=backup_recipient_generate(APP_STORE);
    $secret=$generated['secret'];
    try {
        try {audit('backup_recipient_generate',substr($generated['fingerprint'],0,16));}
        catch(Throwable $e) {error_log('PhoneHub recipient key audit failed: '.get_class($e));}
        // Raw recipient private key is compatible with the existing offline
        // tools/backup-server.php verify/restore CLI operations.
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="phonehub-backup-recovery.key"');
        header('Content-Length: '.strlen($secret));
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('X-Content-Type-Options: nosniff');
        echo $secret;
    } finally {sodium_memzero($secret);}
    exit;
}
function backup_admin_view(bool $embedded=false): void {
    require_owner();
    $status=backup_recipient_status();
    ?>
    <?php if (!$embedded): ?>
    <div class="page-title"><div><h1>备份密钥管理</h1>
        <p>初始化加密备份接收公钥；解密私钥只下载一次，不修改现有 Ed25519 更新签名</p></div>
        <a class="btn" href="?view=update">运行环境自检</a>
    </div>
    <?php else: ?>
    <div class="page-title" id="maintenance-backup"><div><h2>备份密钥管理</h2><p>Curve25519 加密备份接收公钥，与 Ed25519 更新验签相互独立；解密私钥只下载一次。</p></div><a class="btn" href="#maintenance-update">返回系统更新</a></div>
    <?php endif ?>
    <div class="card"><div class="card-head"><h2>Curve25519 备份密钥</h2>
        <span class="pill <?=$status['configured']?'ok':'off'?>"><?=$status['configured']?'已配置公钥':'尚未配置'?></span></div>
        <?php if ($status['configured']): ?>
          <p>备份接收公钥已安装，支持现有 CLI 加密备份工具。</p>
          <p class="muted">公钥 SHA-256 指纹：<code><?=h($status['fingerprint'])?></code></p>
          <p class="footnote">解密私钥在创建时只提供一次，不会保存在服务器，也不能再次下载。如已经遗失，请先确认是否存在需要恢复的旧备份，不能直接重置密钥。</p>
        <?php else: ?>
          <p>点击下方按钮，后台自动创建独立的备份加密密钥对，将公钥保存至受保护的 storage，立即下载私钥文件。这个私钥可以解密之后生成的数据库和关键存储文件备份。</p>
          <form method="post" action="index.php" data-backup-key-download>
            <input type="hidden" name="action" value="backup_key_generate">
            <input type="hidden" name="csrf" value="<?=h(csrf())?>">
            <button class="btn primary" type="submit">生成备份密钥并下载私钥（仅此一次）</button>
          </form>
          <p class="footnote">请将下载的 32 字节 .key 文件放入独立的加密离线存储，并确认保存成功后再创建备份。不要上传 GitHub 或发送到聊天窗口。该私钥与 Ed25519 签名密钥完全不同。</p>
        <?php endif ?>
    </div>
    <div class="card"><div class="card-head"><h2>使用边界</h2></div>
      <p class="muted">密钥初始化不会触发数据库备份，也不提供定时任务、异地同步、密钥轮换或在线恢复。生成公钥后，可通过现有的 PHP CLI 备份工具执行加密导出；恢复操作必须在隔离环境中使用离线私钥。</p>
    </div>
    <?php
}
