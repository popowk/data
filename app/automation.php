<?php
declare(strict_types=1);
// PhoneHub automation v1: scoped machine credentials, staged client releases,
// explicit owner approval for stable, and idempotent publication/disable.
require_once __DIR__.'/releases.php';

const AUTOMATION_PERMISSIONS=['release:prepare','release:read','release:publish','release:disable'];
const AUTOMATION_RATE_PER_MINUTE=60;

function automation_fail(string $code,string $message,int $http=400): never {
    http_response_code($http);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode(['ok'=>false,'error_code'=>$code,'error'=>$message],JSON_UNESCAPED_UNICODE);
    exit;
}
function automation_ok(array $data,int $http=200): never {
    http_response_code($http);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode(['ok'=>true]+$data,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
    exit;
}
function automation_list_input(mixed $input,array $allow,string $name): array {
    if (!is_array($input) || !$input || count($input)>count($allow))
        throw new RuntimeException('请选择有效的'.$name);
    $out=[];
    foreach ($input as $item) {
        if (!is_string($item) || !in_array($item,$allow,true) || in_array($item,$out,true))
            throw new RuntimeException($name.'存在非法或重复值');
        $out[]=$item;
    }
    return $out;
}
function automation_csv_list(string $value): array {
    $data=json_decode($value,true);
    return is_array($data)?$data:[];
}
function automation_issue_token(array $details,int $createdBy): array {
    $secret='phat_'.bin2hex(random_bytes(32));
    $hash=hash('sha256',$secret);
    sql('INSERT INTO phonehub_automation_tokens
      (label,token_hash,platforms,channels,permissions,source_ip,expires_at,created_by)
      VALUES(?,?,?,?,?,?,?,?)',[
        $details['label'],$hash,json_encode($details['platforms']),
        json_encode($details['channels']),json_encode($details['permissions']),
        $details['source_ip'],$details['expires_at'],$createdBy
    ]);
    return ['token_id'=>(int)db()->lastInsertId(),'token'=>$secret];
}
function automation_admin_action(string $action): never {
    require_owner();
    if ($action==='automation_token_create') {
        $label=trim((string)($_POST['label']??''));
        if ($label==='' || utf8_length($label)>64) throw new RuntimeException('令牌名称须为 1–64 字');
        $platforms=automation_list_input($_POST['platforms']??null,
            ['core','douyin','xiaohongshu','mcp','skill','mcp-codex','mcp-harness'],'平台范围');
        $channels=automation_list_input($_POST['channels']??null,['beta','stable'],'发布渠道');
        $permissions=automation_list_input($_POST['permissions']??null,AUTOMATION_PERMISSIONS,'API 权限');
        $days=filter_var($_POST['expires_days']??null,FILTER_VALIDATE_INT);
        if ($days===false || $days<1 || $days>365) throw new RuntimeException('令牌有效期须为 1–365 天');
        $source=trim((string)($_POST['source_ip']??''));
        if ($source!=='' && !filter_var($source,FILTER_VALIDATE_IP))
            throw new RuntimeException('来源 IP 必须是完整的 IPv4 或 IPv6 地址');
        $expires=gmdate('Y-m-d H:i:s',time()+$days*86400);
        $issued=automation_issue_token([
            'label'=>$label,'platforms'=>$platforms,'channels'=>$channels,
            'permissions'=>$permissions,'source_ip'=>$source?:null,'expires_at'=>$expires
        ],admin_id());
        audit('automation_token_create',(string)$issued['token_id']);
        automation_ok(['message'=>'令牌已创建；完整值仅显示一次','expires_at'=>$expires]+$issued);
    }
    if ($action==='automation_token_revoke' || $action==='automation_token_rotate') {
        $id=filter_var($_POST['id']??null,FILTER_VALIDATE_INT);
        if (!$id || $id<1) throw new RuntimeException('令牌 ID 无效');
        db()->beginTransaction();
        $row=sql('SELECT * FROM phonehub_automation_tokens WHERE id=? FOR UPDATE',[$id])->fetch();
        if (!$row) throw new RuntimeException('令牌不存在');
        if ($action==='automation_token_revoke') {
            if (!$row['revoked_at'])
                sql('UPDATE phonehub_automation_tokens SET revoked_at=UTC_TIMESTAMP() WHERE id=?',[$id]);
            audit('automation_token_revoke',(string)$id);
            db()->commit();
            automation_ok(['message'=>'令牌已撤销','token_id'=>$id]);
        }
        if ($row['revoked_at'] || strtotime((string)$row['expires_at'].' UTC')<=time())
            throw new RuntimeException('已撤销或已到期令牌不能直接轮换，请创建新令牌');
        // Rotation preserves the remaining scope and expiry; never extends privileges.
        $issued=automation_issue_token([
            'label'=>(string)$row['label'],
            'platforms'=>automation_csv_list((string)$row['platforms']),
            'channels'=>automation_csv_list((string)$row['channels']),
            'permissions'=>automation_csv_list((string)$row['permissions']),
            'source_ip'=>$row['source_ip'],
            'expires_at'=>$row['expires_at']
        ],admin_id());
        sql('UPDATE phonehub_automation_tokens SET revoked_at=UTC_TIMESTAMP() WHERE id=?',[$id]);
        audit('automation_token_rotate',$id.' -> '.$issued['token_id']);
        db()->commit();
        automation_ok(['message'=>'令牌已轮换；旧令牌立即失效','expires_at'=>$row['expires_at']]+$issued);
    }
    if (in_array($action,['automation_release_approve','automation_release_reject'],true)) {
        $id=filter_var($_POST['id']??null,FILTER_VALIDATE_INT);
        if (!$id || $id<1) throw new RuntimeException('发布任务 ID 无效');
        db()->beginTransaction();
        $row=sql('SELECT * FROM phonehub_automation_releases WHERE id=? FOR UPDATE',[$id])->fetch();
        if (!$row) throw new RuntimeException('发布任务不存在');
        if ($row['status']!=='prepared') throw new RuntimeException('当前状态不能批准或拒绝');
        if ($action==='automation_release_approve') {
            if ($row['channel']!=='stable') throw new RuntimeException('beta 不需要主管理员批准');
            if ($row['approved_at']===null) {
                automation_verify_stage_file($row);
                sql('UPDATE phonehub_automation_releases SET approved_by=?,approved_at=UTC_TIMESTAMP() WHERE id=?',[admin_id(),$id]);
                audit('automation_release_approve',$row['platform'].'/'.$row['channel'].' v'.$row['version']);
            }
            db()->commit();
            automation_ok(['message'=>'已批准 stable 发布；有对应发布权限的令牌可继续发布','id'=>$id]);
        }
        sql("UPDATE phonehub_automation_releases SET status='rejected' WHERE id=?",[$id]);
        audit('automation_release_reject',$row['platform'].'/'.$row['channel'].' v'.$row['version']);
        db()->commit();
        @unlink(release_store().'/'.$row['storage_name']);
        automation_ok(['message'=>'待发布版本已拒绝','id'=>$id]);
    }
    throw new RuntimeException('未知自动化管理操作');
}
function automation_require_https(): void {
    $https=(!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off')
        || ((string)($_SERVER['SERVER_PORT']??'')==='443');
    $localTest=PHP_SAPI==='cli-server' && getenv('PHONEHUB_AUTOMATION_TEST_ALLOW_HTTP')==='1'
        && in_array((string)($_SERVER['REMOTE_ADDR']??''),['127.0.0.1','::1'],true);
    if (!$https && !$localTest)
        automation_fail('HTTPS_REQUIRED','自动化发布仅允许 HTTPS',403);
}
function automation_auth(string $permission): array {
    automation_require_https();
    $header=(string)($_SERVER['HTTP_AUTHORIZATION']??$_SERVER['REDIRECT_HTTP_AUTHORIZATION']??'');
    if (!preg_match('/^Bearer (phat_[0-9a-f]{64})$/D',$header,$match))
        automation_fail('UNAUTHORIZED','未提供有效的自动化发布令牌',401);
    $hash=hash('sha256',$match[1]);
    $row=sql('SELECT * FROM phonehub_automation_tokens
      WHERE token_hash=? AND revoked_at IS NULL AND expires_at>UTC_TIMESTAMP()',[$hash])->fetch();
    if (!$row) automation_fail('UNAUTHORIZED','自动化令牌无效或已到期',401);
    if ($row['source_ip']!==null &&
        !hash_equals((string)$row['source_ip'],(string)($_SERVER['REMOTE_ADDR']??'')))
        automation_fail('SOURCE_DENIED','自动化令牌不允许当前来源 IP',403);
    $permissions=automation_csv_list((string)$row['permissions']);
    if (!in_array($permission,$permissions,true)) automation_fail('PERMISSION_DENIED','令牌没有此操作权限',403);
    // Atomic one-minute counter; disabled/expired credentials do not consume quota.
    sql('INSERT INTO phonehub_automation_rate(token_id,window_start,requests)
       VALUES(?,DATE_FORMAT(UTC_TIMESTAMP(),"%Y-%m-%d %H:%i:00"),1)
       ON DUPLICATE KEY UPDATE requests=requests+1',[(int)$row['id']]);
    $rate=(int)sql('SELECT requests FROM phonehub_automation_rate
       WHERE token_id=? AND window_start=DATE_FORMAT(UTC_TIMESTAMP(),"%Y-%m-%d %H:%i:00")',[(int)$row['id']])->fetchColumn();
    if ($rate>AUTOMATION_RATE_PER_MINUTE)
        automation_fail('RATE_LIMIT','自动化调用超过每分钟限制',429);
    // Bounded retention of atomic minute buckets, sampled to avoid a cleanup
    // query on every request. Historical audit remains in its own table.
    if (random_int(1,128)===1)
        sql('DELETE FROM phonehub_automation_rate WHERE window_start<DATE_SUB(UTC_TIMESTAMP(),INTERVAL 2 DAY)');
    sql('UPDATE phonehub_automation_tokens SET last_used_at=UTC_TIMESTAMP() WHERE id=?',[$row['id']]);
    $row['platform_list']=automation_csv_list((string)$row['platforms']);
    $row['channel_list']=automation_csv_list((string)$row['channels']);
    return $row;
}
function automation_scope(array $token,string $platform,string $channel): void {
    if (!in_array($platform,$token['platform_list'],true) ||
        !in_array($channel,$token['channel_list'],true))
        automation_fail('SCOPE_DENIED','发布目标或渠道超出令牌范围',403);
}
function automation_event(?int $tokenId,string $event,?int $releaseId,string $detail=''): void {
    // Only a bounded event label and process state; never log credentials or ZIP content.
    sql('INSERT INTO phonehub_automation_audit(token_id,event,release_id,detail,source_ip)
       VALUES(?,?,?,?,?)',[$tokenId,$event,$releaseId,substr($detail,0,120),
       substr((string)($_SERVER['REMOTE_ADDR']??''),0,45)]);
}
function automation_valid_id(mixed $value): int {
    if (!is_string($value) && !is_int($value)) automation_fail('INVALID_ID','发布任务 ID 无效');
    $id=filter_var($value,FILTER_VALIDATE_INT);
    if ($id===false || $id<1) automation_fail('INVALID_ID','发布任务 ID 无效');
    return $id;
}
function automation_verify_stage_file(array $row): string {
    $name=(string)$row['storage_name'];
    if (!preg_match('/^[0-9a-f]{40}\.zip$/D',$name))
        throw new RuntimeException('暂存文件路径格式错误');
    $path=release_store().'/'.$name;
    if (is_link($path) || !is_file($path) ||
        (int)filesize($path)!==(int)$row['size_bytes'] ||
        !hash_equals((string)$row['sha256'],(string)hash_file('sha256',$path)))
        throw new RuntimeException('暂存 ZIP 已缺失或内容发生变化，拒绝发布');
    inspect_release_zip($path);
    return $path;
}
function automation_public_stage(array $row): array {
    return [
        'id'=>(int)$row['id'],'platform'=>$row['platform'],'channel'=>$row['channel'],
        'version'=>$row['version'],'min_client'=>$row['min_client'],'status'=>$row['status'],
        'sha256'=>$row['sha256'],'size_bytes'=>(int)$row['size_bytes'],
        'filename'=>$row['filename'],'notes'=>$row['notes'],
        'commit_sha'=>$row['commit_sha'],'build_run_id'=>$row['build_run_id'],
        'submitted_at'=>$row['created_at'],'approved'=>(bool)$row['approved_at'],
        'approved_at'=>$row['approved_at'],
        'release_id'=>$row['published_release_id']===null?null:(int)$row['published_release_id'],
        'published_enabled'=>isset($row['public_enabled'])?((int)$row['public_enabled']===1):null,
        'client_install_verified'=>false // No attested client install report is implemented.
    ];
}
function automation_check_version_floor(string $platform,string $channel,string $version): void {
    // Disabled releases remain part of the version floor. A machine must not
    // republish an older version under a fresh task after a newer version
    // was already published, even if that newer release is now disabled.
    $rows=sql('SELECT version FROM phonehub_releases WHERE platform=? AND channel=?',[$platform,$channel])->fetchAll();
    foreach($rows as $row) {
        if (version_compare($version,(string)$row['version'],'<'))
            throw new AutomationHttpException('VERSION_ROLLBACK',
                '版本号低于已发布的历史版本，拒绝回退',409);
    }
}
function automation_prepare(array $token): never {
    $platform=trim((string)($_POST['platform']??''));
    $channel=trim((string)($_POST['channel']??''));
    try {release_platform($platform);release_channel($channel);}
    catch(Throwable $e) {automation_fail('INVALID_SCOPE','发布目标或渠道无效');}
    automation_scope($token,$platform,$channel);
    $version=trim((string)($_POST['version']??''));
    $min=trim((string)($_POST['min_client']??'0.7.1'));
    if (!valid_version($version) || !valid_version($min))
        automation_fail('INVALID_VERSION','版本号格式不正确');
    $notes=trim((string)($_POST['notes']??''));
    if (strlen($notes)>1000 || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F]/',$notes))
        automation_fail('INVALID_NOTES','版本说明无效');
    $expected=(string)($_POST['sha256']??'');
    if (!preg_match('/^[0-9a-f]{64}$/D',$expected))
        automation_fail('INVALID_SHA256','必须提交构建 ZIP 的小写 SHA-256');
    $key=(string)($_POST['idempotency_key']??'');
    if (!preg_match('/^[a-zA-Z0-9_-]{8,64}$/D',$key))
        automation_fail('INVALID_IDEMPOTENCY_KEY','必须提供 8–64 位幂等键');
    $commit=trim((string)($_POST['commit_sha']??''));
    if ($commit!=='' && !preg_match('/^[0-9a-f]{40}$/D',$commit))
        automation_fail('INVALID_COMMIT','Git Commit SHA 格式不正确');
    $run=trim((string)($_POST['build_run_id']??''));
    if (strlen($run)>100 || ($run!=='' && !preg_match('/^[a-zA-Z0-9_.:-]+$/D',$run)))
        automation_fail('INVALID_BUILD','构建运行 ID 格式不正确');
    $existing=sql('SELECT *,NULL AS public_enabled FROM phonehub_automation_releases WHERE token_id=? AND idempotency_key=?',
        [(int)$token['id'],$key])->fetch();
    if ($existing) {
        if ($existing['platform']!==$platform || $existing['channel']!==$channel ||
            $existing['version']!==$version || !hash_equals($existing['sha256'],$expected) ||
            $existing['min_client']!==$min ||
            ($notes!=='' && $existing['notes']!==$notes) ||
            ($commit!=='' && $existing['commit_sha']!==$commit) ||
            ($run!=='' && $existing['build_run_id']!==$run))
            automation_fail('IDEMPOTENCY_CONFLICT','幂等键对应另一份发布内容',409);
        automation_ok(['release'=>automation_public_stage($existing),'replayed'=>true]);
    }
    // Check both in prepare and again at publish: an old prepared upload may
    // become stale when a higher version is published in the meantime.
    automation_check_version_floor($platform,$channel,$version);
    $file=$_FILES['file']??null;
    if (!is_array($file) || (int)($file['error']??-1)!==UPLOAD_ERR_OK ||
        !is_uploaded_file((string)($file['tmp_name']??'')))
        automation_fail('UPLOAD_FAILED','缺少上传 ZIP 或上传失败');
    $size=(int)($file['size']??0);
    if ($size<1 || $size>CLIENT_RELEASE_LIMIT ||
        !is_file((string)$file['tmp_name']) || filesize($file['tmp_name'])!==$size)
        automation_fail('UPLOAD_LIMIT','ZIP 不可用或超过 50 MiB',413);
    $filename=basename((string)($file['name']??''));
    if (!preg_match('/^[a-zA-Z0-9_.-]{1,160}\.zip$/iD',$filename))
        automation_fail('INVALID_FILENAME','ZIP 文件名不符合规则');
    if (!hash_equals($expected,(string)hash_file('sha256',(string)$file['tmp_name'])))
        automation_fail('SHA256_MISMATCH','上传 ZIP 与构建摘要不一致',422);
    inspect_release_zip((string)$file['tmp_name']);
    $random=bin2hex(random_bytes(20)).'.zip';
    $dest=release_store().'/'.$random;
    if (!move_uploaded_file($file['tmp_name'],$dest))
        automation_fail('UPLOAD_FAILED','服务器无法保存 ZIP',503);
    @chmod($dest,0600);
    try {
        db()->beginTransaction();
        if (sql('SELECT id FROM phonehub_releases WHERE platform=? AND channel=? AND version=?',
            [$platform,$channel,$version])->fetch())
            automation_fail_in_transaction('VERSION_CONFLICT','此平台/渠道/版本已经发布',409);
        // Unique keys on staged scope and token/idempotency key prevent races.
        sql('INSERT INTO phonehub_automation_releases
          (token_id,idempotency_key,platform,channel,version,min_client,notes,filename,
           storage_name,size_bytes,sha256,commit_sha,build_run_id,status)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,"prepared")',[
            (int)$token['id'],$key,$platform,$channel,$version,$min,$notes,
            $filename,$random,$size,$expected,$commit?:null,$run?:null
        ]);
        $id=(int)db()->lastInsertId();
        automation_event((int)$token['id'],'prepare',$id,$platform.'/'.$channel.' v'.$version);
        db()->commit();
    } catch(Throwable $e) {
        if (db()->inTransaction()) db()->rollBack();
        @unlink($dest);
        if ($e instanceof PDOException && $e->getCode()==='23000')
            automation_fail('VERSION_CONFLICT','此版本或幂等键已存在',409);
        throw $e;
    }
    automation_ok(['release'=>automation_public_stage(sql('SELECT *,NULL AS public_enabled FROM phonehub_automation_releases WHERE id=?',[$id])->fetch()),'replayed'=>false],201);
}
function automation_fail_in_transaction(string $code,string $message,int $http): never {
    if (db()->inTransaction()) db()->rollBack();
    throw new AutomationHttpException($code,$message,$http);
}
class AutomationHttpException extends RuntimeException {
    public function __construct(public string $errorCode,string $message,public int $http) {
        parent::__construct($message);
    }
}
function automation_get_row(int $id,array $token,bool $lock=false): array {
    $row=sql('SELECT a.*,r.enabled AS public_enabled FROM phonehub_automation_releases a
        LEFT JOIN phonehub_releases r ON r.id=a.published_release_id
        WHERE a.id=?'.($lock?' FOR UPDATE':''),[$id])->fetch();
    if (!$row) automation_fail('NOT_FOUND','发布任务不存在',404);
    automation_scope($token,(string)$row['platform'],(string)$row['channel']);
    return $row;
}
function automation_publish(int $id,array $token): never {
    db()->beginTransaction();
    $row=automation_get_row($id,$token,true);
    if ($row['status']==='published') {
        db()->commit();
        automation_ok(['release'=>automation_public_stage($row),'replayed'=>true]);
    }
    if ($row['status']!=='prepared')
        automation_fail_in_transaction('INVALID_STATE','当前任务不能发布',409);
    if ($row['channel']==='stable' && $row['approved_at']===null)
        automation_fail_in_transaction('APPROVAL_REQUIRED','stable 必须经主管理员审批',403);
    if (sql('SELECT id FROM phonehub_releases WHERE platform=? AND channel=? AND version=?',
        [$row['platform'],$row['channel'],$row['version']])->fetch())
        automation_fail_in_transaction('VERSION_CONFLICT','版本号已由其他发布入口使用',409);
    automation_check_version_floor($row['platform'],$row['channel'],$row['version']);
    $path=automation_verify_stage_file($row);
    [$secret,$pub]=release_keypair();
    $raw=json_encode([
        'format'=>1,'platform'=>$row['platform'],'channel'=>$row['channel'],
        'version'=>$row['version'],'min_client'=>$row['min_client'],
        'filename'=>$row['filename'],'size_bytes'=>(int)$row['size_bytes'],
        'sha256'=>$row['sha256'],'notes'=>$row['notes'],
        'released_at'=>gmdate('Y-m-d\TH:i:s\Z')
    ],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
    $signature=base64_encode(sodium_crypto_sign_detached($raw,$secret));
    try {
        sql('INSERT INTO phonehub_releases
          (platform,channel,version,min_client,notes,filename,storage_name,size_bytes,sha256,manifest,signature)
          VALUES(?,?,?,?,?,?,?,?,?,?,?)',[
            $row['platform'],$row['channel'],$row['version'],$row['min_client'],
            $row['notes'],$row['filename'],$row['storage_name'],(int)$row['size_bytes'],
            $row['sha256'],$raw,$signature
        ]);
    } catch(PDOException $e) {
        if ($e->getCode()==='23000')
            automation_fail_in_transaction('VERSION_CONFLICT','版本已由其他发布入口占用',409);
        throw $e;
    }
    $publicId=(int)db()->lastInsertId();
    sql("UPDATE phonehub_automation_releases SET status='published',published_release_id=?,published_at=UTC_TIMESTAMP() WHERE id=?",[$publicId,$id]);
    automation_event((int)$token['id'],'publish',$id,$row['platform'].'/'.$row['channel'].' v'.$row['version']);
    db()->commit();
    $new=automation_get_row($id,$token);
    automation_ok(['release'=>automation_public_stage($new),'public_release_id'=>$publicId,'replayed'=>false]);
}
function automation_disable(int $id,array $token): never {
    db()->beginTransaction();
    $row=automation_get_row($id,$token,true);
    $next=$row['status'];
    if ($next==='prepared') {
        $next='cancelled';
    } elseif ($next==='published' || $next==='disabled') {
        if ($row['published_release_id']!==null)
            sql('UPDATE phonehub_releases SET enabled=0 WHERE id=?',[$row['published_release_id']]);
        $next='disabled';
    } elseif ($next!=='rejected' && $next!=='cancelled') {
        automation_fail_in_transaction('INVALID_STATE','当前状态不能停用',409);
    }
    if ($row['status']!==$next) {
        sql('UPDATE phonehub_automation_releases SET status=? WHERE id=?',[$next,$id]);
        automation_event((int)$token['id'],'disable',$id,$row['platform'].'/'.$row['channel'].' v'.$row['version']);
    }
    db()->commit();
    if ($next==='cancelled') @unlink(release_store().'/'.$row['storage_name']);
    $updated=automation_get_row($id,$token);
    automation_ok(['release'=>automation_public_stage($updated)]);
}
function automation_api(): never {
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    if (!installed()) automation_fail('NOT_INSTALLED','PhoneHub 尚未安装',503);
    $route=(string)($_GET['route']??'');
    $route=trim($route,'/');
    $method=(string)($_SERVER['REQUEST_METHOD']??'GET');
    if ($method==='GET' && $route==='releases') {
        $token=automation_auth('release:read');
        $platforms=$token['platform_list'];$channels=$token['channel_list'];
        $p=implode(',',array_fill(0,count($platforms),'?'));
        $c=implode(',',array_fill(0,count($channels),'?'));
        $params=array_merge($platforms,$channels);
        $staged=sql("SELECT a.*,r.enabled AS public_enabled
            FROM phonehub_automation_releases a
            LEFT JOIN phonehub_releases r ON r.id=a.published_release_id
            WHERE a.platform IN ($p) AND a.channel IN ($c) ORDER BY a.id DESC LIMIT 50",$params)->fetchAll();
        $published=sql("SELECT id,platform,channel,version,sha256,enabled,created_at
            FROM phonehub_releases WHERE platform IN ($p) AND channel IN ($c)
            ORDER BY id DESC LIMIT 50",$params)->fetchAll();
        automation_ok(['releases'=>array_map('automation_public_stage',$staged),
            'published_releases'=>$published,'limit'=>50]);
    }
    if ($method==='POST' && $route==='releases/prepare') {
        $token=automation_auth('release:prepare');
        automation_prepare($token);
    }
    if (preg_match('~^releases/([1-9][0-9]*)(?:/(publish|disable))?$~D',$route,$match)) {
        $id=automation_valid_id($match[1]);
        if ($method==='GET' && !isset($match[2])) {
            $token=automation_auth('release:read');
            automation_ok(['release'=>automation_public_stage(automation_get_row($id,$token))]);
        }
        if ($method==='POST' && ($match[2]??'')==='publish') {
            $token=automation_auth('release:publish');
            automation_publish($id,$token);
        }
        if ($method==='POST' && ($match[2]??'')==='disable') {
            $token=automation_auth('release:disable');
            automation_disable($id,$token);
        }
    }
    automation_fail('NOT_FOUND','自动化接口或请求方法不存在',404);
}
function automation_admin_view(): void {
    require_global_admin();
    $canOperate=admin_role()==='owner';
    $tokens=sql('SELECT id,label,platforms,channels,permissions,source_ip,expires_at,revoked_at,last_used_at
        FROM phonehub_automation_tokens ORDER BY id DESC LIMIT 50')->fetchAll();
    $stages=sql('SELECT a.id,a.platform,a.channel,a.version,a.status,a.sha256,a.size_bytes,
        a.approved_at,a.created_at,a.commit_sha,a.build_run_id,t.label AS token_label
        FROM phonehub_automation_releases a LEFT JOIN phonehub_automation_tokens t ON t.id=a.token_id
        ORDER BY a.id DESC LIMIT 60')->fetchAll();
    ?>
    <div class="card"><div class="card-head"><h2>AI / CI 专用发布令牌</h2></div>
      <p class="muted">令牌仅显示一次，正式版发布需主账号审批。</p>
      <?php if($canOperate): ?><form data-ajax="automation_token_create">
        <div class="form-grid">
          <div class="field"><label>令牌名称</label><input name="label" required maxlength="64" placeholder="CI beta 发布机器人"></div>
          <div class="field"><label>有效期（天）</label><input name="expires_days" type="number" min="1" max="365" value="30" required></div>
          <div class="field span2"><label>限制来源 IP（可留空）</label><input name="source_ip" placeholder="仅此真实来源 IP；不信任 X-Forwarded-For"></div>
          <div class="field span2"><label>平台</label><div class="check-row">
            <?php foreach(['core','douyin','xiaohongshu','mcp','skill','mcp-codex','mcp-harness'] as $p): ?>
            <label><input type="checkbox" name="platforms[]" value="<?=h($p)?>" <?=$p==='core'?'checked':''?>> <?=h($p)?></label>
            <?php endforeach ?></div></div>
          <div class="field span2"><label>渠道</label><div class="check-row">
            <label><input type="checkbox" name="channels[]" value="beta" checked> beta</label>
            <label><input type="checkbox" name="channels[]" value="stable"> stable（必须审批）</label>
          </div></div>
          <div class="field span2"><label>权限</label><div class="check-row">
            <?php foreach(AUTOMATION_PERMISSIONS as $p): ?>
            <label><input type="checkbox" name="permissions[]" value="<?=h($p)?>" checked> <?=h($p)?></label>
            <?php endforeach ?></div></div>
        </div><div class="editor-actions"><button class="btn primary">生成一次性令牌</button></div>
      </form><?php endif ?>
      <div class="table-scroll"><table><thead><tr><th>令牌</th><th>范围与权限</th><th>到期 / 最近使用</th><th>状态</th><th>操作</th></tr></thead><tbody>
      <?php foreach($tokens as $t): ?>
      <tr><td><b>#<?=(int)$t['id']?> <?=h($t['label'])?></b></td>
      <td><?=h(implode('、',automation_csv_list($t['platforms'])))?> / <?=h(implode('、',automation_csv_list($t['channels'])))?><small><?=h(implode('、',automation_csv_list($t['permissions'])))?><?=$t['source_ip']?' · IP '.h($t['source_ip']):''?></small></td>
      <td><?=h($t['expires_at'])?> UTC <small><?=h($t['last_used_at']??'从未使用')?></small></td>
      <td><?= $t['revoked_at']?'已撤销':(strtotime($t['expires_at'].' UTC')<=time()?'已过期':'有效')?></td>
      <td><?php if($canOperate && !$t['revoked_at'] && strtotime($t['expires_at'].' UTC')>time()): ?>
        <button class="small-link" data-action="automation-token-rotate" data-id="<?=(int)$t['id']?>">轮换</button>
        <button class="small-link" data-action="automation-token-revoke" data-id="<?=(int)$t['id']?>">撤销</button>
      <?php endif ?></td></tr>
      <?php endforeach ?></tbody></table></div>
    </div>
    <div class="card"><div class="card-head"><h2>待发布任务与稳定版审批</h2><span class="count">最近 60 条</span></div>
      <p class="muted">测试版可自动发布，正式版需主账号审批；审批不等于客户端安装验证。</p>
      <div class="table-scroll"><table><thead><tr><th>任务 / 来源</th><th>发布目标</th><th>提交摘要</th><th>状态 / 审批</th><th>操作</th></tr></thead><tbody>
      <?php foreach($stages as $r): ?>
      <tr><td>#<?=(int)$r['id']?> <?=h($r['token_label']??'已删除令牌')?> <small><?=h($r['created_at'])?> UTC</small></td>
      <td><?=h($r['platform'].' / '.$r['channel'].' / '.$r['version'])?></td>
      <td><code><?=h(substr($r['sha256'],0,16))?>…</code> <small><?=h($r['commit_sha']??'')?></small></td>
      <td><?=h($r['status'])?> <?=$r['approved_at']?'· 已批准':''?></td>
      <td><?php if($canOperate && $r['status']==='prepared' && $r['channel']==='stable' && !$r['approved_at']): ?>
         <button class="small-link" data-action="automation-release-approve" data-id="<?=(int)$r['id']?>">批准 stable</button>
      <?php endif ?>
      <?php if($canOperate && $r['status']==='prepared'): ?>
         <button class="small-link" data-action="automation-release-reject" data-id="<?=(int)$r['id']?>">拒绝</button>
      <?php endif ?></td></tr>
      <?php endforeach ?></tbody></table></div>
      <details class="help-details"><summary>自动发布接口说明</summary><p>配置方法见 <code>docs/自动化核心更新API-v0.5.12.md</code>。Nginx 未设置路由时，可使用 <code>automation/v1/index.php?route=releases/...</code>。</p></details>
    </div>
    <?php
}
