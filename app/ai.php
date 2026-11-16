<?php
declare(strict_types=1);

const AI_DEFAULT_PROVIDER='deepseek';
const AI_DEFAULT_MODEL='deepseek-flash';
const AI_ALLOWED_MODELS=['deepseek-flash','deepseek-v4-pro'];
const AI_DEEPSEEK_CHAT_URL='https://api.deepseek.com/chat/completions';
const AI_MAX_REQUEST_BYTES=262144;
const AI_MAX_RESPONSE_BYTES=4194304;

function ai_setting(string $key,string $fallback=''): string {
    $value=client_sql('SELECT setting_value FROM phonehub_ai_settings WHERE setting_key=?',[$key])->fetchColumn();
    return $value===false?$fallback:(string)$value;
}
function ai_settings(): array {
    $model=ai_setting('model',AI_DEFAULT_MODEL);
    $cipher=ai_setting('api_key_ciphertext','');
    $keyUsable=false;
    if ($cipher!=='') { try {$keyUsable=ai_decrypt_secret($cipher)!=='';} catch(Throwable $e) {$keyUsable=false;} }
    return [
        'enabled'=>ai_setting('enabled','1')==='1',
        'provider'=>AI_DEFAULT_PROVIDER,
        'model'=>in_array($model,AI_ALLOWED_MODELS,true)?$model:AI_DEFAULT_MODEL,
        'client_key_enabled'=>ai_setting('client_key_enabled','0')==='1',
        'max_tokens'=>max(256,min(8192,(int)ai_setting('max_tokens','4096'))),
        'requests_per_minute'=>max(1,min(30,(int)ai_setting('requests_per_minute','10'))),
        'server_key_configured'=>$keyUsable
    ];
}
function ai_master_key(bool $create=true): string {
    $path=APP_STORE.'/ai-master.key';
    if (is_link($path)) throw new RuntimeException('AI 主密钥文件不能是符号链接');
    if (is_file($path)) {
        $key=file_get_contents($path);
        if (!is_string($key) || strlen($key)!==SODIUM_CRYPTO_SECRETBOX_KEYBYTES)
            throw new RuntimeException('AI 主密钥文件损坏');
        if (PHP_OS_FAMILY!=='Windows') {
            $mode=fileperms($path);
            if ($mode===false || (($mode & 0077)!==0 && !chmod($path,0600)))
                throw new RuntimeException('AI 主密钥权限不安全，无法限制为仅服务器用户可读');
        }
        return $key;
    }
    if (!$create) throw new RuntimeException('AI 主密钥文件丢失，禁止自动重建以免永久丢失原密钥');
    $key=random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    $fp=@fopen($path,'x+b');
    if (!$fp) {
        if (is_file($path)) return ai_master_key($create);
        if (!$create) throw new RuntimeException('AI 主密钥文件丢失，禁止自动重建以免永久丢失原密钥');
        throw new RuntimeException('无法安全创建 AI 主密钥文件');
    }
    try {
        if (fwrite($fp,$key)!==strlen($key) || !fflush($fp)) {
            @unlink($path);
            throw new RuntimeException('无法写入 AI 主密钥文件');
        }
        if (PHP_OS_FAMILY!=='Windows' && !chmod($path,0600)) {
            @unlink($path);
            throw new RuntimeException('无法将 AI 主密钥权限限制为仅服务器用户可读');
        }
    } finally {fclose($fp);}
    return $key;
}
function ai_encrypt_secret(string $secret): string {
    if (!extension_loaded('sodium')) throw new RuntimeException('服务器需要启用 PHP sodium 扩展');
    if ($secret==='') return '';
    $nonce=random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    return base64_encode($nonce.sodium_crypto_secretbox($secret,$nonce,ai_master_key()));
}
function ai_decrypt_secret(string $encoded): string {
    if ($encoded==='') return '';
    if (!extension_loaded('sodium')) throw new RuntimeException('服务器需要启用 PHP sodium 扩展');
    $raw=base64_decode($encoded,true);
    if (!is_string($raw) || strlen($raw)<=SODIUM_CRYPTO_SECRETBOX_NONCEBYTES)
        throw new RuntimeException('AI 服务密钥密文格式错误');
    $nonce=substr($raw,0,SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $plain=sodium_crypto_secretbox_open(substr($raw,SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),$nonce,ai_master_key(false));
    if (!is_string($plain)) throw new RuntimeException('AI 服务密钥解密失败，请检查主密钥备份');
    return $plain;
}
function ai_server_secret(): string {
    return ai_decrypt_secret(ai_setting('api_key_ciphertext',''));
}
function ai_save_settings(array $post): array {
    require_owner();
    $enabled=isset($post['enabled'])?'1':'0';
    $byok=isset($post['client_key_enabled'])?'1':'0';
    $model=(string)($post['model']??AI_DEFAULT_MODEL);
    if (!in_array($model,AI_ALLOWED_MODELS,true)) throw new RuntimeException('只允许选择已审核的 DeepSeek 模型');
    $max=(int)($post['max_tokens']??4096);
    $rpm=(int)($post['requests_per_minute']??10);
    if ($max<256 || $max>8192) throw new RuntimeException('单次最大输出 Token 必须在 256–8192 之间');
    if ($rpm<1 || $rpm>30) throw new RuntimeException('每客户每分钟请求上限必须在 1–30 之间');
    $newSecret=trim((string)($post['api_key']??''));
    if (strlen($newSecret)>512 || preg_match('/[\r\n\x00]/',$newSecret)) throw new RuntimeException('DeepSeek API Key 格式不正确');
    $remove=isset($post['remove_api_key']);
    if ($newSecret!=='' && $remove) throw new RuntimeException('不能同时提交新密钥和删除密钥');
    if ($newSecret!=='') {
        if (!preg_match('/^[A-Za-z0-9._-]{16,512}$/D',$newSecret)) throw new RuntimeException('DeepSeek API Key 含有不允许的字符');
        $cipher=ai_encrypt_secret($newSecret);
        client_sql('INSERT INTO phonehub_ai_settings(setting_key,setting_value) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)', ['api_key_ciphertext',$cipher]);
    } elseif ($remove) {
        client_sql('DELETE FROM phonehub_ai_settings WHERE setting_key=?',['api_key_ciphertext']);
    }
    $values=['enabled'=>$enabled,'client_key_enabled'=>$byok,'model'=>$model,
        'max_tokens'=>(string)$max,'requests_per_minute'=>(string)$rpm];
    foreach($values as $key=>$value) {
        client_sql('INSERT INTO phonehub_ai_settings(setting_key,setting_value) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)',[$key,$value]);
    }
    audit('ai_settings_save','enabled='.$enabled.', model='.$model.', client_key_enabled='.$byok.', secret_changed='.(($newSecret!==''||$remove)?'yes':'no'));
    return ['message'=>'AI 接口配置已保存','server_key_configured'=>ai_settings()['server_key_configured']];
}
function ai_user_policy(int $userId): array {
    $row=client_sql('SELECT ai_enabled,allow_client_ai_key,ai_daily_limit FROM phonehub_users WHERE id=?',[$userId])->fetch();
    if (!$row) api_problem('ACCOUNT_NOT_FOUND','客户账号不存在',401);
    return ['enabled'=>(int)$row['ai_enabled']===1,'allow_client_key'=>(int)$row['allow_client_ai_key']===1,
        'daily_limit'=>max(0,(int)$row['ai_daily_limit'])];
}
function ai_daily_usage(int $userId): int {
    return (int)client_sql('SELECT COUNT(*) FROM phonehub_ai_usage WHERE user_id=? AND created_at>=UTC_DATE()',[$userId])->fetchColumn();
}
function api_ai_status(int $userId): never {
    $global=ai_settings();$user=ai_user_policy($userId);$used=ai_daily_usage($userId);
    $serverUsable=$global['server_key_configured'];
    if ($serverUsable) { try {$serverUsable=ai_server_secret()!=='';} catch(Throwable $e) {$serverUsable=false;} }
    $enabled=$global['enabled'] && $user['enabled'];
    $clientAllowed=$enabled && $global['client_key_enabled'] && $user['allow_client_key'];
    api_out([
        'ok'=>true,'enabled'=>$enabled,'provider'=>AI_DEFAULT_PROVIDER,'default_model'=>$global['model'],
        'server_mode_available'=>$enabled && $serverUsable,
        'server_key_configured'=>$serverUsable,
        'client_key_allowed'=>$clientAllowed,
        'allowed_models'=>AI_ALLOWED_MODELS,
        'max_tokens'=>$global['max_tokens'],
        'requests_per_minute'=>$global['requests_per_minute'],
        'daily_limit'=>$user['daily_limit'],'daily_used'=>$used,
        'daily_remaining'=>$user['daily_limit']===0?0:max(0,$user['daily_limit']-$used)
    ]);
}
function ai_reserve_request(int $userId,string $device,string $mode,string $model,array $settings): string {
    global $pdo;
    $requestId=bin2hex(random_bytes(16));
    $pdo->beginTransaction();
    try {
        $account=client_sql('SELECT ai_enabled,allow_client_ai_key,ai_daily_limit FROM phonehub_users WHERE id=? FOR UPDATE',[$userId])->fetch();
        $globalEnabled=client_sql('SELECT setting_value FROM phonehub_ai_settings WHERE setting_key=? FOR UPDATE',['enabled'])->fetchColumn();
        if (!$account || (int)$account['ai_enabled']!==1 || $globalEnabled!=='1') {
            $pdo->rollBack();
            api_problem('AI_DISABLED','当前账号未开放 AI 功能',403);
        }
        if ($mode==='client') {
            $clientAllowed=client_sql('SELECT setting_value FROM phonehub_ai_settings WHERE setting_key=? FOR UPDATE',['client_key_enabled'])->fetchColumn();
            if ($clientAllowed!=='1' || (int)$account['allow_client_ai_key']!==1) {
                $pdo->rollBack();
                api_problem('CLIENT_KEY_FORBIDDEN','管理员尚未允许此客户使用自带 API Key',403);
            }
        }
        $minute=(int)client_sql('SELECT COUNT(*) FROM phonehub_ai_usage WHERE user_id=? AND created_at>=DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 MINUTE)',[$userId])->fetchColumn();
        if ($minute >= $settings['requests_per_minute']) {
            $pdo->rollBack();
            api_problem('AI_RATE_LIMIT','AI 请求过于频繁，请稍后重试',429);
        }
        $daily=(int)client_sql('SELECT COUNT(*) FROM phonehub_ai_usage WHERE user_id=? AND created_at>=UTC_DATE()',[$userId])->fetchColumn();
        if ((int)$account['ai_daily_limit']<1 || $daily >= (int)$account['ai_daily_limit']) {
            $pdo->rollBack();
            api_problem('AI_DAILY_LIMIT','当前账号 AI 每日额度已用完',429);
        }
        client_sql('INSERT INTO phonehub_ai_usage(request_id,user_id,device_id,mode,model,status,created_at) VALUES(?,?,?,?,?,"pending",UTC_TIMESTAMP())',
            [$requestId,$userId,$device,$mode,$model]);
        $pdo->commit();
        return $requestId;
    } catch(Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        throw $e;
    }
}
function ai_finish_request(string $requestId,string $status,int $httpStatus,int $promptTokens,int $completionTokens,int $elapsedMs): void {
    client_sql('UPDATE phonehub_ai_usage SET status=?,http_status=?,prompt_tokens=?,completion_tokens=?,elapsed_ms=? WHERE request_id=?',
        [$status,$httpStatus,max(0,$promptTokens),max(0,$completionTokens),max(0,$elapsedMs),$requestId]);
}
function api_ai_chat(array $input,array $session,int $userId): never {
    $settings=ai_settings();$policy=ai_user_policy($userId);
    if (!$settings['enabled'] || !$policy['enabled']) api_problem('AI_DISABLED','当前账号未开放 AI 功能',403);
    $mode=(string)($input['credential_mode']??'server');
    if (!in_array($mode,['server','client'],true)) api_problem('INVALID_MODE','AI 密钥模式无效');
    if ($mode==='server') {
        if (!$settings['server_key_configured']) api_problem('AI_NOT_CONFIGURED','服务器尚未配置 AI 服务密钥',503);
        $apiKey=ai_server_secret();
    } else {
        if (!$settings['client_key_enabled'] || !$policy['allow_client_key'])
            api_problem('CLIENT_KEY_FORBIDDEN','管理员尚未允许此客户使用自带 API Key',403);
        $apiKey=(string)($input['api_key']??'');
        if (strlen($apiKey)<16 || strlen($apiKey)>512 || preg_match('/[\r\n\x00]/',$apiKey))
            api_problem('INVALID_CLIENT_KEY','客户端 API Key 格式不正确');
    }
    $messages=$input['messages']??null;
    if (!is_array($messages) || !array_is_list($messages) || count($messages)<1 || count($messages)>40)
        api_problem('INVALID_MESSAGES','messages 必须为 1–40 条消息的数组');
    $clean=[];$total=0;
    foreach($messages as $message) {
        if (!is_array($message)) api_problem('INVALID_MESSAGES','消息结构不正确');
        $role=(string)($message['role']??'');
        $content=$message['content']??null;
        if (!in_array($role,['system','user','assistant'],true) || !is_string($content) || $content==='')
            api_problem('INVALID_MESSAGES','仅支持 system、user、assistant 的纯文本消息');
        $total+=strlen($content);
        if (strlen($content)>32768 || $total>131072 || preg_match('//u',$content)!==1)
            api_problem('INVALID_MESSAGES','消息内容过长或不是有效 UTF-8');
        $clean[]=['role'=>$role,'content'=>$content];
    }
    $maxTokens=(int)($input['max_tokens']??min(2048,$settings['max_tokens']));
    if ($maxTokens<1 || $maxTokens>$settings['max_tokens']) api_problem('INVALID_MAX_TOKENS','max_tokens 超出服务器限制');
    $temperature=$input['temperature']??0.7;
    if (!is_numeric($temperature) || (float)$temperature<0 || (float)$temperature>2)
        api_problem('INVALID_PARAMETER','temperature 必须在 0–2 之间');
    $topP=$input['top_p']??1.0;
    if (!is_numeric($topP) || (float)$topP<0 || (float)$topP>1)
        api_problem('INVALID_PARAMETER','top_p 必须在 0–1 之间');
    if (!empty($input['stream'])) api_problem('STREAM_UNSUPPORTED','当前版本仅支持非流式 AI 请求');
    $thinking=(string)($input['thinking']??'disabled');
    if (!in_array($thinking,['enabled','disabled'],true)) api_problem('INVALID_PARAMETER','thinking 仅支持 enabled 或 disabled');
    $model=$settings['model'];
    $requestId=ai_reserve_request($userId,(string)$session['device_id'],$mode,$model,$settings);
    $payload=[
        'model'=>$model,'messages'=>$clean,'max_tokens'=>$maxTokens,
        'temperature'=>(float)$temperature,'top_p'=>(float)$topP,'stream'=>false,
        'thinking'=>['type'=>$thinking],
        'safety_check'=>['level'=>'high']
    ];
    $body=json_encode($payload,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
    $response='';$started=microtime(true);$status=0;
    if (!extension_loaded('curl')) {
        ai_finish_request($requestId,'failed',0,0,0,(int)((microtime(true)-$started)*1000));
        api_problem('AI_TRANSPORT_UNAVAILABLE','服务器未启用 PHP cURL 扩展',503);
    }
    $ch=curl_init(AI_DEEPSEEK_CHAT_URL);
    curl_setopt_array($ch,[
        CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$body,CURLOPT_RETURNTRANSFER=>false,
        CURLOPT_CONNECTTIMEOUT=>10,CURLOPT_TIMEOUT=>90,
        CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,
        CURLOPT_FOLLOWLOCATION=>false,CURLOPT_MAXREDIRS=>0,
        CURLOPT_HTTPHEADER=>['Content-Type: application/json','Accept: application/json','Authorization: Bearer '.$apiKey],
        CURLOPT_WRITEFUNCTION=>static function($curl,string $chunk) use (&$response): int {
            if (strlen($response)+strlen($chunk)>AI_MAX_RESPONSE_BYTES) return 0;
            $response.=$chunk;return strlen($chunk);
        }
    ]);
    $ok=curl_exec($ch);$status=(int)curl_getinfo($ch,CURLINFO_RESPONSE_CODE);$curlError=curl_errno($ch);curl_close($ch);
    $elapsed=(int)((microtime(true)-$started)*1000);
    if ($ok===false || $curlError!==0 || strlen($response)>AI_MAX_RESPONSE_BYTES) {
        ai_finish_request($requestId,'failed',$status,0,0,$elapsed);
        error_log('PhoneHub AI transport failure; curl_errno='.$curlError);
        api_problem('AI_UPSTREAM_UNAVAILABLE','AI 服务暂时不可用，请稍后重试',502);
    }
    if ($status<200 || $status>=300) {
        ai_finish_request($requestId,'failed',$status,0,0,$elapsed);
        if ($status===401 || $status===403) api_problem('AI_UPSTREAM_AUTH','AI 服务密钥无效或无权调用',502);
        if ($status===429) api_problem('AI_UPSTREAM_RATE_LIMIT','AI 服务商限流，请稍后重试',429);
        api_problem('AI_UPSTREAM_ERROR','AI 服务商暂时返回错误',502);
    }
    try {$decoded=json_decode($response,true,64,JSON_THROW_ON_ERROR);}
    catch(Throwable $e) {
        ai_finish_request($requestId,'failed',$status,0,0,$elapsed);
        api_problem('AI_BAD_RESPONSE','AI 服务返回格式异常',502);
    }
    if (!is_array($decoded) || !isset($decoded['choices']) || !is_array($decoded['choices'])) {
        ai_finish_request($requestId,'failed',$status,0,0,$elapsed);
        api_problem('AI_BAD_RESPONSE','AI 服务返回格式异常',502);
    }
    $usage=is_array($decoded['usage']??null)?$decoded['usage']:[];
    ai_finish_request($requestId,'success',$status,(int)($usage['prompt_tokens']??0),(int)($usage['completion_tokens']??0),$elapsed);
    api_out($decoded);
}
function ai_admin_view(): void {
    require_owner();
    $s=ai_settings();
    $usage=sql("SELECT u.username,g.mode,g.model,g.status,g.http_status,g.prompt_tokens,g.completion_tokens,g.elapsed_ms,g.created_at
        FROM phonehub_ai_usage g JOIN phonehub_users u ON u.id=g.user_id ORDER BY g.id DESC LIMIT 100")->fetchAll();
    $today=(int)sql("SELECT COUNT(*) FROM phonehub_ai_usage WHERE created_at>=UTC_DATE()")->fetchColumn();
    ?>
    <div class="page-title"><div><h1>AI 接口管理</h1><p>默认由服务器代理 DeepSeek；服务端密钥不会下发给客户端</p></div></div>
    <div class="card"><div class="card-head"><h2>服务端 AI 中转</h2><span class="pill <?=$s['enabled']?'ok':'off'?>"><?=$s['enabled']?'已开放':'已关闭'?></span></div>
      <form data-ajax="ai_settings_save">
        <input type="hidden" name="action" value="ai_settings_save">
        <div class="form-grid">
          <div class="field"><label>服务商</label><input value="DeepSeek" readonly></div>
          <div class="field"><label>默认模型</label><select name="model"><?php foreach(AI_ALLOWED_MODELS as $m): ?><option value="<?=h($m)?>" <?=$s['model']===$m?'selected':''?>><?=h($m)?></option><?php endforeach ?></select></div>
          <div class="field"><label>服务器 DeepSeek API Key（留空不修改）</label><input type="password" name="api_key" autocomplete="new-password" placeholder="<?=$s['server_key_configured']?'已安全配置；留空保持不变':'尚未配置，请粘贴服务端密钥'?>"></div>
          <div class="field"><label>单次最大输出 Token</label><input type="number" name="max_tokens" min="256" max="8192" value="<?=$s['max_tokens']?>"></div>
          <div class="field"><label>每客户每分钟请求上限</label><input type="number" name="requests_per_minute" min="1" max="30" value="<?=$s['requests_per_minute']?>"></div>
          <div class="field"><label>AI 总开关</label><label class="check-row"><input type="checkbox" name="enabled" <?=$s['enabled']?'checked':''?>> 允许客户使用 AI</label></div>
          <div class="field"><label>允许客户端自带 Key（全局开关）</label><label class="check-row"><input type="checkbox" name="client_key_enabled" <?=$s['client_key_enabled']?'checked':''?>> 仅对已单独授权客户生效</label></div>
          <div class="field"><label>删除已保存的服务器 Key</label><label class="check-row"><input type="checkbox" name="remove_api_key"> 删除密钥</label></div>
        </div><div class="editor-actions"><button class="btn primary">保存 AI 配置</button></div>
      </form>
      <p class="muted">服务器密钥使用 sodium secretbox 加密存入数据库；加密主密钥保存在 storage/ai-master.key。必须备份该文件，丢失后无法解密原密钥。当前接口固定连接 https://api.deepseek.com，不接受客户端自定义 URL，避免 SSRF。</p>
    </div>
    <div class="stats"><div class="stat"><span>今日 AI 请求</span><strong><?=$today?></strong><small>只记录模型、Token、耗时与状态，不保存提示词</small></div><div class="stat"><span>服务端密钥</span><strong><?=$s['server_key_configured']?'已配置':'未配置'?></strong><small>客户端永远无法读取密钥</small></div><div class="stat"><span>客户端自带 Key</span><strong><?=$s['client_key_enabled']?'全局允许':'全局关闭'?></strong><small>还需在客户授权中单独勾选</small></div></div>
    <div class="card"><div class="card-head"><h2>最近 AI 调用记录</h2><span class="count">最近 100 条 · 不记录 Prompt</span></div>
      <div class="table-scroll"><table><thead><tr><th>时间</th><th>客户</th><th>模式</th><th>模型</th><th>状态</th><th>HTTP</th><th>Token</th><th>耗时</th></tr></thead><tbody>
      <?php foreach($usage as $u): ?><tr><td><?=h(utc_to_cn($u['created_at']))?></td><td><?=h($u['username'])?></td><td><?=h($u['mode'])?></td><td><?=h($u['model'])?></td><td><?=h($u['status'])?></td><td><?=(int)$u['http_status']?></td><td><?=(int)$u['prompt_tokens']?> / <?=(int)$u['completion_tokens']?></td><td><?=(int)$u['elapsed_ms']?> ms</td></tr><?php endforeach ?>
      </tbody></table></div>
    </div>
    <?php
}
function ai_admin_action(string $action): never {
    require_owner();
    if ($action==='ai_settings_save') json_response(['ok'=>true]+ai_save_settings($_POST));
    throw new RuntimeException('未知 AI 管理操作');
}
