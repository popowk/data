<?php
declare(strict_types=1);

const LEGACY_API_REFERENCE_SHA256='897229b5865ec23b89a3a1e9765f8af69c4dd6010e1878fe1aa4776ea4acb291';
const LEGACY_API_TAG='PhoneHub managed gateway v2';

function gateway_target(): string {
    $parent=realpath(dirname(APP_ROOT));
    $name=basename(realpath(APP_ROOT) ?: APP_ROOT);
    if (!$parent || $name!=='license') return '';
    $directory=$parent.'/phonehub';
    if (!is_dir($directory) || is_link($directory) || realpath($directory)!==$directory) return '';
    return $directory.'/api.php';
}

function gateway_bootstrap(): string {
    return "<?php\n".
        "// ".LEGACY_API_TAG."\n".
        "// Server-side bridge to the current PHP license API. Preserve this file when updating.\n".
        "require dirname(__DIR__) . '/license/api/phonehub.php';\n";
}

function gateway_status(): array {
    $target=gateway_target();
    if ($target==='') return ['path'=>'需要同站点 /license/ 与 /phonehub/ 目录','can_install'=>false,'message'=>'未找到可安全接管的客户端目录'];
    if (is_link($target) || !is_file($target) || !is_readable($target)) return ['path'=>$target,'can_install'=>false,'message'=>'旧客户端 API 不存在、不可读或为符号链接'];
    $content=file_get_contents($target);
    if ($content===false) return ['path'=>$target,'can_install'=>false,'message'=>'无法读取旧 API'];
    if (hash_equals($content,gateway_bootstrap())) return ['path'=>$target,'can_install'=>false,'message'=>'客户端接口已接管：手机绑定校验正在由本项目执行'];
    $same=hash_equals(LEGACY_API_REFERENCE_SHA256,hash('sha256',$content));
    return [
        'path'=>$target,
        'can_install'=>$same && is_writable($target) && is_writable(dirname($target)) && is_file(APP_ROOT.'/api/phonehub.php'),
        'message'=>$same?'已识别 PhoneHub 0.7.1 原始 API，可以备份后接管':'当前 API 与上传的参考代码不一致；禁止自动覆盖。请先核对线上修改'
    ];
}

function gateway_install(): array {
    $status=gateway_status();
    if (!$status['can_install']) throw new RuntimeException('旧接口与已验证参考版本不匹配，或目标没有写入权限，无法安全自动接管');
    $target=$status['path'];
    // Store backup outside the client-visible endpoint, under protected admin storage.
    $directory=APP_STORE.'/backups/gateways';
    if (!is_dir($directory) && !mkdir($directory,0700,true)) throw new RuntimeException('无法创建旧 API 备份目录');
    $backup=$directory.'/phonehub-api-'.gmdate('Ymd-His').'-'.bin2hex(random_bytes(4)).'.bak';
    if (!copy($target,$backup)) throw new RuntimeException('旧接口备份失败，已停止接管');
    @chmod($backup,0600);
    $temp=tempnam(dirname($target),'.phgw-');
    if (!$temp) throw new RuntimeException('目标目录无法创建临时文件');
    try {
        if (file_put_contents($temp,gateway_bootstrap(),LOCK_EX)===false) throw new RuntimeException('新接口写入失败');
        @chmod($temp,0644);
        if (!rename($temp,$target)) throw new RuntimeException('新接口替换失败');
        if (function_exists('opcache_invalidate')) @opcache_invalidate($target,true);
    } finally {if (is_file($temp)) @unlink($temp);}
    audit('gateway_install','phonehub/api.php');
    return ['message'=>'客户端接口接管成功，原文件已备份；手机绑定检查正式生效','backup'=>basename($backup)];
}
