<?php
declare(strict_types=1);
require_once __DIR__.'/releases.php';

/**
 * Legacy encrypted operation packages are opaque, client-generated JSON.
 * Server verifies transport structure and sizes, NOT the embedded ciphertext
 * or vendor signature (there is no trusted client envelope signing key here).
 * Never log or return the 32-byte content key.
 */
const OPERATION_PACKAGE_MAX_BYTES = 12582912; // 12 MiB; DB MEDIUMTEXT < 16 MiB
function operation_package_decode(string $json,?string $expectedId=null,?int $expectedVersion=null): array {
    if ($json==='' || strlen($json)>OPERATION_PACKAGE_MAX_BYTES)
        throw new RuntimeException('操作包 JSON 大小须在 1 字节至 12 MiB 之间');
    try {$data=json_decode($json,true,32,JSON_THROW_ON_ERROR);}
    catch(JsonException $e) {throw new RuntimeException('操作包不是有效 JSON 文件');}
    if (!is_array($data) || array_is_list($data) ||
        !isset($data['envelope'],$data['content_key']) ||
        !is_array($data['envelope']) || array_is_list($data['envelope']) ||
        !is_string($data['content_key']))
        throw new RuntimeException('操作包须包含 envelope 对象及 content_key 字符串');
    if (array_diff(array_keys($data),['envelope','content_key','package_id','version']))
        throw new RuntimeException('操作包包含不支持的顶层字段');
    if ($expectedId!==null && array_key_exists('package_id',$data) &&
        $data['package_id']!==$expectedId)
        throw new RuntimeException('文件中的 package_id 与发布目标不一致');
    if ($expectedVersion!==null && array_key_exists('version',$data) &&
        $data['version']!==$expectedVersion)
        throw new RuntimeException('文件中的 version 与发布版本不一致');
    $env=$data['envelope'];
    foreach (['manifest','signature','nonce','ciphertext'] as $key) {
        if (!isset($env[$key]) || !is_string($env[$key]) || $env[$key]==='')
            throw new RuntimeException('加密操作包缺少 '.$key.' 字符串');
        if (base64_decode($env[$key],true)===false)
            throw new RuntimeException('加密操作包的 '.$key.' 不是有效 Base64');
    }
    $sig=base64_decode($env['signature'],true);
    $nonce=base64_decode($env['nonce'],true);
    $cipher=base64_decode($env['ciphertext'],true);
    $manifest=base64_decode($env['manifest'],true);
    $key=base64_decode($data['content_key'],true);
    if (!is_string($sig) || strlen($sig)!==64)
        throw new RuntimeException('操作包签名字节长度应为 64');
    if (!is_string($nonce) || !in_array(strlen($nonce),[12,24],true))
        throw new RuntimeException('操作包 nonce 长度必须是 12 或 24 字节');
    if (!is_string($manifest) || $manifest==='' || !is_string($cipher) || $cipher==='')
        throw new RuntimeException('操作包清单或密文不能为空');
    if (!is_string($key) || strlen($key)!==32 || strlen($data['content_key'])>64)
        throw new RuntimeException('操作包 content_key 必须是 32 字节的 Base64');
    $encoded=json_encode($env,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
    if (strlen($encoded)>16777215)
        throw new RuntimeException('操作包密文超过数据库字段上限');
    return ['envelope'=>$encoded,'content_key'=>$data['content_key']];
}
function operation_package_publish_record(string $packageId,int $version,string $payload): array {
    require_global_admin();
    if (!preg_match('/^[a-z0-9-]{1,32}$/D',$packageId))
        throw new RuntimeException('操作包 ID 应为 1–32 位小写字母、数字或连字符');
    if ($version<1 || $version>2147483647)
        throw new RuntimeException('操作包版本须为 1–2147483647 的整数');
    $record=operation_package_decode($payload,$packageId,$version);
    if (sql('SELECT id FROM phonehub_packages WHERE package_id=? AND version=? LIMIT 1',
        [$packageId,$version])->fetch())
        throw new RuntimeException('此操作包版本已存在，不允许覆盖；请使用更高的版本号');
    try {
        sql('INSERT INTO phonehub_packages(package_id,version,envelope,content_key,enabled) VALUES(?,?,?,?,1)',
            [$packageId,$version,$record['envelope'],$record['content_key']]);
    } catch(PDOException $e) {
        if ($e->getCode()==='23000') throw new RuntimeException('此操作包版本已存在，不允许重复发布',0,$e);
        throw $e;
    }
    $id=(int)db()->lastInsertId();
    audit('package_publish',$packageId.' v'.$version.' #'.$id);
    return ['id'=>$id,'package_id'=>$packageId,'version'=>$version,
        'message'=>'已发布加密操作包 '.$packageId.' v'.$version];
}
function operation_package_publish_upload(array $file,array $post): array {
    require_global_admin();
    if (!isset($file['error']) || (int)$file['error']!==UPLOAD_ERR_OK ||
        !is_uploaded_file((string)($file['tmp_name']??'')))
        throw new RuntimeException('上传失败；请检查 JSON 文件及 PHP 上传大小限制');
    $size=(int)($file['size']??0);
    $path=(string)($file['tmp_name']??'');
    if ($size<1 || $size>OPERATION_PACKAGE_MAX_BYTES || !is_file($path) ||
        filesize($path)!==$size)
        throw new RuntimeException('加密操作包 JSON 不可为空或超过 12 MiB');
    $name=(string)($file['name']??'');
    if (!preg_match('/^[a-zA-Z0-9_.-]{1,160}\.json$/iD',$name))
        throw new RuntimeException('请上传名称安全、扩展名为 .json 的加密操作包');
    $id=(string)($post['package_id']??'');
    $versionString=(string)($post['version']??'');
    if (!preg_match('/^[1-9][0-9]{0,9}$/D',$versionString) ||
        (int)$versionString>2147483647)
        throw new RuntimeException('操作包版本须为 1–2147483647 的整数');
    $bytes=file_get_contents($path);
    if (!is_string($bytes) || strlen($bytes)!==$size)
        throw new RuntimeException('加密操作包文件读取失败');
    return operation_package_publish_record($id,(int)$versionString,$bytes);
}
function operation_package_toggle(int $id): array {
    require_global_admin();
    if ($id<1) throw new RuntimeException('操作包版本 ID 不正确');
    $row=sql('SELECT id,package_id,version,enabled FROM phonehub_packages WHERE id=?',[$id])->fetch();
    if (!$row) throw new RuntimeException('此操作包历史版本不存在');
    $next=(int)$row['enabled']?0:1;
    sql('UPDATE phonehub_packages SET enabled=? WHERE id=?',[$next,$id]);
    audit('package_toggle',$row['package_id'].' v'.$row['version'].' enabled='.$next);
    return ['message'=>$next?'操作包版本已恢复':'操作包版本已停用',
        'enabled'=>$next,'id'=>$id];
}

function release_admin_action(string $action): never {
    require_global_admin();
    if ($action==='main_program_url_save') {
        $url=main_program_validate_download_url((string)($_POST['download_url']??''));
        sql('INSERT INTO phonehub_download_settings(resource,download_url)
            VALUES(?,?) ON DUPLICATE KEY UPDATE download_url=VALUES(download_url)',
            ['main_program',$url]);
        audit('main_program_url_save','main_program');
        json_response(['ok'=>true,'message'=>'官网主程序下载地址已保存；客户端缓存最长约 5 分钟更新']);
    }
    if ($action==='scrcpy_url_save') {
        $url=scrcpy_validate_download_url((string)($_POST['download_url']??''));
        sql('INSERT INTO phonehub_download_settings(resource,download_url)
            VALUES(?,?) ON DUPLICATE KEY UPDATE download_url=VALUES(download_url)',
            ['scrcpy',$url]);
        // Avoid recording the full public URL or signed query tokens in audit.
        audit('scrcpy_url_save','scrcpy');
        json_response(['ok'=>true,'message'=>'scrcpy 下载地址已保存；客户端缓存最长约 5 分钟更新']);
    }
    if ($action==='release_publish') {
        $r=release_publish($_FILES['file']??[],$_POST);
        json_response(['ok'=>true,'message'=>'已发布签名更新包 '.$r['platform'].' v'.$r['version']]+$r);
    }
    if ($action==='release_toggle') {
        $result=release_toggle((int)($_POST['id']??0));
        json_response(['ok'=>true]+$result);
    }
    if ($action==='release_delete') {
        $result=release_delete_obsolete_core((int)($_POST['id']??0));
        json_response(['ok'=>true]+$result);
    }
    if ($action==='package_publish') {
        json_response(['ok'=>true]+operation_package_publish_upload($_FILES['file']??[],$_POST));
    }
    if ($action==='package_toggle') {
        json_response(['ok'=>true]+operation_package_toggle((int)($_POST['id']??0)));
    }
    if ($action==='logs_purge') {
        $days=(int)($_POST['days']??30);
        if ($days<7 || $days>365) throw new RuntimeException('日志保留天数应为 7–365');
        $count=sql('DELETE FROM phonehub_client_logs WHERE created_at<DATE_SUB(UTC_TIMESTAMP(), INTERVAL '.$days.' DAY)')->rowCount();
        audit('logs_purge','older_than='.$days.' days, removed='.$count);
        json_response(['ok'=>true,'message'=>'已删除 '.$count.' 条过期日志']);
    }
    throw new RuntimeException('未知发布管理操作');
}
/**
 * Display latest usable version per type, all-time and 30-day download counts
 * PER PACKAGE ID (historical download records did not store package version).
 * Read-only roles can view metadata without receiving any envelope/key bytes.
 */
function release_package_overview(): void {
    $pkgQ=trim((string)($_GET['pkg_q']??''));
    if (!preg_match('/^[a-z0-9-]{0,32}$/D',$pkgQ)) $pkgQ='';
    $pattern='%'.$pkgQ.'%';
    $pkgTotal=(int)sql('SELECT COUNT(*) FROM phonehub_packages WHERE package_id LIKE ?',[$pattern])->fetchColumn();
    $pkgPages=max(1,(int)ceil($pkgTotal/50));
    $pkgPage=min($pkgPages,max(1,(int)($_GET['pkg_page']??1)));
    $pkgOffset=($pkgPage-1)*50;
    $rows=sql('SELECT id,package_id,version,enabled,created_at FROM phonehub_packages
        WHERE package_id LIKE ? ORDER BY package_id ASC,version DESC,id DESC LIMIT 50 OFFSET '.$pkgOffset,
        [$pattern])->fetchAll();
    $counts=sql('SELECT package_id,COUNT(*) AS total,
        SUM(downloaded_at>=DATE_SUB(UTC_TIMESTAMP(),INTERVAL 30 DAY)) AS last30,
        MAX(downloaded_at) AS latest
        FROM phonehub_package_downloads GROUP BY package_id')->fetchAll();
    $stats=[];foreach ($counts as $c) $stats[$c['package_id']]=$c;
    // Summary always counts all versions, not just 50 visible history rows.
    $summaryRows=sql('SELECT package_id,COUNT(*) AS versions,MAX(version) AS latest_version,
        MAX(CASE WHEN enabled=1 THEN version ELSE NULL END) AS latest_enabled
        FROM phonehub_packages WHERE package_id LIKE ? GROUP BY package_id ORDER BY package_id',
        [$pattern])->fetchAll();
    $groups=[];$categories=[];
    foreach ($summaryRows as $entry) {
        $id=(string)$entry['package_id'];
        $groups[$id]=$entry;
        $category=phonehub_operation_package_category($id);
        $categories[$category][$id]=$entry;
    }
    $packagePageLink=static fn(int $page): string =>
        'index.php?'.http_build_query(['view'=>'releases','pkg_q'=>$pkgQ,'pkg_page'=>$page]).'#legacy-operation-packages';
    $canEdit=phonehub_role_can_action(admin_role(),'package_publish');
    ?>
    <section class="card" id="legacy-operation-packages">
      <div class="card-head"><h2>操作包管理中心</h2><span class="count"><?=count($categories)?> 个分类 · <?=count($groups)?> 个独立包 · 共 <?=$pkgTotal?> 个版本</span></div>
      <p class="muted">加密操作包与签名更新 ZIP 分开管理；下载数据按操作包 ID 统计。</p>
      <?php if($canEdit): ?>
      <form data-ajax="package_publish" enctype="multipart/form-data" class="package-publish-form">
        <input type="hidden" name="action" value="package_publish">
        <div class="form-grid">
          <div class="field"><label>操作包 ID</label><input name="package_id" list="operation-package-targets" pattern="[a-z0-9-]{1,32}" maxlength="32" placeholder="douyin" required>
            <datalist id="operation-package-targets">
              <option value="douyin" label="抖音 · 主操作包"></option>
              <option value="douyin-notification" label="抖音 · 通知操作包"></option>
              <option value="xiaohongshu" label="小红书"></option>
              <option value="mcp" label="MCP"></option>
              <option value="skill" label="Skill"></option>
              <option value="mcp-codex" label="Codex MCP"></option>
              <option value="mcp-harness" label="DeepSeek Harness MCP"></option>
            </datalist></div>
          <div class="field"><label>新版本号（整数）</label><input name="version" type="number" min="1" max="2147483647" step="1" required placeholder="2"></div>
          <div class="field span2"><label>加密封装 JSON（最多 12 MiB）</label><input name="file" type="file" accept=".json,application/json" required></div>
        </div>
        <div class="editor-actions"><button class="btn primary" data-confirm-submit="确认上传并立即启用此加密操作包版本？现有客户可能开始下载新版本。">上传并发布加密操作包</button></div>
      </form>
      <details class="help-details"><summary>操作包格式与授权说明</summary>
        <p>抖音主包与通知包共用“抖音”授权，但各自独立发布；客户端仍按原包 ID 下载。</p>
        <p>仅接受加密工具生成的 JSON：<code>{"envelope":{"manifest":"Base64","signature":"Base64","nonce":"Base64","ciphertext":"Base64"},"content_key":"Base64"}</code>。版本不可覆盖，发布后默认使用已启用的最高版本。</p>
      </details>
      <?php endif ?>
      <div class="card-head package-subsection-head"><h2>操作包概览</h2></div>
      <form class="device-search-form" method="get" action="index.php">
        <input type="hidden" name="view" value="releases">
        <label for="pkg-history-filter">操作包 ID</label>
        <input id="pkg-history-filter" name="pkg_q" maxlength="32" pattern="[a-z0-9-]*"
          value="<?=h($pkgQ)?>" placeholder="筛选操作包 ID">
        <button type="submit" class="btn">筛选历史</button>
        <span class="muted">共 <?=$pkgTotal?> 个版本；第 <?=$pkgPage?> / <?=$pkgPages?> 页</span>
      </form>
      <div class="table-scroll package-summary-table"><table><thead><tr><th>包 ID</th><th>最新版本</th><th>当前可下载版本</th><th>版本总数</th><th>累计下载</th><th>近 30 天</th><th>最后下载</th></tr></thead><tbody>
        <?php foreach ($categories as $category=>$packages): ?>
        <tr class="package-category-row"><td colspan="7"><strong><?=h($category)?></strong> <small class="muted">· <?=count($packages)?> 个独立操作包</small></td></tr>
        <?php foreach ($packages as $id=>$g): $c=$stats[$id]??[]; ?>
        <tr><td><b><?=h($id)?></b><?php if($id==='douyin'): ?> <small class="muted">主操作包</small><?php elseif($id==='douyin-notification'): ?> <small class="muted">通知操作包</small><?php endif ?></td><td>v<?=(int)$g['latest_version']?></td><td><?= $g['latest_enabled']===null?'<span class="pill off">全部停用</span>':'v'.(int)$g['latest_enabled']?></td><td><?=(int)$g['versions']?></td><td><?=(int)($c['total']??0)?></td><td><?=(int)($c['last30']??0)?></td><td><?=h($c['latest']??'—')?></td></tr>
        <?php endforeach ?>
        <?php endforeach ?>
        <?php if (!$groups): ?><tr><td colspan="7" class="empty-result">尚无操作包，可以上传第一份加密封装 JSON</td></tr><?php endif ?>
      </tbody></table></div>
      <div class="card-head package-subsection-head package-history-head"><h2>历史版本与上下架</h2><span class="count">每页 50 条</span></div>
      <div class="table-scroll package-history-table"><table><thead><tr><th>操作包</th><th>版本</th><th>状态</th><th>发布时间（UTC）</th><th>操作</th></tr></thead><tbody>
        <?php foreach ($rows as $p): ?>
        <tr><td><small class="muted"><?=h(phonehub_operation_package_category((string)$p['package_id']))?></small> · <?=h($p['package_id'])?></td><td>v<?=(int)$p['version']?></td><td><span class="pill <?=(int)$p['enabled']?'ok':'off'?>"><?=(int)$p['enabled']?'已启用':'已停用'?></span></td><td><?=h($p['created_at'])?></td><td>
          <?php if ($canEdit): ?><button class="small-link" data-action="package-toggle" data-id="<?=(int)$p['id']?>"><?=(int)$p['enabled']?'停用':'恢复'?></button>
          <?php else: ?><span class="muted">只读</span><?php endif ?>
        </td></tr>
        <?php endforeach ?>
        <?php if (!$rows): ?><tr><td colspan="5" class="empty-result">暂无已发布的操作包版本</td></tr><?php endif ?>
      </tbody></table></div>
      <?php if($pkgPages>1): ?><nav class="device-pager" aria-label="操作包历史分页">
        <?php if($pkgPage>1): ?><a class="btn" href="<?=h($packagePageLink($pkgPage-1))?>">上一页</a><?php endif ?>
        <span>第 <?=$pkgPage?> / <?=$pkgPages?> 页</span>
        <?php if($pkgPage<$pkgPages): ?><a class="btn" href="<?=h($packagePageLink($pkgPage+1))?>">下一页</a><?php endif ?>
      </nav><?php endif ?>
      <p class="footnote package-bottom-note">客户端获取已启用的最高版本；所有版本停用后不可下载。</p>
    </section>
    <?php
}
/** Global-admin-only legacy encrypted operation-package download history. */
function release_download_history_view(): void {
    require_global_admin();
    $keyword=trim((string)($_GET['download_q']??''));
    if (utf8_length($keyword)>64) $keyword=utf8_limit($keyword,64);
    $pattern='%'.str_replace(['\\','%','_'],['\\\\','\\%','\\_'],$keyword).'%';
    $from=' FROM phonehub_package_downloads d
      LEFT JOIN phonehub_users u ON u.id=d.user_id
      WHERE d.package_id LIKE ? OR u.username LIKE ?';
    $params=[$pattern,$pattern];
    $total=(int)sql('SELECT COUNT(*)'.$from,$params)->fetchColumn();
    $pages=max(1,(int)ceil($total/50));
    $page=min($pages,max(1,(int)($_GET['download_page']??1)));
    $offset=($page-1)*50;
    $rows=sql('SELECT d.id,d.package_id,d.downloaded_at,u.username'.$from.
        ' ORDER BY d.id DESC LIMIT 50 OFFSET '.$offset,$params)->fetchAll();
    $pageLink=static fn(int $n): string=>'index.php?'.http_build_query([
        'view'=>'releases','download_q'=>$keyword,'download_page'=>$n]).'#operation-download-history';
    ?>
    <section class="card" id="operation-download-history">
      <div class="card-head"><h2>操作包下载记录</h2><span class="count">共 <?=$total?> 条 · 每页 50 条</span></div>
      <p class="muted">仅统计客户端通过旧操作包接口获取加密操作包的请求，不包括独立的核心 ZIP 文件下载。历史数据只有包 ID，没有具体包版本；这里不展示设备指纹、解密密钥或文件内容。</p>
      <form class="device-search-form" method="get" action="index.php">
        <input type="hidden" name="view" value="releases">
        <label for="operation-download-q">客户账号 / 操作包 ID</label>
        <input id="operation-download-q" name="download_q" maxlength="64"
          value="<?=h($keyword)?>" placeholder="搜索客户或包 ID">
        <button class="btn" type="submit">查询</button>
        <span class="muted">第 <?=$page?> / <?=$pages?> 页</span>
      </form>
      <div class="table-scroll"><table><thead><tr><th>下载时间（UTC）</th><th>客户账号</th><th>操作包 ID</th></tr></thead><tbody>
        <?php foreach($rows as $row): ?>
        <tr><td><?=h($row['downloaded_at'])?></td><td><?=h($row['username']??'账号已删除')?></td><td><?=h($row['package_id'])?></td></tr>
        <?php endforeach ?>
        <?php if(!$rows): ?><tr><td colspan="3">没有符合条件的下载记录</td></tr><?php endif ?>
      </tbody></table></div>
      <?php if($pages>1): ?><nav class="device-pager" aria-label="操作包下载记录分页">
        <?php if($page>1): ?><a class="btn" href="<?=h($pageLink($page-1))?>">上一页</a><?php endif ?>
        <span>第 <?=$page?> / <?=$pages?> 页</span>
        <?php if($page<$pages): ?><a class="btn" href="<?=h($pageLink($page+1))?>">下一页</a><?php endif ?>
      </nav><?php endif ?>
    </section>
    <?php
}
function release_admin_view(): void {
    require_global_admin();
    $urls=sql("SELECT resource,download_url FROM phonehub_download_settings
        WHERE resource IN ('scrcpy','main_program')")->fetchAll(PDO::FETCH_KEY_PAIR);
    $scrcpyUrl=(string)($urls['scrcpy']??SCRCPY_DEFAULT_DOWNLOAD_URL);
    $mainProgramUrl=(string)($urls['main_program']??MAIN_PROGRAM_DEFAULT_DOWNLOAD_URL);
    $releaseQ=trim((string)($_GET['release_q']??''));
    if (utf8_length($releaseQ)>48) $releaseQ=utf8_limit($releaseQ,48);
    $releaseLike='%'.str_replace(['\\','%','_'],['\\\\','\\%','\\_'],$releaseQ).'%';
    $releaseCount=(int)sql('SELECT COUNT(*) FROM phonehub_releases
        WHERE platform LIKE ? OR channel LIKE ? OR version LIKE ?',
        [$releaseLike,$releaseLike,$releaseLike])->fetchColumn();
    $releasePages=max(1,(int)ceil($releaseCount/50));
    $releasePage=min($releasePages,max(1,(int)($_GET['release_page']??1)));
    $releaseOffset=($releasePage-1)*50;
    $list=sql('SELECT id,platform,channel,version,min_client,size_bytes,sha256,signature,enabled,created_at
        FROM phonehub_releases WHERE platform LIKE ? OR channel LIKE ? OR version LIKE ?
        ORDER BY id DESC LIMIT 50 OFFSET '.$releaseOffset,
        [$releaseLike,$releaseLike,$releaseLike])->fetchAll();
    $releasePageLink=static fn(int $page): string =>
        'index.php?'.http_build_query(['view'=>'releases','release_q'=>$releaseQ,'release_page'=>$page]).'#release-history';
    // The owner may delete a disabled older core only when the channel has
    // a *newer* enabled core. PHP uses semantic version ordering, never ID.
    $enabledCore=sql("SELECT channel,version FROM phonehub_releases
        WHERE platform='core' AND enabled=1")->fetchAll();
    $canDeleteCore=static function(array $row) use ($enabledCore): bool {
        if (admin_role()!=='owner' || (string)$row['platform']!=='core' || (int)$row['enabled']!==0)
            return false;
        foreach ($enabledCore as $enabled) {
            if ((string)$enabled['channel']===(string)$row['channel'] &&
                version_compare((string)$enabled['version'],(string)$row['version'],'>'))
                return true;
        }
        return false;
    };
    ?>
    <div class="page-title"><div><h1>版本与操作包</h1><p>更新发布、操作包与下载地址</p></div></div>
    <div class="card" id="scrcpy-download-settings">
      <div class="card-head"><h2>scrcpy 下载地址</h2></div>
      <form data-ajax="scrcpy_url_save">
        <input type="hidden" name="action" value="scrcpy_url_save">
        <div class="field">
          <label for="scrcpy-download-url">scrcpy Windows ZIP 下载地址（HTTPS）</label>
          <input id="scrcpy-download-url" name="download_url" type="url" maxlength="512" value="<?=h($scrcpyUrl)?>" placeholder="https://example.com/scrcpy-win64.zip" required>
        </div>
        <div class="editor-actions"><button type="submit" class="btn primary" data-confirm-submit="确认更新 scrcpy 下载地址？客户端会在缓存到期后获取新地址。">保存下载地址</button></div>
      </form>
      <details class="help-details"><summary>客户端查询接口</summary><p><a href="api/phonehub.php?action=scrcpy_download" target="_blank" rel="noopener">scrcpy_download</a> · 公开查询，返回下载地址，缓存最长 5 分钟。</p></details>
    </div>
    <div class="card" id="main-program-download-settings">
      <div class="card-head"><h2>官网主程序下载地址</h2></div>
      <form data-ajax="main_program_url_save">
        <input type="hidden" name="action" value="main_program_url_save">
        <div class="field">
          <label for="main-program-download-url">官网主程序下载地址（HTTPS）</label>
          <input id="main-program-download-url" name="download_url" type="url" maxlength="512" value="<?=h($mainProgramUrl)?>" placeholder="https://example.com/PhoneHub-setup.exe" required>
        </div>
        <div class="editor-actions"><button type="submit" class="btn primary" data-confirm-submit="确认修改官网主程序下载地址？该项不会影响 scrcpy 下载配置。">保存主程序地址</button></div>
      </form>
      <details class="help-details"><summary>客户端查询接口</summary><p><a href="api/phonehub.php?action=main_program_download" target="_blank" rel="noopener">main_program_download</a> · 公开查询，返回下载地址，缓存最长 5 分钟。</p></details>
    </div>
    <div class="card"><div class="card-head"><h2>上传新版本（50 MB 以内）</h2></div>
      <form data-ajax="release_publish" enctype="multipart/form-data">
       <input type="hidden" name="action" value="release_publish">
       <div class="form-grid">
        <div class="field"><label>更新目标</label><select name="platform"><option value="core">core（客户端核心）</option><option value="douyin">douyin（抖音模块）</option><option value="xiaohongshu">xiaohongshu（小红书模块）</option><option value="mcp">mcp（MCP 连接包）</option><option value="mcp-codex">mcp-codex（Codex MCP）</option><option value="mcp-harness">mcp-harness（DeepSeek Harness MCP）</option><option value="skill">skill（Skill 技能包）</option></select></div>
        <div class="field"><label>发布渠道</label><select name="channel"><option value="stable">正式版 stable</option><option value="beta">测试版 beta</option></select></div>
        <div class="field"><label>版本号</label><input name="version" required placeholder="1.0.1" pattern="[0-9]+\.[0-9]+\.[0-9]+([\-][0-9a-zA-Z.-]+)?"></div>
        <div class="field"><label>最低客户端版本</label><input name="min_client" required value="0.7.1"></div>
        <div class="field span2"><label>更新 ZIP</label><input name="file" type="file" accept=".zip,application/zip" required></div>
        <div class="field span2"><label>版本说明</label><textarea name="notes" maxlength="1000" rows="3" style="padding:12px;border:1px solid #dce3ef;border-radius:8px;width:100%;resize:vertical" placeholder="更新内容与兼容提醒"></textarea></div>
       </div><div class="editor-actions"><button class="btn primary" data-confirm-submit="确认发布此版本并签署更新包？版本号发布后不可重复。">上传并签名发布</button></div>
      </form>
      <details class="help-details"><summary>签名与部署要求</summary>
        <p>服务器需启用 sodium 和 ZipArchive；PHP 上传上限至少 50 MB。签名私钥仅保存在服务器，不上传 GitHub。</p>
        <p>客户端必须使用预置公钥验证 Ed25519 签名、文件 SHA-256，并安全解压 ZIP；不能直接信任接口返回的公钥。</p>
      </details>
    </div>
    <div class="card"><div class="card-head"><h2>签名公钥</h2></div>
      <?php $pub=release_public_key(); ?>
      <?php if ($pub): ?>
        <p class="muted">客户端须预置并固定信任该公钥。</p>
        <code class="public-key"><?=h($pub)?></code>
      <?php else: ?><p class="muted">首次发布后显示签名公钥。</p><?php endif ?>
    </div>
    <div class="card" id="release-history"><div class="card-head"><h2>已发布版本</h2><span class="count"><?=$releaseCount?> 个版本；每页 50 条</span></div>
      <form class="device-search-form" method="get" action="index.php">
        <input type="hidden" name="view" value="releases">
        <label for="release-history-filter">目标、渠道或版本号</label>
        <input id="release-history-filter" name="release_q" maxlength="48" value="<?=h($releaseQ)?>" placeholder="core / stable / 1.0.0">
        <button type="submit" class="btn">筛选版本</button>
        <span class="muted">第 <?=$releasePage?> / <?=$releasePages?> 页</span>
      </form>
      <div class="table-scroll"><table><thead><tr><th>更新目标</th><th>渠道</th><th>版本</th><th>最低客户端</th><th>大小</th><th>状态</th><th>操作</th></tr></thead><tbody>
        <?php foreach($list as $x): ?><tr><td><?=h($x['platform'])?></td><td><?=h($x['channel'])?></td><td><b><?=h($x['version'])?></b></td><td><?=h($x['min_client'])?></td><td><?=number_format((int)$x['size_bytes']/1024/1024,2)?> MB</td><td><span class="pill <?=(int)$x['enabled']?'ok':'off'?>"><?=(int)$x['enabled']?'已发布':'已停用'?></span></td><td><button class="small-link" data-action="release-toggle" data-id="<?=(int)$x['id']?>"><?=(int)$x['enabled']?'暂停下载':'恢复下载'?></button>
        <?php if($canDeleteCore($x)): ?>
        <button class="small-link danger-action" data-action="release-delete"
          data-id="<?=(int)$x['id']?>" data-label="<?=h($x['channel'].' core v'.$x['version'])?>">永久删除旧版</button>
        <?php endif ?>
        </td></tr><?php endforeach ?>
      </tbody></table></div>
      <?php if($releasePages>1): ?><nav class="device-pager" aria-label="签名版本分页">
        <?php if($releasePage>1): ?><a class="btn" href="<?=h($releasePageLink($releasePage-1))?>">上一页</a><?php endif ?>
        <span>第 <?=$releasePage?> / <?=$releasePages?> 页</span>
        <?php if($releasePage<$releasePages): ?><a class="btn" href="<?=h($releasePageLink($releasePage+1))?>">下一页</a><?php endif ?>
      </nav><?php endif ?>
    </div>
    <?php release_package_overview();release_download_history_view(); ?>
    <?php
    if (is_file(__DIR__.'/automation.php')) {
        require_once __DIR__.'/automation.php';
        automation_admin_view();
    } else {
        // An old pinned updater can only install its historical allowlist on
        // pass one. Keep the release page usable until the second repair pass
        // installs the new automation module.
        echo '<div class="card"><p>旧版更新器已更新基础程序，但自动化发布模块尚未补齐。请前往「系统更新」再次检查，执行「补齐缺失模块」。</p><a href="index.php?view=update">系统更新</a></div>';
    }
}
