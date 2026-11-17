<?php
declare(strict_types=1);
// Owner-only opening quota templates. No pricing, orders, billing or privileges.
function plan_admin_action(string $action): never {
    require_owner();
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
    require_owner();
    $plans=sql('SELECT p.*, (SELECT COUNT(*) FROM phonehub_user_meta m WHERE m.opening_plan_code=p.plan_code) AS users FROM phonehub_plan_templates p ORDER BY p.sort_order,p.id')->fetchAll();
    ?>
    <div class="page-title"><div><h1>套餐管理</h1><p>用于新客户开户的电脑与手机额度；不包含价格、订单或支付</p></div><button class="btn primary" type="button" data-action="new-plan">+ 新增套餐</button></div>
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
      <div class="table-scroll"><table><thead><tr><th>名称</th><th>电脑</th><th>手机</th><th>已开户客户</th><th>排序</th><th>状态</th><th>操作</th></tr></thead><tbody>
      <?php foreach($plans as $p):
        $edit=['id'=>(int)$p['id'],'name'=>$p['name'],'device_limit'=>(int)$p['device_limit'],
           'mobile_limit'=>(int)$p['mobile_limit'],'sort_order'=>(int)$p['sort_order']];
      ?>
        <tr><td><b><?=h($p['name'])?></b><small class="device-subline"><?=h($p['plan_code'])?></small></td>
          <td><?=(int)$p['device_limit']?></td><td><?=(int)$p['mobile_limit']?></td><td><?=(int)$p['users']?></td><td><?=(int)$p['sort_order']?></td>
          <td><span class="pill <?=(int)$p['enabled']?'ok':'off'?>"><?=(int)$p['enabled']?'启用':'停用'?></span></td>
          <td><button class="small-link" type="button" data-plan-edit="<?=h(json_encode($edit,JSON_UNESCAPED_UNICODE|JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_QUOT|JSON_HEX_APOS))?>">编辑</button>
          <button class="small-link <?=(int)$p['enabled']?'danger-action':''?>" type="button" data-action="plan-toggle" data-id="<?=(int)$p['id']?>"><?=(int)$p['enabled']?'停用':'启用'?></button></td>
        </tr>
      <?php endforeach ?></tbody></table></div>
    </div>
    <?php
}
