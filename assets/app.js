(() => {
  const $ = (selector, root=document) => root.querySelector(selector);
  const token = () => $('meta[name="csrf"]')?.content || '';
  let updateAvailable = false;
  let activeDeviceTab = 'computers';
  function setDeviceTab(tab) {
    activeDeviceTab=tab;
    document.querySelectorAll('[data-device-tab]').forEach(b=>{
      const chosen=b.dataset.deviceTab===tab;
      b.classList.toggle('active',chosen);
      b.setAttribute('aria-selected',String(chosen));
    });
    document.querySelectorAll('[data-device-panel]').forEach(p=>{
      p.hidden=p.dataset.devicePanel!==tab;
    });
  }
  function showSensitive(label,value) {
    const overlay=document.createElement('div');overlay.className='secret-overlay';
    const dialog=document.createElement('section');dialog.className='secret-dialog';
    dialog.setAttribute('role','dialog');dialog.setAttribute('aria-modal','true');
    const title=document.createElement('h2');title.textContent=label;
    const note=document.createElement('p');note.textContent='此数据为敏感设备信息，本次查看已经记录在管理员操作日志中。';
    const code=document.createElement('code');code.className='secret-value';code.textContent=value;
    const close=document.createElement('button');close.type='button';close.className='btn';close.textContent='关闭';
    const copy=document.createElement('button');copy.type='button';copy.className='btn primary';copy.textContent='复制';
    close.addEventListener('click',()=>overlay.remove());
    copy.addEventListener('click',()=>navigator.clipboard.writeText(value).then(()=>toast('已复制')).catch(()=>toast('复制失败',true)));
    const buttons=document.createElement('div');buttons.className='secret-buttons';buttons.append(copy,close);
    dialog.append(title,note,code,buttons);overlay.append(dialog);document.body.append(overlay);
    close.focus();
  }
  function showPassword(username, password) {
    const overlay=document.createElement('div');overlay.className='secret-overlay';
    const dialog=document.createElement('section');dialog.className='secret-dialog';
    dialog.setAttribute('role','dialog');dialog.setAttribute('aria-modal','true');
    const title=document.createElement('h2');title.textContent='随机密码（仅显示一次）';
    const description=document.createElement('p');description.textContent='账号：'+username+'。请立即复制并安全交付，关闭后无法再次查看原密码。';
    const secret=document.createElement('code');secret.className='secret-value';secret.textContent=password;
    const actions=document.createElement('div');actions.className='secret-buttons';
    const copy=document.createElement('button');copy.type='button';copy.className='btn primary';copy.textContent='复制密码';
    const close=document.createElement('button');close.type='button';close.className='btn';close.textContent='已保存，关闭';
    copy.addEventListener('click',async()=> {
      try { await navigator.clipboard.writeText(password);toast('密码已复制');}
      catch(e) { toast('复制失败，请手动选择密码复制',true); }
    });
    close.addEventListener('click',()=>overlay.remove());
    actions.append(copy,close);dialog.append(title,description,secret,actions);overlay.append(dialog);document.body.append(overlay);
    close.focus();
  }
  function toast(message, error=false) {
    const el = $('#toast');
    if (!el) { const hint=$('#message'); if (hint) hint.textContent=message; return; }
    el.textContent = message; el.classList.toggle('error', error); el.classList.add('show');
    clearTimeout(el._hide); el._hide=setTimeout(()=>el.classList.remove('show'),3800);
  }
  async function request(action, fields={}) {
    const body = fields instanceof FormData ? fields : new FormData();
    if (!(fields instanceof FormData)) Object.entries(fields).forEach(([k,v])=>body.append(k,v));
    body.set('action',action); body.set('csrf',token());
    const response=await fetch('index.php',{method:'POST',body,credentials:'same-origin',cache:'no-store',headers:{'X-Requested-With':'XMLHttpRequest'}});
    const payload=await response.json().catch(()=>({ok:false,error:'服务器返回格式异常'}));
    if (!response.ok || !payload.ok) throw new Error(payload.error || '操作失败');
    return payload;
  }
  async function refreshContent() {
    const root = $('#content'); if (!root) return;
    const response=await fetch(location.href,{credentials:'same-origin',cache:'no-store'});
    if (!response.ok) throw new Error('页面数据获取失败');
    const doc = new DOMParser().parseFromString(await response.text(),'text/html');
    const updated = $('#content',doc);
    if (updated) {
      root.replaceWith(updated);
      if (document.querySelector('[data-device-tab]')) setDeviceTab(activeDeviceTab);
    }
  }
  async function refreshAfterSuccess() {
    try { await refreshContent(); }
    catch (error) { toast('操作已完成，但页面刷新失败，请手动刷新页面',true); }
  }
  document.addEventListener('submit',async event=>{
    const form=event.target.closest('form[data-ajax]');if (!form)return;
    event.preventDefault();
    const confirmMessage=form.querySelector('[data-confirm-submit]')?.dataset.confirmSubmit;
    if(confirmMessage && !confirm(confirmMessage))return;
    const action=form.dataset.ajax;
    const submit=$('button[type="submit"],button:not([type])',form);
    if(submit)submit.disabled=true;
    try {
      const result=await request(action,new FormData(form));
      if(action==='login'){location.href='index.php';return;}
      toast(result.message || '保存成功');
      // Reveal one-time credentials before refreshing page content. If the refresh
      // fails after the server committed the password reset, the secret must not be lost.
      if (result.password) showPassword(result.username || '客户', result.password);
      await refreshAfterSuccess();
    } catch(err){toast(err.message,true);}
    finally {if(submit)submit.disabled=false;}
  });
  function applyOpeningPlan(form) {
    const picker=form.elements.opening_plan;
    if(!picker) return;
    const code=picker.value;
    const option=picker.selectedOptions[0];
    const preset=code && code!=='custom';
    if(preset && option?.dataset.pc && option?.dataset.mobile) {
      form.elements.device_limit.value=option.dataset.pc;
      form.elements.mobile_limit.value=option.dataset.mobile;
    }
    // The backend enforces preset quotas; read-only prevents an accidental
    // mismatch between displayed numbers and the account's actual limits.
    form.elements.device_limit.readOnly=!!preset;
    form.elements.mobile_limit.readOnly=!!preset;
  }
  function openEditor(payload) {
    const container=$('#account-editor');if(!container)return;
    const form=$('form',container);form.reset();
    const openingField=$('#opening-plan-field',container);
    if(openingField)openingField.hidden=!!payload;
    if(form.elements.opening_plan) {
      form.elements.opening_plan.disabled=!!payload;
      form.elements.opening_plan.value='';
    }
    form.elements.id.value=payload?.id || 0;
    form.elements.username.value=payload?.username || '';
    form.elements.password.value='';
    form.elements.group_id.value=payload?.group_id || 0;
    form.elements.device_limit.value=payload?.device_limit || 3;
    form.elements.mobile_limit.value=payload?.mobile_limit ?? 1;
    applyOpeningPlan(form);
    form.elements.license_until.value=payload?.license_until || '';
    form.elements.notes.value=payload?.notes || '';
    form.elements.enabled.checked=payload?!!payload.enabled:true;
    form.elements.ai_enabled.checked=payload?!!payload.ai_enabled:true;
    form.elements.allow_client_ai_key.checked=payload?!!payload.allow_client_ai_key:false;
    form.elements.ai_daily_limit.value=payload?.ai_daily_limit ?? 100;
    form.querySelectorAll('input[name="entitlements[]"]').forEach(el=>el.checked=payload ? payload.entitlements.includes(el.value) : el.value==='douyin');
    $('#editor-title').textContent=payload?'编辑客户授权':'创建客户';
    container.hidden=false;
    container.scrollIntoView({behavior:'smooth',block:'start'});
    form.elements.username.focus({preventScroll:true});
  }
  async function checkUpdate() {
    const el=$('#update-status'),button=$('#apply-update');if(!el)return;
    el.textContent='正在从国内镜像获取版本信息…';
    if(button)button.disabled=true; updateAvailable=false;
    try {
      const info=await request('update_check');
      updateAvailable=!!info.available;
      if(button)button.disabled=!updateAvailable;
      if (button) button.textContent=info.repair ? '补齐缺失模块' : '下载并安装更新';
      const trustLabel=info.signature_verified
        ? ' · Ed25519 独立签名验证通过'
        : ' · 提醒：尚未配置固定签名公钥，目前仅校验 HTTPS 镜像';
      el.textContent=(info.repair ? ('检测到首次升级尚缺少 '+(info.missing_modules?.length||0)+' 个模块，点击补齐即可，无需手工上传') :
        (info.available ? ('发现新版本 v'+info.latest+'（当前 v'+info.current+'），可下载安装') : ('当前已是最新版本 v'+info.current)))+trustLabel;
    } catch(err){el.textContent='检查失败：'+err.message;toast(err.message,true);}
  }
  document.addEventListener('click',async event=>{
    const edit=event.target.closest('[data-edit]');
    if (edit) {try{openEditor(JSON.parse(edit.dataset.edit));}catch(e){toast('客户数据无法读取',true);}return;}
    const trigger=event.target.closest('[data-action]');if(!trigger)return;
    const action=trigger.dataset.action, id=trigger.dataset.id;
    if (action==='new-account'){openEditor(null);return;}
    if (action==='close-editor'){$('#account-editor').hidden=true;return;}
    if (action==='check-update'){await checkUpdate();return;}
    if (action==='generate-diagnostic') {
      const area=$('#diagnostic-report-text');
      const copy=$('#copy-diagnostic');
      const status=$('#diagnostic-status');
      if(!area || !copy) return;
      trigger.disabled=true;copy.disabled=true;
      area.value='';
      if(status)status.textContent='正在检查服务端状态…';
      try {
        const data=await request('diagnostic_report');
        if(typeof data.report!=='string' || !data.report.startsWith('PhoneHub 故障诊断报告'))
          throw new Error('服务器未返回有效诊断报告');
        area.value=data.report;
        copy.disabled=false;
        if(status)status.textContent='报告已生成，可点击复制';
      } catch(err) {
        if(status)status.textContent='诊断生成失败；请检查 PHP 错误日志';
        toast(err.message,true);
      } finally {trigger.disabled=false;}
      return;
    }
    if (action==='copy-diagnostic') {
      const area=$('#diagnostic-report-text');
      if(!area?.value)return;
      try {
        if(navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(area.value);
        } else {
          area.focus();area.select();
          if(!document.execCommand('copy')) throw new Error('无法自动复制');
          area.setSelectionRange(0,0);
        }
        toast('已复制脱敏诊断报告，可以直接粘贴到聊天中');
      } catch(err) {
        area.focus();area.select();
        toast('自动复制不可用，诊断内容已选中，可使用 ⌘C / Ctrl+C',true);
      }
      return;
    }
    if (action==='diagnose-update'){
      const target=$('#update-diagnostics');
      trigger.disabled=true;
      if(target) target.textContent='正在检查 PHP、数据库及程序目录…';
      try{
        const result=await request('update_diagnostics');
        const checks=Array.isArray(result.checks)?result.checks:[];
        const symbols={ok:'✓',warning:'!',error:'×'};
        const lines=checks.map(x=>(symbols[x.status]||'?')+' '+x.name+'：'+x.detail);
        lines.unshift('自检结果：'+(result.summary?.errors||0)+' 项异常，'+(result.summary?.warnings||0)+' 项需人工确认');
        if(target) target.textContent=lines.join('\n');
      }catch(err){
        if(target) target.textContent='运行环境自检失败：'+err.message;
      }finally{trigger.disabled=false;}
      return;
    }
    if (action==='apply-update'){
      if(!updateAvailable || !confirm('更新将备份并替换管理后台代码，确认继续？'))return;
      trigger.disabled=true;$('#update-status').textContent='正在下载、备份并安装更新…';
      try{
        const result=await request('update_apply');
        if(result.cache_reset===false){
          const warning=result.message||'更新文件已安装，但 PHP OPcache 未能确认刷新';
          toast(warning,true);
          $('#update-status').textContent=warning+'。请在服务器重启 PHP-FPM/Web 服务后，再重新打开管理后台。';
          return;
        }
        toast((result.message||'更新成功')+'：v'+result.version);
        location.replace('index.php?view=update&_='+Date.now());
      } catch(err){
        toast(err.message,true);
        $('#update-status').textContent='更新失败：'+err.message;
      }
      finally{trigger.disabled=false;}
      return;
    }
    if (action==='device-reveal') {
      if (!confirm('将查看完整敏感标识并记录审计日志，确认继续？')) return;
      trigger.disabled=true;
      try {
        const result=await request('device_reveal',{id,kind:trigger.dataset.kind});
        showSensitive(trigger.dataset.kind==='imei'?'完整 IMEI':'完整手机号',result.value);
      } catch(err) {toast(err.message,true);}
      finally {trigger.disabled=false;}
      return;
    }
    if (action==='device-block') {
      const kind=trigger.dataset.kind;
      const reason=prompt('独立拉黑 '+kind+'，请输入原因（不会同时拉黑其他标识）：','管理员禁止访问');
      if (reason===null) return;
      if (!reason.trim()) {toast('拉黑原因不能为空',true);return;}
      if (!confirm('确认拉黑该设备标识？匹配设备会立即失效。')) return;
      trigger.disabled=true;
      try {
        const result=await request('device_blacklist_add',{id,kind,reason:reason.trim()});
        toast(result.message||'已拉黑');await refreshAfterSuccess();
      } catch(err) {toast(err.message,true);}
      finally {trigger.disabled=false;}
      return;
    }
    const map={
      'logout':['logout',{},false],
      'signing-activate':['signing_activate',{},true],
      'revoke-account':['reset_sessions',{id},true],
      'reset-account-password':['account_password',{id},true],
      'revoke-session':['revoke_session',{id},true],
      'delete-group':['group_delete',{id},true],
      'admin-reset':['admin_reset',{id},true],
      'admin-toggle':['admin_toggle',{id},true],
      'admin-delete':['admin_delete',{id},true],
      'mobile-revoke':['mobile_revoke',{id},true],
      'mobile-blacklist':['mobile_blacklist',{id,reason:'管理员手动拉黑'},true],
      'mobile-unblacklist':['mobile_unblacklist',{id},true],
      'release-toggle':['release_toggle',{id},true],
      'logs-purge':['logs_purge',{days:30},true],
      'gateway-install':['gateway_install',{},true]
    };
    if(!map[action])return;
    const [operation,fields,confirmNeeded]=map[action];
    if(confirmNeeded && !confirm('确定执行此操作吗？'))return;
    trigger.disabled=true;
    try{
      const result=await request(operation,fields);
      if(operation==='logout'){location.href='index.php';return;}
      toast(result.message||'操作成功');
      // Display one-time passwords before any non-critical page refresh.
      if(result.password)showPassword(result.username||'账号',result.password);
      await refreshAfterSuccess();
    }catch(err){toast(err.message,true);}
    finally{trigger.disabled=false;}
  });
  document.addEventListener('click',event=>{
    const tab=event.target.closest('[data-device-tab]');
    if(tab) {setDeviceTab(tab.dataset.deviceTab);return;}
    const copy=event.target.closest('[data-device-copy]');
    if(copy) {
      navigator.clipboard.writeText(copy.dataset.deviceCopy||'')
        .then(()=>toast('电脑 ID 已复制')).catch(()=>toast('复制失败，请手动选择',true));
    }
  });
  // Group bulk form: only submit values for options the administrator explicitly enables.
  document.addEventListener('change',event=>{
    if(event.target.id==='opening-plan') {
      const editor=$('#account-editor form');
      if(editor) applyOpeningPlan(editor);
      return;
    }
    const toggle=event.target.closest('.bulk-option-toggle');
    if(toggle){
      const option=toggle.closest('.bulk-option');
      option?.classList.toggle('is-selected',toggle.checked);
      option?.querySelectorAll('[data-bulk-field]').forEach(field=>{field.disabled=!toggle.checked;});
      const summary=$('#bulk-summary');
      if(summary){
        const selected=[...document.querySelectorAll('.bulk-option-toggle:checked')].map(x=>x.closest('.bulk-option')?.querySelector('strong')?.textContent||'配置');
        summary.textContent=selected.length?('将修改：'+selected.join('、')):'尚未选择修改项';
      }
    }
    if(event.target.id==='bulk-group'){
      const option=event.target.selectedOptions[0];
      const count=option?.dataset.members;
      const meta=$('#bulk-member-count');
      if(meta)meta.textContent=event.target.value?(count+' 位客户将受到影响'):'尚未选择分组';
    }
  });
  if ($('#update-status')) checkUpdate();
})();