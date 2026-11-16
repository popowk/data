(() => {
  const $ = (selector, root=document) => root.querySelector(selector);
  const token = () => $('meta[name="csrf"]')?.content || '';
  let updateAvailable = false;
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
    const response=await fetch('index.php',{method:'POST',body,credentials:'same-origin',headers:{'X-Requested-With':'XMLHttpRequest'}});
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
    if (updated) root.replaceWith(updated);
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
  function openEditor(payload) {
    const container=$('#account-editor');if(!container)return;
    const form=$('form',container);form.reset();
    form.elements.id.value=payload?.id || 0;
    form.elements.username.value=payload?.username || '';
    form.elements.password.value='';
    form.elements.group_id.value=payload?.group_id || 0;
    form.elements.device_limit.value=payload?.device_limit || 3;
    form.elements.mobile_limit.value=payload?.mobile_limit ?? 1;
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
      el.textContent=info.repair ? ('检测到首次升级尚缺少 '+(info.missing_modules?.length||0)+' 个模块，点击补齐即可，无需手工上传') :
        (info.available ? ('发现新版本 v'+info.latest+'（当前 v'+info.current+'），可下载安装') : ('当前已是最新版本 v'+info.current));
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
    if (action==='apply-update'){
      if(!updateAvailable || !confirm('更新将备份并替换管理后台代码，确认继续？'))return;
      trigger.disabled=true;$('#update-status').textContent='正在下载、备份并安装更新…';
      try{const result=await request('update_apply');toast(result.message+'：v'+result.version);location.href='index.php?view=update';}
      catch(err){toast(err.message,true);$('#update-status').textContent='更新失败：'+err.message;}
      finally{trigger.disabled=false;}
      return;
    }
    const map={
      'logout':['logout',{},false],
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
  // Group bulk form: only submit values for options the administrator explicitly enables.
  document.addEventListener('change',event=>{
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