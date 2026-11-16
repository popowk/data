(() => {
  const $ = (selector, root=document) => root.querySelector(selector);
  const token = () => $('meta[name="csrf"]')?.content || '';
  let updateAvailable = false;
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
  document.addEventListener('submit',async event=>{
    const form=event.target.closest('form[data-ajax]');if (!form)return;
    event.preventDefault();
    const action=form.dataset.ajax;
    const submit=$('button[type="submit"],button:not([type])',form);
    if(submit)submit.disabled=true;
    try {
      const result=await request(action,new FormData(form));
      if(action==='login'){location.href='index.php';return;}
      toast(result.message || '保存成功');
      await refreshContent();
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
    form.elements.mobile_limit.value=payload?.mobile_limit ?? 0;
    form.elements.license_until.value=payload?.license_until || '';
    form.elements.notes.value=payload?.notes || '';
    form.elements.enabled.checked=payload?!!payload.enabled:true;
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
      el.textContent=info.available ? ('发现新版本 v'+info.latest+'（当前 v'+info.current+'），可下载安装') : ('当前已是最新版本 v'+info.current);
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
    const map={'logout':['logout',{},false],'revoke-account':['reset_sessions',{id},true],'revoke-session':['revoke_session',{id},true],'delete-group':['group_delete',{id},true]};
    if(!map[action])return;
    const [operation,fields,confirmNeeded]=map[action];
    if(confirmNeeded && !confirm('确定执行此操作吗？'))return;
    trigger.disabled=true;
    try{
      const result=await request(operation,fields);
      if(operation==='logout'){location.href='index.php';return;}
      toast(result.message||'操作成功');await refreshContent();
    }catch(err){toast(err.message,true);}
    finally{trigger.disabled=false;}
  });
  if ($('#update-status')) checkUpdate();
})();