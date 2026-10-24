(() => {
  'use strict';
  const $ = selector => document.querySelector(selector);
  const h = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
  const state = {token:null, data:null, busy:false, result:null, profile:null, loading:false, revision:0, inventoryRevision:0, requestedSelection:null};
  async function api(path, value, retry=true) {
    if(!state.token){const response=await fetch('/api/session',{cache:'no-store'});const session=await response.json();state.token=session.token;}
    const response=await fetch(path,{method:value===undefined?'GET':'POST',cache:'no-store',headers:{'X-Session-Token':state.token,'Content-Type':'application/json'},...(value===undefined?{}:{body:JSON.stringify(value)})});
    const data=await response.json();
    if(response.status===403){state.token=null;if(value===undefined&&retry)return api(path,undefined,false);}
    if(!response.ok)throw new Error(data.error||'本机检测未完成，请重试。');
    return data;
  }
  const error = message => {$('#guide-error').textContent=message;$('#guide-error').hidden=!message;};
  function busy(active,message='') {
    state.busy=active;[...document.querySelectorAll('#guide-workspace button,#guide-form input,#guide-form textarea,#guide-form select')].forEach(node=>{node.disabled=active;});
    $('#guide-progress').textContent=message||'点击后比较普通连接与已识别的代理入口。';
  }
  function step(index){[1,2,3].forEach(value=>{const node=$('#guide-step-'+value);node.classList.toggle('completed',value<index);if(value===index)node.setAttribute('aria-current','step');else node.removeAttribute('aria-current');});}
  function toolMarkup(tool) {
    const entrances=(tool.proxy_options||[]).map(option=>`<span class="guide-port">${h(option.proxy_url)}</span>`).join('');
    const details=(tool.endpoints||[]).map(endpoint=>`<li>${h(endpoint.transport?.toUpperCase())} ${h(endpoint.address)}:${h(endpoint.port)} · ${h(endpoint.owner||'归属待确认')} · ${endpoint.usable_proxy?h(endpoint.protocol?.toUpperCase()+' 入口（待检测）'):'专用或协议待确认'}</li>`).join('');
    const interfaces=(tool.interfaces||[]).map(item=>`<li>${h(item.description||item.name)} · ${h(item.status)}</li>`).join('');
    return `<article class="guide-tool"><div><strong>${h(tool.name)}</strong><span>${h(tool.state_label)}</span></div><p>${h(tool.kind)} · ${h(tool.action_label)}</p>${entrances}<small>${h(tool.notice)}</small><details><summary>识别依据 · ${Number(tool.process_count)||0} 个进程 / ${Number(tool.listener_count)||0} 个监听</summary><ul>${(tool.processes||[]).map(item=>`<li>${h(item.name)} · PID ${h(item.pid)}</li>`).join('')}${(tool.services||[]).map(item=>`<li>服务 ${h(item.name)} · ${h(item.state)}</li>`).join('')}${interfaces}${details}</ul></details></article>`;
  }
  function renderInventory(data,selected) {
    state.data=data;
    const appId=selected||$('#guide-app').value;
    // Do not replace a select while the user is choosing a software entry.
    const signature=JSON.stringify((data.catalog?.apps||[]).map(app=>[app.id,app.name,app.protected]));
    if(signature!==state.appsSignature){$('#guide-app').innerHTML='<option value="">选择软件…</option>'+(data.catalog?.apps||[]).map(app=>`<option value="${h(app.id)}">${h(app.name)}${app.protected?'（网络组件 / 受保护）':''}</option>`).join('');state.appsSignature=signature;}
    if((data.catalog?.apps||[]).some(app=>app.id===appId))$('#guide-app').value=appId;
    const toolsSignature=JSON.stringify(data.tools||[]);
    if(toolsSignature!==state.toolsSignature){$('#guide-tools').innerHTML=(data.tools||[]).length?data.tools.map(toolMarkup).join(''):'<p class="guide-empty">尚未发现代理或隧道工具。可先启动已有客户端，再点击“重新识别网络工具”。未运行的便携软件可能没有安装记录。</p>';state.toolsSignature=toolsSignature;}
    const date=data.snapshot_captured_at?new Date(data.snapshot_captured_at):null;
    $('#guide-observed').textContent=data.discovering?'正在识别进程、端口、服务与网卡…':date?`${date.toLocaleTimeString('zh-CN',{hour12:false})} 的观察${data.snapshot_stale?' · 旧快照，需重新识别':''}`:'尚未完成本机识别';
  }
  async function load(selected){
    if(selected)state.requestedSelection=selected;
    if(state.loading)return;state.loading=true;
    const revision=state.inventoryRevision;let reload=false;
    try{const data=await api('/api/troubleshoot');if(revision!==state.inventoryRevision){reload=true;return;}renderInventory(data,state.requestedSelection);state.requestedSelection=null;}
    catch(exc){if(revision===state.inventoryRevision)error(exc.message);else reload=true;}
    finally{state.loading=false;if(reload)load();}
  }
  async function scan(){if(state.busy)return;error('');busy(true,'正在识别已安装软件、进程、服务、端口与网卡…');try{const result=await api('/api/discover',{});if(result.error)throw new Error(result.error);await load();}catch(exc){error(exc.message);}finally{busy(false);}}
  function invalidate(){state.revision++;state.result=null;state.profile=null;step(1);$('#guide-result').innerHTML='<div class="guide-placeholder"><h2>问题信息已更新</h2><p>点击“检测并给出建议”，获得针对当前软件和地址的结果。</p></div>';}
  function renderResult(result){
    const advice=result.recommendation;
    const rows=result.results.map(item=>`<tr><td>${h(item.name)}</td><td class="${item.ok?'guide-pass':'guide-fail'}">${h(item.label)}</td></tr>`).join('');
    $('#guide-result').innerHTML=`<span class="guide-result-kicker">针对 ${h(result.app_name)} 的建议</span><h2>${h(advice.title)}</h2><p>${h(advice.reason)}</p><div class="guide-next"><strong>下一步</strong><p>${h(advice.action)}</p>${advice.profile?'<button id="guide-prepare" class="button button-primary">准备此软件的代理启动方案</button>':''}</div><div id="guide-action"></div><details class="guide-comparison" open><summary>这次比较了哪些连接方式</summary><table><thead><tr><th>连接方式</th><th>结果</th></tr></thead><tbody>${rows}</tbody></table></details><p class="guide-hint">${h(result.scope)} ${h(result.network_notice)}</p><div class="guide-feedback"><p>按建议操作后，原来的下载或登录成功了吗？</p><button type="button" class="button button-outline" data-guide-outcome="resolved">已经成功</button><button type="button" class="button button-quiet" data-guide-outcome="failed">仍然失败</button><p id="guide-feedback-message" role="status"></p></div>`;
    step(3);
  }
  $('#guide-form').addEventListener('submit',async event=>{
    event.preventDefault();if(state.busy)return;error('');busy(true,'正在重新识别本机环境，然后比较普通连接与最多 3 个代理入口…');step(2);state.result=null;state.profile=null;
    const revision=++state.revision;
    try{const result=await api('/api/troubleshoot/check',{app_id:$('#guide-app').value,url:$('#guide-url').value,error_text:$('#guide-error-text').value});if(revision!==state.revision)return;state.result=result;renderResult(result);await load();}
    catch(exc){error(exc.message);step(1);}finally{busy(false,'检测完成后，请在原软件中实际重试并确认结果。');}
  });
  $('#guide-error-text').addEventListener('input',()=>{const match=$('#guide-error-text').value.match(/https?:\/\/[^\s<>"']+/);if(match)$('#guide-url').value=match[0].replace(/[).,:;，。；：）]+$/,'');invalidate();});
  $('#guide-url').addEventListener('input',invalidate);$('#guide-app').addEventListener('change',invalidate);
  $('#guide-rescan').addEventListener('click',scan);
  $('#guide-add-app').addEventListener('click',()=>document.dispatchEvent(new CustomEvent('flowdesk:add-app')));
  $('#guide-result').addEventListener('click',async event=>{
    if(state.busy||!state.result)return;
    const outcome=event.target.closest('[data-guide-outcome]');
    if(outcome){busy(true);try{const data=await api('/api/troubleshoot/feedback',{check_id:state.result.check_id,outcome:outcome.dataset.guideOutcome});$('#guide-feedback-message').textContent=data.message;if(data.outcome==='failed')$('#guide-error-text').focus();}catch(exc){error(exc.message);}finally{busy(false);}return;}
    if(event.target.closest('#guide-prepare')){
      busy(true,'正在准备所选软件的启动文件…');error('');
      try{const profile=await api('/api/troubleshoot/profile',{check_id:state.result.check_id});state.profile=profile;
        $('#guide-action').innerHTML=`<div class="guide-launch"><h3>${h(profile.app_name)} · ${h(profile.proxy_url)}</h3><ol>${profile.steps.map(text=>`<li>${h(text)}</li>`).join('')}</ol><p>先关闭目标软件，保留代理客户端运行，然后点击：</p><button id="guide-launch" class="button button-primary">按方案启动 ${h(profile.app_name)}</button><p id="guide-launch-status" role="status"></p><details><summary>也可以下载启动文件手动运行</summary><button id="guide-download" class="button button-outline">下载启动文件</button><p>下载后在 PowerShell 中运行：</p><code>&amp; '下载文件的完整路径' -Launch</code><details><summary>查看启动文件内容</summary><pre>${h(profile.content)}</pre></details></details><p class="guide-hint">准备和下载不会执行程序；启动文件只为目标新进程设置代理环境，是否采用仍需实际重试确认。</p></div>`;
      }catch(exc){error(exc.message);}finally{busy(false);}return;
    }
    if(event.target.closest('#guide-download')&&state.profile){
      const blob=new Blob(['\ufeff',state.profile.content],{type:'text/plain;charset=utf-8'}),url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download=state.profile.filename;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
    }
    if(event.target.closest('#guide-launch')&&state.profile){
      busy(true,'正在确认目标软件已关闭，然后按方案创建新进程…');error('');
      try{const launched=await api('/api/troubleshoot/launch',{check_id:state.result.check_id});$('#guide-launch-status').textContent=launched.notice+' · PID '+launched.pid;}
      catch(exc){error(exc.message);}finally{busy(false);}
    }
  });
  document.addEventListener('flowdesk:catalog-mutated',event=>{state.inventoryRevision++;invalidate();load(event.detail?.app_id);});
  document.addEventListener('flowdesk:workspace',event=>{if(event.detail?.name==='guide')load();});
  load();
  setInterval(()=>{if(!$('#guide-workspace').hidden&&!state.busy)load();},5000);
})();
