'use strict';
// Actual canvas functions with synthetic DOM/API: never launches a user application.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict'),path=require('node:path'),crypto=require('node:crypto');
const root=path.resolve(__dirname,'..'),product=fs.readFileSync(path.join(root,'web/app.js'),'utf8');
const begin=product.indexOf('  const appFlowApps'),end=product.indexOf('  function renderLibrary',begin);
assert(begin>0&&end>begin);const source=product.slice(begin,end),nodes=new Map(),calls=[],passed=[],confirmations=[];
const node=selector=>{if(!nodes.has(selector))nodes.set(selector,{innerHTML:'',textContent:'',value:'',hidden:false,disabled:false,scrollTop:0,style:{},classList:{add(){},toggle(){}},setAttribute(){}});return nodes.get(selector);};
const seed={catalog:{apps:[{id:'setup',name:'Hermes <fixture>',category:'application',protected:false,running_processes:[]},{id:'codex',name:'Codex',category:'application',protected:true,running_processes:[]}]},routes:[{app_id:'setup',saved:false,mode:'inherit',proxy_url:'',can_apply:true,method:'新进程环境',notice:'应用需要支持',executable:'C:\\Fixture\\Hermes.exe',running:false}],tools:[{id:'v2rayn',name:'v2rayN',state_label:'运行中',proxy_options:[{protocol:'http',proxy_url:'http://127.0.0.1:10808',host:'127.0.0.1',port:10808}],endpoints:[]},{id:'uu',name:'UU',state_label:'运行中',kind:'加速器',proxy_options:[],listener_count:1,endpoints:[{transport:'tcp',port:60443}]}]};
const state={appMode:true,workspace:'routing',appRoutes:JSON.parse(JSON.stringify(seed)),runtime:{channels:[]},appScene:['setup'],appDraftTargets:{},appLayout:{},selected:{kind:'channel',id:'flow:setup'},plan:{name:'Existing relay plan',targets:[{id:'direct',type:'direct'}],channels:[{id:'legacy',default_target:'direct'}]},pending:null,appFlowBusy:false,connected:true,appFlowLoading:false,focusMode:true};
const baseline=JSON.stringify(state.plan);let pendingSave=null,pendingInspect=null,pendingPrepare=null,confirmResult=true,prepareResult={ticket:'fixture-ticket',can_launch:true,requires_confirmation:false,summary:'Ready',steps:[],notice:''};const failures=new Map();
const context={state,$:node,$$:()=>[],h:value=>String(value??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'),icon:()=>'',pointer:null,
  localStorage:{setItem(){}},requestAnimationFrame:()=>{},fit(){},applyView(){},requestEdges(){},isSelected:()=>false,
  cancelConnection:()=>{state.pending=null;},renderGraph(){},renderInspector(){context.renderAppFlowInspector();},renderLibrary(){},showInspector(){},activity(){},toast(){},
  confirm(message){confirmations.push(message);return confirmResult;},
  api:async(endpoint,method='GET',body)=>{calls.push({endpoint,method,body:body&&JSON.parse(JSON.stringify(body))});
    const failure=failures.get(endpoint);if(failure)throw new Error(failure);
    if(endpoint==='/api/app-routes')return JSON.parse(JSON.stringify(state.appRoutes));
    if(endpoint.endsWith('/save')){if(pendingSave)return pendingSave;const result=JSON.parse(JSON.stringify(state.appRoutes));Object.assign(result.routes.find(item=>item.app_id===body.app_id),body,{saved:true});return result;}
    if(endpoint.endsWith('/inspect'))return pendingInspect||{summary:'检查软件 <fixture>',checks:[{label:'后台代理',status:'warning',detail:'未设置 HTTPS_PROXY'}],backend:{state:'running',pid:456}};
    if(endpoint.endsWith('/shortcut'))return {notice:'桌面快捷方式已创建；目标尚未启动。',path:'C:\\Fixture\\Desktop\\Hermes.lnk'};
    if(endpoint.endsWith('/prepare-launch'))return pendingPrepare||JSON.parse(JSON.stringify(prepareResult));
    if(endpoint.endsWith('/launch'))return {...JSON.parse(JSON.stringify(state.appRoutes)),launch:{pid:123,notice:'fixture launch'}};
    throw new Error('Unexpected operation '+endpoint);
  }};
vm.createContext(context);vm.runInContext(source,context);context.channel=id=>context.appFlowChannels().find(item=>item.id===id);context.target=id=>context.appFlowTargets().find(item=>item.id===id);
const call=code=>vm.runInContext(code,context),launchCalls=()=>calls.filter(item=>item.endpoint==='/api/app-routes/launch').length;
async function check(name,work){await work();assert.equal(JSON.stringify(state.plan),baseline,'App wiring must not alter the legacy relay plan');assert.equal(state.appFlowBusy,false,'Action lock must be released');passed.push(name);}
function selectedSetup(){state.selected={kind:'channel',id:'flow:setup'};}
(async()=>{
  await check('Recognized HTTP entrance appears as a target; UU private port is not wireable',async()=>{
    const targets=context.appFlowTargets();assert(targets.some(item=>item.proxy_url==='http://127.0.0.1:10808'));assert(!targets.some(item=>item.port===60443));
    assert(targets.some(item=>item.type==='inherit'));assert(targets.some(item=>item.type==='clear'));
  });
  await check('Wire drawing changes the draft without executing or saving anything',async()=>{
    state.pending={channel:'flow:setup'};context.appFlowConnect('flow-proxy:http://127.0.0.1:10808');
    assert.equal(call('appFlowChoice("setup").mode'),'http_environment');assert.equal(calls.length,0);assert.equal(call('appFlowSaved("setup")'),false);
  });
  await check('Inspector offers software checks and shortcut with explicit saved-versus-applied wording',async()=>{
    context.renderAppFlowGraph();assert(node('#node-layer').innerHTML.includes('v2rayN'));assert(node('#node-layer').innerHTML.includes('Hermes &lt;fixture&gt;'));
    context.renderAppFlowInspector();const html=node('#inspector-content').innerHTML;assert(html.includes('保存连接设置'));assert(html.includes('按此设置启动'));assert(html.includes('检查此软件'));assert(html.includes('创建桌面快捷方式'));assert(html.includes('保存不会立即改变软件的连接'));
  });
  await check('Save persists only the selected connection and never starts software',async()=>{
    await context.appFlowAction('save');assert.equal(calls.at(-1).endpoint,'/api/app-routes/save');assert.deepEqual(calls.at(-1).body,{app_id:'setup',mode:'http_environment',proxy_url:'http://127.0.0.1:10808'});
    assert.equal(call('appFlowSaved("setup")'),true);assert.equal(launchCalls(),0);
  });
  await check('Launch first prepares, then uses only the issued ticket and app identity',async()=>{
    const start=calls.length;await context.appFlowAction('launch');assert.deepEqual(calls.slice(start).map(item=>item.endpoint),['/api/app-routes/prepare-launch','/api/app-routes/launch']);assert.deepEqual(calls.at(-1).body,{app_id:'setup',ticket:'fixture-ticket'});
  });
  await check('Software check displays escaped structured evidence without save, launch or restart',async()=>{
    const start=calls.length;await context.appFlowAction('inspect');assert.deepEqual(calls.slice(start).map(item=>item.endpoint),['/api/app-routes/inspect']);const html=node('#inspector-content').innerHTML;assert(html.includes('检查软件 &lt;fixture&gt;'));assert(html.includes('未设置 HTTPS_PROXY'));assert(html.includes('需要注意'));assert(!html.includes('检查软件 <fixture>'));
  });
  await check('Shortcut creation does not replace routes or launch a program',async()=>{
    const start=calls.length,before=JSON.stringify(state.appRoutes);await context.appFlowAction('shortcut');assert.deepEqual(calls.slice(start).map(item=>item.endpoint),['/api/app-routes/shortcut']);assert.equal(JSON.stringify(state.appRoutes),before);assert(state.appFlowMessages.setup.text.includes('快捷方式'));
  });
  await check('Running Hermes has an apply-and-open action and explains its independent backend',async()=>{
    Object.assign(state.appRoutes.routes[0],{running:true,integration:{id:'hermes',label:'Hermes 窗口与后台',notice:'后台需要采用独立代理设置。'}});context.renderAppFlowInspector();const html=node('#inspector-content').innerHTML;assert(html.includes('应用并打开'));assert(html.includes('Hermes 窗口与独立后台'));assert(html.includes('首次应用可能需要从 Hermes 菜单正常退出旧窗口'));assert(html.includes('后台处理会另行预览'));
  });
  await check('Backend changes show the actual preparation steps and cancellation never launches',async()=>{
    prepareResult={ticket:'restart-ticket',can_launch:true,requires_confirmation:true,summary:'将重启 Hermes 后台',steps:['等待当前任务结束','重启独立后台并设置代理'],notice:'其他本机 Hermes 窗口会重新连接。'};confirmResult=false;const before=launchCalls();await context.appFlowAction('launch');assert.equal(launchCalls(),before);assert(confirmations.at(-1).includes('重启独立后台并设置代理'));assert(confirmations.at(-1).includes('其他本机 Hermes 窗口'));assert(state.appFlowMessages.setup.text.includes('已取消'));
  });
  await check('Confirmed backend preparation sends its current ticket',async()=>{
    confirmResult=true;const before=launchCalls();await context.appFlowAction('launch');assert.equal(launchCalls(),before+1);assert.equal(calls.at(-1).body.ticket,'restart-ticket');
  });
  await check('Blocked preparation and a missing ticket never launch',async()=>{
    const before=launchCalls();prepareResult={can_launch:false,summary:'后台正在执行任务，请稍后重试'};await context.appFlowAction('launch');assert.equal(launchCalls(),before);assert(state.appFlowMessages.setup.text.includes('正在执行任务'));
    prepareResult={can_launch:true,requires_confirmation:false};await context.appFlowAction('launch');assert.equal(launchCalls(),before);assert(state.appFlowMessages.setup.error);
  });
  await check('A changed connection during preparation cannot apply an obsolete ticket',async()=>{
    let resolve;pendingPrepare=new Promise(done=>resolve=done);const before=launchCalls(),task=context.appFlowAction('launch');await new Promise(done=>setImmediate(done));state.appDraftTargets.setup='flow-clear';resolve({ticket:'old-ticket',can_launch:true});await task;pendingPrepare=null;assert.equal(launchCalls(),before);assert(state.appFlowMessages.setup.text.includes('已变化'));delete state.appDraftTargets.setup;
  });
  await check('Installer is identified as an installer with guidance to select the installed main program',async()=>{
    state.appRoutes.routes[0].integration={id:'installer',label:'Hermes 安装器',notice:'当前是安装包。'};context.renderAppFlowInspector();assert(node('#inspector-content').innerHTML.includes('日常连接请添加安装后的 Hermes 主程序'));assert(!node('#inspector-content').innerHTML.includes('>应用并打开<'));
    state.appRoutes.routes[0].integration=null;state.appRoutes.routes[0].running=false;
  });
  await check('Failed inspect or shortcut stays an explicit failure and releases the action lock',async()=>{
    for(const action of ['inspect','shortcut']){const endpoint='/api/app-routes/'+action;failures.set(endpoint,'fixture '+action+' failed');await context.appFlowAction(action);assert.equal(state.appFlowBusy,false);assert(state.appFlowMessages.setup.error);assert(state.appFlowMessages.setup.text.includes('failed'));failures.delete(endpoint);}
  });
  await check('Rewiring requires saving before launch or shortcut',async()=>{
    state.pending={channel:'flow:setup'};context.appFlowConnect('flow-clear');assert.equal(call('appFlowSaved("setup")'),false);const count=calls.length;await context.appFlowAction('launch');await context.appFlowAction('shortcut');assert.equal(calls.length,count);
    await context.appFlowAction('save');assert.equal(calls.at(-1).body.mode,'clear_environment');assert.equal(calls.at(-1).body.proxy_url,'');
  });
  await check('A newer wire made while saving stays an unsaved draft',async()=>{
    state.pending={channel:'flow:setup'};context.appFlowConnect('flow-default');let resolve;pendingSave=new Promise(done=>resolve=done);const task=context.appFlowAction('save');
    await new Promise(done=>setImmediate(done));state.pending={channel:'flow:setup'};context.appFlowConnect('flow-clear');const response=JSON.parse(JSON.stringify(state.appRoutes));Object.assign(response.routes[0],{mode:'inherit',proxy_url:'',saved:true});resolve(response);await task;pendingSave=null;
    assert.equal(call('appFlowChoice("setup").mode'),'clear_environment');assert.equal(call('appFlowSaved("setup")'),false);delete state.appDraftTargets.setup;
  });
  await check('A late diagnostic is retained for its application and never shown under another selection',async()=>{
    state.appRoutes.catalog.apps.push({id:'other',name:'Other',category:'application',protected:false,running_processes:[]});state.appRoutes.routes.push({app_id:'other',saved:false,mode:'inherit',proxy_url:'',can_apply:true,method:'新进程环境',notice:'Other notice',executable:'C:\\Fixture\\Other.exe',running:false});state.appScene.push('other');
    let resolve;pendingInspect=new Promise(done=>resolve=done);const task=context.appFlowAction('inspect');await new Promise(done=>setImmediate(done));state.selected={kind:'channel',id:'flow:other'};resolve({summary:'Only setup diagnostic',checks:[]});await task;pendingInspect=null;context.renderAppFlowInspector();assert(!node('#inspector-content').innerHTML.includes('Only setup diagnostic'));assert.equal(state.appFlowInspections.setup.summary,'Only setup diagnostic');assert(!state.appFlowMessages.other);
  });
  await check('Selection changes during launch preparation cancel application of the prepared target',async()=>{
    selectedSetup();let resolve;pendingPrepare=new Promise(done=>resolve=done);const before=launchCalls(),task=context.appFlowAction('launch');await new Promise(done=>setImmediate(done));state.selected={kind:'channel',id:'flow:other'};resolve({ticket:'old-selection',can_launch:true});await task;pendingPrepare=null;assert.equal(launchCalls(),before);assert(!node('#inspector-content').innerHTML.includes('所选软件或连接方式已变化'));
  });
  await check('Protected applications cannot become editable source nodes',async()=>{
    context.appFlowAdd('codex');assert(!state.appScene.includes('codex'));context.renderAppFlowInspector();assert(!node('#inspector-content').innerHTML.includes('id="flow-save"'));
  });
  await check('Inspecting an entrance preserves the focused application in a multi-app diagram',async()=>{
    state.selected={kind:'channel',id:'flow:other'};context.renderAppFlowGraph();state.selected={kind:'target',id:'flow-proxy:http://127.0.0.1:10808'};context.renderAppFlowGraph();assert(state.worldNodes.some(item=>item.id==='flow:other'));assert(!state.worldNodes.some(item=>item.id==='flow:setup'));
  });
  const report={checked_at:new Date().toISOString(),method:'Actual canvas model, renderer and actions with synthetic DOM/API; no browser visual check and no application launches',passed,count:passed.length,source_sha256:{'web/app.js':crypto.createHash('sha256').update(product).digest('hex')}};
  fs.mkdirSync(path.join(root,'artifacts'),{recursive:true});fs.writeFileSync(path.join(root,'artifacts/app-flow-ui-verification.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({passed:true,count:passed.length}));
})().catch(error=>{console.error(error);process.exitCode=1;});
