'use strict';
// Actual canvas functions with synthetic DOM/API: never launches a user application.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict'),path=require('node:path'),crypto=require('node:crypto');
const root=path.resolve(__dirname,'..'),product=fs.readFileSync(path.join(root,'web/app.js'),'utf8');
const begin=product.indexOf('  const appFlowApps'),end=product.indexOf('  function renderLibrary',begin);
assert(begin>0&&end>begin);const source=product.slice(begin,end),nodes=new Map(),calls=[],passed=[],confirmations=[],frames=[];
const node=selector=>{if(!nodes.has(selector))nodes.set(selector,{innerHTML:'',textContent:'',value:'',hidden:false,disabled:false,scrollTop:0,style:{},classList:{add(){},toggle(){}},setAttribute(){}});return nodes.get(selector);};
const seed={catalog:{apps:[{id:'setup',name:'Hermes <fixture>',category:'application',protected:false,running_processes:[]},{id:'codex',name:'Codex',category:'application',protected:true,running_processes:[]}]},routes:[{app_id:'setup',saved:false,mode:'inherit',proxy_url:'',can_apply:true,method:'新进程环境',notice:'应用需要支持',executable:'C:\\Fixture\\Hermes.exe',running:false}],tools:[{id:'v2rayn',name:'v2rayN',state_label:'运行中',proxy_options:[{protocol:'http',proxy_url:'http://127.0.0.1:10808',host:'127.0.0.1',port:10808}],endpoints:[]},{id:'uu',name:'UU',state_label:'运行中',kind:'加速器',proxy_options:[],listener_count:1,endpoints:[{transport:'tcp',port:60443}]}]};
const state={appMode:true,workspace:'routing',appRoutes:JSON.parse(JSON.stringify(seed)),runtime:{channels:[]},appScene:['setup'],appDraftTargets:{},appLayout:{},selected:{kind:'channel',id:'flow:setup'},plan:{name:'Existing relay plan',targets:[{id:'direct',type:'direct'}],channels:[{id:'legacy',default_target:'direct'}]},pending:null,appFlowBusy:false,connected:true,appFlowLoading:false,focusMode:true};
const baseline=JSON.stringify(state.plan);let pendingSave=null,pendingInspect=null,pendingPrepare=null,confirmResult=true,pendingToolCheck=null,toolCheckResult=null,prepareResult={ticket:'fixture-ticket',can_launch:true,requires_confirmation:false,summary:'Ready',steps:[],notice:''};const failures=new Map();
Object.assign(node('#graph-viewport'),{clientWidth:900,clientHeight:600,getBoundingClientRect:()=>({left:10,top:20})});
const context={state,document:{activeElement:{closest:()=>null}},$:node,$$:()=>[],h:value=>String(value??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'),icon:()=>'',pointer:null,
  localStorage:{setItem(){}},requestAnimationFrame:callback=>frames.push(callback),fit(){},applyView(){},requestEdges(){},isSelected:()=>false,
  cancelConnection:()=>{state.pending=null;},renderGraph(){context.renderAppFlowGraph();},renderInspector(){context.renderAppFlowInspector();},renderLibrary(){context.renderAppFlowLibrary();},showInspector(){},activity(){},toast(){},
  confirm(message){confirmations.push(message);return confirmResult;},
  api:async(endpoint,method='GET',body)=>{calls.push({endpoint,method,body:body&&JSON.parse(JSON.stringify(body))});
    const failure=failures.get(endpoint);if(failure)throw new Error(failure);
    if(endpoint==='/api/network-tools/check')return pendingToolCheck||JSON.parse(JSON.stringify(toolCheckResult));
    if(endpoint==='/api/app-routes')return JSON.parse(JSON.stringify(state.appRoutes));
    if(endpoint.endsWith('/save')){if(pendingSave)return pendingSave;const result=JSON.parse(JSON.stringify(state.appRoutes));Object.assign(result.routes.find(item=>item.app_id===body.app_id),body,{saved:true});return result;}
    if(endpoint.endsWith('/inspect'))return pendingInspect||{summary:'检查软件 <fixture>',checks:[{label:'后台代理',status:'warning',detail:'未设置 HTTPS_PROXY'}],backend:{state:'running',pid:456}};
    if(endpoint.endsWith('/shortcut'))return {notice:'桌面快捷方式已创建；目标尚未启动。',path:'C:\\Fixture\\Desktop\\Hermes.lnk'};
    if(endpoint.endsWith('/prepare-launch'))return pendingPrepare||JSON.parse(JSON.stringify(prepareResult));
    if(endpoint.endsWith('/launch'))return {...JSON.parse(JSON.stringify(state.appRoutes)),launch:{pid:123,notice:'fixture launch'}};
    throw new Error('Unexpected operation '+endpoint);
  }};
vm.createContext(context);vm.runInContext(source,context);context.channel=id=>context.appFlowChannels().find(item=>item.id===id);context.target=id=>context.appFlowTargets().find(item=>item.id===id);
vm.runInContext(product.slice(product.indexOf('  function selectNode(node)'),product.indexOf('  function connect(to)',product.indexOf('  function selectNode(node)'))),context);
const runFrames=()=>{while(frames.length)frames.shift()();};
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
  await check('All network tools have a keyboard-accessible show action and draggable cards',async()=>{
    state.appRoutes.tools.push({id:'zerotier',name:'ZeroTier',kind:'组网工具',state_label:'运行中',proxy_options:[],endpoints:[]});context.renderAppFlowLibrary();const html=node('#application-library').innerHTML;
    assert(html.includes('data-flow-tool="uu" draggable="true" role="button" tabindex="0"'));assert(html.includes('data-flow-tool="zerotier"'));assert(html.includes('flow-tool-show'));assert(html.includes('显示已有入口'));
  });
  await check('Clicking an HTTP tool reuses and focuses its existing target without editing connections',async()=>{
    selectedSetup();context.renderAppFlowGraph();const before=JSON.stringify(state.appDraftTargets),count=calls.length;context.appFlowShowTool('v2rayn');runFrames();
    assert.equal(state.selected.kind,'target');assert.equal(state.selected.id,'flow-proxy:http://127.0.0.1:10808');assert.equal(state.appFlowSelected,'flow:setup');assert.equal(state.worldNodes.filter(item=>item.id==='target:'+state.selected.id).length,1);assert.equal(JSON.stringify(state.appDraftTargets),before);assert.equal(calls.length,count);
  });
  await check('Core and frontend reports of one HTTP address produce one canvas entrance',async()=>{
    state.appRoutes.tools.push({id:'xray',name:'Xray',kind:'代理核心',proxy_options:[{protocol:'http',port:10808,proxy_url:'http://127.0.0.1:10808'}],endpoints:[]});assert.equal(context.appFlowTargets().filter(item=>item.proxy_url==='http://127.0.0.1:10808').length,1);context.appFlowShowTool('xray');assert.equal(state.selected.id,'flow-proxy:http://127.0.0.1:10808');
  });
  await check('Unknown-protocol proxy becomes a non-wireable context card with an honest check action',async()=>{
    const tool=state.appRoutes.tools.find(item=>item.id==='v2rayn');tool.proxy_options=[];tool.endpoints=[{transport:'tcp',address:'127.0.0.1',port:10808,owner:'xray.exe'}];tool.can_check_http=true;selectedSetup();context.appFlowShowTool('v2rayn');context.renderAppFlowGraph();context.renderAppFlowInspector();
    const card=state.worldNodes.find(item=>item.id==='context:v2rayn');assert.equal(card.kind,'context');assert.equal(card.category,'v2rayn');assert(!card.target);assert.equal(state.appFlowSelected,'flow:setup');assert(node('#inspector-content').innerHTML.includes('尚未确认 HTTP 协议'));assert(node('#inspector-content').innerHTML.includes('检测代理入口'));
    const html=node('#node-layer').innerHTML,part=html.slice(html.indexOf('data-node="context:v2rayn"'));assert(!part.includes('data-target-input'));
    context.selectNode(card);assert.deepEqual(JSON.parse(JSON.stringify(state.selected)),{kind:'context',id:'v2rayn'});
  });
  await check('Keyboard tool selection preserves the source application and does not auto-connect',async()=>{
    selectedSetup();let prevented=false;const card={dataset:{flowTool:'uu'}},event={key:'Enter',target:{closest:selector=>selector==='[data-flow-tool]'?card:null},preventDefault(){prevented=true;}};const before=JSON.stringify(state.appDraftTargets);assert.equal(context.appFlowToolKeydown(event),true);assert(prevented);assert.equal(state.selected.id,'uu');assert.equal(state.appFlowSelected,'flow:setup');assert.equal(JSON.stringify(state.appDraftTargets),before);
    assert.equal(context.appFlowToolKeydown({...event,key:'Tab'}),false);
  });
  await check('Actual tool drag/drop events move an existing HTTP target and preserve the app route',async()=>{
    const data=new Map(),transfer={setData:(key,value)=>data.set(key,value),getData:key=>data.get(key)||''},card={dataset:{flowTool:'xray'}};const before=JSON.stringify(state.appDraftTargets),count=calls.length;
    assert.equal(context.appFlowToolDragStart({target:{closest:selector=>selector==='[data-flow-tool]'?card:null},dataTransfer:transfer,preventDefault(){}}),true);assert.equal(transfer.effectAllowed,'copy');state.view={x:0,y:0,zoom:1};
    assert.equal(context.appFlowToolDrop({dataTransfer:transfer,clientX:410,clientY:320,preventDefault(){}}),true);assert.deepEqual(JSON.parse(JSON.stringify(state.appLayout['target:flow-proxy:http://127.0.0.1:10808'])),{x:400,y:300});assert.equal(state.worldNodes.filter(item=>item.id==='target:flow-proxy:http://127.0.0.1:10808').length,1);assert.equal(JSON.stringify(state.appDraftTargets),before);assert.equal(calls.length,count);
  });
  await check('UU and ZeroTier can be dropped as context but are never HTTP-probed',async()=>{
    const count=calls.length;for(const id of ['uu','zerotier']){const tool=state.appRoutes.tools.find(item=>item.id===id);tool.can_check_http=true;context.appFlowShowTool(id,{x:800,y:90});assert(state.worldNodes.some(item=>item.kind==='context'&&item.category===id));assert.equal(context.appFlowToolCanCheck(tool),false);await context.appFlowToolCheck(id);assert(!node('#inspector-content').innerHTML.includes('id="flow-tool-check"'));}assert.equal(calls.length,count);
    const proxy=state.appRoutes.tools.find(item=>item.id==='v2rayn');proxy.can_check_http=false;assert.equal(context.appFlowToolCanCheck(proxy),false);await context.appFlowToolCheck(proxy.id);assert.equal(calls.length,count);proxy.can_check_http=true;
  });
  await check('SOCKS-only evidence is not presented as an HTTP entrance',async()=>{
    const tool=state.appRoutes.tools.find(item=>item.id==='v2rayn');tool.proxy_options=[{protocol:'socks5',port:10808,proxy_url:'socks5://127.0.0.1:10808'}];context.appFlowShowTool(tool.id);assert.equal(state.selected.kind,'context');assert(node('#inspector-content').innerHTML.includes('目前仅识别到 SOCKS 入口'));assert(node('#inspector-content').innerHTML.includes('当前应用连接需要 HTTP 入口'));tool.proxy_options=[];
  });
  await check('Successful HTTP detection reveals its target but never changes or saves an application connection',async()=>{
    context.appFlowShowTool('v2rayn');const before=JSON.stringify(state.appDraftTargets),routes=JSON.stringify(state.appRoutes.routes),result=JSON.parse(JSON.stringify(state.appRoutes));result.tools.find(item=>item.id==='v2rayn').proxy_options=[{protocol:'http',port:10808,host:'127.0.0.1',proxy_url:'http://127.0.0.1:10808'}];toolCheckResult={summary:'已确认 HTTP CONNECT',checks:[{label:'HTTP',status:'ok',detail:'握手成功 <fixture>'}],app_routes:result};const start=calls.length;
    await context.appFlowToolCheck('v2rayn');assert.deepEqual(calls.slice(start).map(item=>item.endpoint),['/api/network-tools/check']);assert.deepEqual(calls.at(-1).body,{tool_id:'v2rayn'});assert.equal(state.selected.kind,'target');assert.equal(JSON.stringify(state.appDraftTargets),before);assert.equal(JSON.stringify(state.appRoutes.routes),routes);assert(node('#inspector-content').innerHTML.includes('握手成功 &lt;fixture&gt;'));assert.equal(state.appToolChecking,null);runFrames();
  });
  await check('Late detection updates evidence without stealing a different application selection',async()=>{
    const tool=state.appRoutes.tools.find(item=>item.id==='v2rayn');tool.proxy_options=[];context.appFlowShowTool(tool.id);let resolve;pendingToolCheck=new Promise(done=>resolve=done);const task=context.appFlowToolCheck(tool.id);await new Promise(done=>setImmediate(done));assert(state.appFlowBusy);const count=calls.length;await context.appFlowAction('save');assert.equal(calls.length,count);state.selected={kind:'channel',id:'flow:other'};context.renderAppFlowGraph();resolve(toolCheckResult);await task;pendingToolCheck=null;assert.equal(state.selected.id,'flow:other');assert(!node('#inspector-content').innerHTML.includes('已确认 HTTP CONNECT'));
  });
  await check('Failed entry detection preserves routes and displays its tool-specific error',async()=>{
    context.appFlowShowTool('v2rayn');const before=JSON.stringify(state.appRoutes);failures.set('/api/network-tools/check','本机入口检测失败');await context.appFlowToolCheck('v2rayn');failures.delete('/api/network-tools/check');assert.equal(JSON.stringify(state.appRoutes),before);assert(state.appToolMessages.v2rayn.error);assert(node('#inspector-content').innerHTML.includes('本机入口检测失败'));assert.equal(state.appToolChecking,null);
  });
  await check('An offscreen entrance is brought into view even when far from the selected app',async()=>{
    state.appLayout['target:flow-proxy:http://127.0.0.1:10808']={x:9000,y:8000};context.appFlowShowTool('v2rayn');runFrames();const chosen=state.worldNodes.find(item=>item.id==='target:'+state.selected.id),x=chosen.position.x*state.view.zoom+state.view.x,y=chosen.position.y*state.view.zoom+state.view.y;assert(x>=0&&x<900);assert(y>=0&&y<600);assert.equal(state.appFlowSelected,'flow:other');
  });
  await check('Initial asynchronous route load frames its first HTTP entrance',async()=>{
    state.appFlowInitialFit=false;state.appFlowEntranceFit=false;state.appFlowSignature=null;state.view={x:0,y:0,zoom:1};await context.appFlowLoad();runFrames();assert(state.appFlowInitialFit);assert(state.appFlowEntranceFit);const entry=state.worldNodes.find(item=>item.id==='target:flow-proxy:http://127.0.0.1:10808');assert(entry.position.x*state.view.zoom+state.view.x<900);
  });
  await check('Unknown proxy card promises an HTTP check, while accelerator cards retain their private-port explanation',async()=>{
    const proxy=state.appRoutes.tools.find(item=>item.id==='v2rayn');proxy.proxy_options=[];proxy.can_check_http=true;context.appFlowShowTool(proxy.id);let html=node('#node-layer').innerHTML;const begin=html.indexOf('data-node="context:v2rayn"'),end=html.indexOf('</article>',begin),card=html.slice(begin,end);assert(card.includes('确认 HTTP 入口后即可连接应用'));assert(!card.includes('专用端口不作为 HTTP 代理出口'));
    context.appFlowShowTool('uu');html=node('#node-layer').innerHTML;assert(html.slice(html.indexOf('data-node="context:uu"')).includes('专用端口不作为 HTTP 代理出口'));
  });
  await check('Stopped proxies get a start-and-scan instruction instead of accelerator instructions',async()=>{
    const proxy=state.appRoutes.tools.find(item=>item.id==='v2rayn');proxy.can_check_http=false;proxy.endpoints=[];context.appFlowShowTool(proxy.id);let html=node('#inspector-content').innerHTML;assert(html.includes('尚未发现可检测的本机监听，请先打开代理软件，再点自动检测'));assert(!html.includes('加速和组网功能'));assert(!html.includes('id="flow-tool-check"'));
    proxy.proxy_options=[{protocol:'socks5',port:10808,proxy_url:'socks5://127.0.0.1:10808'}];context.appFlowShowTool(proxy.id);html=node('#inspector-content').innerHTML;assert(html.includes('目前仅识别到 SOCKS 入口'));assert(html.includes('当前应用连接需要 HTTP 入口'));assert(!html.includes('加速和组网功能'));
  });
  const report={checked_at:new Date().toISOString(),method:'Actual canvas model, renderer and actions with synthetic DOM/API; no browser visual check and no application launches',passed,count:passed.length,source_sha256:{'web/app.js':crypto.createHash('sha256').update(product).digest('hex')}};
  fs.mkdirSync(path.join(root,'artifacts'),{recursive:true});fs.writeFileSync(path.join(root,'artifacts/app-flow-ui-verification.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({passed:true,count:passed.length}));
})().catch(error=>{console.error(error);process.exitCode=1;});
