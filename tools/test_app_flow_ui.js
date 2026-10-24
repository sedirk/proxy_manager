'use strict';
// Execute the canvas connection model and actions with synthetic DOM/API only.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict'),path=require('node:path'),crypto=require('node:crypto');
const root=path.resolve(__dirname,'..'),product=fs.readFileSync(path.join(root,'web/app.js'),'utf8');
const begin=product.indexOf('  const appFlowApps'),end=product.indexOf('  function renderLibrary',begin);
assert(begin>0&&end>begin);const source=product.slice(begin,end),nodes=new Map(),calls=[],passed=[];
const node=selector=>{if(!nodes.has(selector))nodes.set(selector,{innerHTML:'',textContent:'',value:'',hidden:false,disabled:false,scrollTop:0,style:{},classList:{add(){},toggle(){}},setAttribute(){}});return nodes.get(selector);};
const seed={catalog:{apps:[{id:'setup',name:'Hermes <fixture>',category:'application',protected:false,running_processes:[]},{id:'codex',name:'Codex',category:'application',protected:true,running_processes:[]}]},routes:[{app_id:'setup',saved:false,mode:'inherit',proxy_url:'',can_apply:true,method:'新进程环境',notice:'应用需要支持',executable:'C:\\Fixture\\Hermes.exe',running:false}],tools:[{id:'v2rayn',name:'v2rayN',state_label:'运行中',proxy_options:[{protocol:'http',proxy_url:'http://127.0.0.1:10808',host:'127.0.0.1',port:10808}],endpoints:[]},{id:'uu',name:'UU',state_label:'运行中',kind:'加速器',proxy_options:[],listener_count:1,endpoints:[{transport:'tcp',port:60443}]}]};
const state={appMode:true,workspace:'routing',appRoutes:JSON.parse(JSON.stringify(seed)),runtime:{channels:[]},appScene:['setup'],appDraftTargets:{},appLayout:{},selected:{kind:'channel',id:'flow:setup'},plan:{name:'Existing relay plan',targets:[{id:'direct',type:'direct'}],channels:[{id:'legacy',default_target:'direct'}]},pending:null,appFlowBusy:false,connected:true,appFlowLoading:false,focusMode:true};
const baseline=JSON.stringify(state.plan);let pendingSave=null;
const context={state,$:node,$$:()=>[],h:value=>String(value??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'),icon:()=>'',pointer:null,
  localStorage:{setItem(){}},requestAnimationFrame:()=>{},fit(){},applyView(){},requestEdges(){},isSelected:()=>false,
  cancelConnection:()=>{state.pending=null;},renderGraph(){},renderInspector(){},renderLibrary(){},showInspector(){},activity(){},toast(){},
  api:async(endpoint,method='GET',body)=>{calls.push({endpoint,method,body:body&&JSON.parse(JSON.stringify(body))});
    if(endpoint==='/api/app-routes')return JSON.parse(JSON.stringify(state.appRoutes));
    if(endpoint.endsWith('/save')){if(pendingSave)return pendingSave;const result=JSON.parse(JSON.stringify(state.appRoutes));Object.assign(result.routes[0],body,{saved:true});return result;}
    if(endpoint.endsWith('/launch'))return {...JSON.parse(JSON.stringify(state.appRoutes)),launch:{pid:123,notice:'fixture launch'}};
    throw new Error('Unexpected operation '+endpoint);
  }};
vm.createContext(context);vm.runInContext(source,context);context.channel=id=>context.appFlowChannels().find(item=>item.id===id);context.target=id=>context.appFlowTargets().find(item=>item.id===id);
const call=code=>vm.runInContext(code,context);
async function check(name,work){await work();assert.equal(JSON.stringify(state.plan),baseline,'App wiring must not alter the legacy relay plan');passed.push(name);}
(async()=>{
  await check('Recognized HTTP entrance appears as a target; UU private port is not wireable',async()=>{
    const targets=context.appFlowTargets();assert(targets.some(item=>item.proxy_url==='http://127.0.0.1:10808'));assert(!targets.some(item=>item.port===60443));
    assert(targets.some(item=>item.type==='inherit'));assert(targets.some(item=>item.type==='clear'));
  });
  await check('Wire drawing changes the app connection draft without executing or saving anything',async()=>{
    state.pending={channel:'flow:setup'};context.appFlowConnect('flow-proxy:http://127.0.0.1:10808');
    assert.equal(call('appFlowChoice("setup").mode'),'http_environment');assert.equal(calls.length,0);assert.equal(call('appFlowSaved("setup")'),false);
  });
  await check('The graph and inspector render the same selected entrance and explain the application method',async()=>{
    context.renderAppFlowGraph();assert(node('#node-layer').innerHTML.includes('v2rayN'));assert(node('#node-layer').innerHTML.includes('Hermes &lt;fixture&gt;'));
    context.renderAppFlowInspector();assert(node('#inspector-content').innerHTML.includes('保存连接设置'));assert(node('#inspector-content').innerHTML.includes('按此设置启动'));assert(node('#inspector-content').innerHTML.includes('新进程环境'));
  });
  await check('Save applies only the selected software connection and marks the matching wire saved',async()=>{
    await context.appFlowAction('save');assert.equal(calls.at(-1).endpoint,'/api/app-routes/save');assert.deepEqual(calls.at(-1).body,{app_id:'setup',mode:'http_environment',proxy_url:'http://127.0.0.1:10808'});
    assert.equal(call('appFlowSaved("setup")'),true);assert(!calls.some(item=>item.endpoint.endsWith('/launch')));
  });
  await check('Launch is a separate explicit action bound to the saved software, not arbitrary parameters',async()=>{
    await context.appFlowAction('launch');assert.deepEqual(calls.at(-1).body,{app_id:'setup'});assert.equal(calls.at(-1).endpoint,'/api/app-routes/launch');
  });
  await check('Rewiring to clear mode invalidates saved status and cannot launch until saved',async()=>{
    state.pending={channel:'flow:setup'};context.appFlowConnect('flow-clear');assert.equal(call('appFlowSaved("setup")'),false);const count=calls.length;await context.appFlowAction('launch');assert.equal(calls.length,count);
    await context.appFlowAction('save');assert.equal(calls.at(-1).body.mode,'clear_environment');assert.equal(calls.at(-1).body.proxy_url,'');
  });
  await check('A newer wire made while saving is retained as an unsaved draft',async()=>{
    state.pending={channel:'flow:setup'};context.appFlowConnect('flow-default');let resolve;pendingSave=new Promise(done=>resolve=done);const task=context.appFlowAction('save');
    await new Promise(done=>setImmediate(done));state.pending={channel:'flow:setup'};context.appFlowConnect('flow-clear');const response=JSON.parse(JSON.stringify(state.appRoutes));Object.assign(response.routes[0],{mode:'inherit',proxy_url:'',saved:true});resolve(response);await task;pendingSave=null;
    assert.equal(call('appFlowChoice("setup").mode'),'clear_environment');assert.equal(call('appFlowSaved("setup")'),false);
  });
  await check('Protected applications are inspected without becoming editable source nodes',async()=>{
    context.appFlowAdd('codex');assert(!state.appScene.includes('codex'));context.renderAppFlowInspector();assert(!node('#inspector-content').innerHTML.includes('id="flow-save"'));
  });
  await check('Inspecting an entrance preserves the focused application in a multi-application diagram',async()=>{
    state.appRoutes.catalog.apps.push({id:'other',name:'Other',category:'application',protected:false,running_processes:[]});state.appScene.push('other');state.selected={kind:'channel',id:'flow:other'};context.renderAppFlowGraph();
    state.selected={kind:'target',id:'flow-proxy:http://127.0.0.1:10808'};context.renderAppFlowGraph();assert(state.worldNodes.some(item=>item.id==='flow:other'));assert(!state.worldNodes.some(item=>item.id==='flow:setup'));
  });
  const report={checked_at:new Date().toISOString(),method:'Actual canvas model, renderer and action functions with synthetic DOM/API; no browser visual check',passed,count:passed.length,source_sha256:{'web/app.js':crypto.createHash('sha256').update(product).digest('hex')}};
  fs.mkdirSync(path.join(root,'artifacts'),{recursive:true});fs.writeFileSync(path.join(root,'artifacts/app-flow-ui-verification.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({passed:true,count:passed.length}));
})().catch(error=>{console.error(error);process.exitCode=1;});
