'use strict';
// Actual descriptions and renderers; synthetic DOM only, no browser layout claim.
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const root=path.resolve(__dirname,'..'),model=require('../web/routing-view.js'),source=fs.readFileSync(path.join(root,'web/app.js'),'utf8');
const passed=[],nodes=new Map();
function node(selector){if(!nodes.has(selector))nodes.set(selector,{innerHTML:'',textContent:'',hidden:false,style:{},classList:{add(){},toggle(){}}});return nodes.get(selector);}
const plan={name:'Fixture',targets:[{id:'direct',name:'直连 · 系统路由',type:'direct'},{id:'proxy',name:'Existing proxy',type:'http',host:'127.0.0.1',port:10808}],channels:[{id:'steam',app_id:'steam',name:'Steam',default_target:'proxy',rules:[{id:'download',domains:['steamcontent.com','*.steamcontent.com'],target:'direct'}]}],dns_overrides:{}};
const state={appMode:false,connected:true,dirty:false,plan,runtime:{running:false,channels:[]},events:[],selected:{kind:'channel',id:'steam'},pending:null,focusMode:true};
let cards=[],ports=[];
const context={state,FlowDeskRouting:model,$:node,$$:selector=>selector==='[data-rule-card]'?cards:selector==='[data-channel-output]'?ports.filter(p=>p.dataset.channelOutput):selector==='[data-target-input]'?ports.filter(p=>p.dataset.targetInput):[],
  h:value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),icon:()=>'',
  recipes:[{id:'steam',symbol:'S'}],category:()=> 'steam',target:id=>state.plan.targets.find(t=>t.id===id),channel:id=>state.plan.channels.find(c=>c.id===id),
  routeSignature:()=>JSON.stringify(state.plan),endpointText:item=>`${item.host}:${item.port}`,targetName:id=>id,
  visualNodes:()=>[{id:'app:steam',kind:'source',category:'steam',name:'Steam',channels:state.plan.channels,position:{x:50,y:100}},...state.plan.targets.map((target,index)=>({id:'target:'+target.id,kind:'target',target,position:{x:475,y:index*210}}))],
  isSelected:()=>true,applyView(){},requestEdges(){},renderInspector(){},showInspector(){},point:p=>p.point,curve:()=> 'M0 0 C0 0 1 1 2 2'};
vm.createContext(context);
function extract(begin,end){const start=source.indexOf(begin),stop=source.indexOf(end,start);assert(start>=0&&stop>start);vm.runInContext(source.slice(start,stop),context);}
extract('  function relayChannelStatus','  function showInspector');
extract('  function renderGraph()','  function applyView()');
extract('  function renderEdges()','  function fit()');
extract('  function renderInspectorBase()','  function renderActivity()');
const baseline=JSON.stringify(plan);
function check(name,work){work();assert.equal(JSON.stringify(plan),baseline,'Descriptions and rendering must not mutate the saved routing policy');passed.push(name);}
check('Bare domains and their wildcard pair are described together without changing rule data',()=>{
  assert.deepEqual(model.domains(plan.channels[0].rules[0]),['steamcontent.com 及其子域名']);
  assert.deepEqual(model.domains({domains:['*.example.com']}),['example.com 的子域名（不含它本身）']);
  assert.deepEqual(model.domains({domains:['*','other.test']}),['所有网站']);
  assert.match(model.ruleTitle({domains:[]}),/尚未填写/);
});
check('Graph shows concrete websites before the fallback and preserves each connector identity',()=>{
  context.renderGraph();const html=node('#node-layer').innerHTML;
  assert(html.includes('steamcontent.com 及其子域名'));assert(html.indexOf('<small>这些网站')<html.indexOf('<strong>其他网站'));
  assert(html.includes('data-rule-output="download"'));assert(html.includes('data-channel-output="steam"'));
  assert(html.includes('普通网络'));assert(!html.includes('域名规则 1'));assert(!html.includes('默认出口 / 下载'));
  assert(html.includes('分流入口未启动'));assert(html.includes('软件接入'));assert(html.includes('待验证'));
  assert(!html.includes('尚未接入真实应用'));assert(!html.includes('预览后才运行'));
});
check('Inspector explains actual matches, ordering, fallback and the three separate stages',()=>{
  context.renderInspectorBase();const html=node('#inspector-content').innerHTML;
  for(const value of ['steamcontent.com 及其子域名','普通网络','先检查 1','没有匹配上面的网站时','① 方案','② 分流入口','③ 软件实际使用','尚未验证'])assert(html.includes(value));
  assert(html.includes('子域名，不包括 example.com 本身'));assert(!html.includes('运行默认出口 ID'));
});
check('A listening relay can load current rules without claiming the target application is connected',()=>{
  state.runtime={running:true,channels:[{id:'steam',proxy_url:'http://127.0.0.1:12345'}]};state.runtimeSignature=JSON.stringify(plan);
  const status=context.relayChannelStatus(plan.channels[0]);assert.equal(status.loaded,true);
  context.renderGraph();context.renderInspectorBase();
  assert(node('#node-layer').innerHTML.includes('分流入口运行中'));
  assert(node('#inspector-content').innerHTML.includes('http://127.0.0.1:12345'));
  assert(node('#inspector-content').innerHTML.includes('去应用连接设置软件'));
  assert(node('#inspector-content').innerHTML.includes('尚未验证'));
});
check('Changed rules and disconnected service never appear as currently loaded',()=>{
  state.runtimeSignature='previous-plan';let status=context.relayChannelStatus(plan.channels[0]);assert.equal(status.live,true);assert.equal(status.loaded,false);
  context.renderGraph();assert(node('#node-layer').innerHTML.includes('改动尚未应用'));assert(node('#node-layer').innerHTML.includes('仍用上次规则'));
  state.connected=false;status=context.relayChannelStatus(plan.channels[0]);assert.equal(status.live,false);assert.equal(status.label,'运行状态未同步');
  context.renderInspectorBase();assert(node('#inspector-content').innerHTML.includes('本机草稿'));state.connected=true;
});
check('Rule links display actual hostnames; solid lines require a current, connected relay',()=>{
  ports=[{dataset:{channelOutput:'steam',ruleOutput:'download'},point:{x:1,y:2}},{dataset:{channelOutput:'steam'},point:{x:1,y:4}},{dataset:{targetInput:'direct'},point:{x:5,y:2}},{dataset:{targetInput:'proxy'},point:{x:5,y:4}}];
  context.renderEdges();let html=node('#edge-layer').innerHTML;assert(html.includes('steamcontent.com'));assert(html.includes('其他网站'));assert(html.includes('edge-arrow-draft'));assert(!html.includes('graph-edge running'));
  state.runtimeSignature=JSON.stringify(plan);context.renderEdges();html=node('#edge-layer').innerHTML;assert(html.includes('graph-edge running'));assert(!html.includes('edge-arrow-draft'));
});
check('Website selection opens the matching editor without editing or enabling a route',()=>{
  let focused=false,scrolled=false;cards=[{dataset:{ruleCard:'download'},scrollIntoView(){scrolled=true;},querySelector(){return{focus(){focused=true;}};}}];
  context.selectRelayRule('steam','download');assert(focused&&scrolled);assert.equal(state.selected.id,'steam');
});
check('Untrusted website and target names remain escaped in HTML',()=>{
  const hostile={channels:[{id:'test',name:'Test',default_target:'proxy',rules:[{id:'x',domains:['<img src=x onerror=alert(1)>'],target:'proxy'}]}]};
  const html=context.relaySourceRows(hostile);assert(!html.includes('<img'));assert(html.includes('&lt;img'));
});
const report={method:'Actual descriptions and graph/inspector functions with synthetic DOM; no browser visual acceptance',count:passed.length,passed,source_sha256:{'web/app.js':crypto.createHash('sha256').update(source).digest('hex'),'web/routing-view.js':crypto.createHash('sha256').update(fs.readFileSync(path.join(root,'web/routing-view.js'))).digest('hex')}};
fs.writeFileSync(path.join(root,'artifacts/routing-view-verification.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({passed:true,count:passed.length}));
