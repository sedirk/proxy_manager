'use strict';
// Product event functions with a synthetic DOM/API. This does not automate a browser.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict'),path=require('node:path'),crypto=require('node:crypto');
const root=path.resolve(__dirname,'..'),html=fs.readFileSync(path.join(root,'web/index.html'),'utf8'),product=fs.readFileSync(path.join(root,'web/guide.js'),'utf8');
const nodes=new Map(),calls=[],downloads=[],events=[],timers=[],passed=[];
class Node {
  constructor(id){this.id=id;this.value='';this.hidden=false;this.disabled=false;this.textContent='';this.attributes={};this.handlers={};this.classes=new Set();this.classList={toggle:(name,on)=>on?this.classes.add(name):this.classes.delete(name)};}
  addEventListener(event,handler){this.handlers[event]=handler;}
  setAttribute(key,value){this.attributes[key]=value;}removeAttribute(key){delete this.attributes[key];}focus(){this.focused=true;}
  set innerHTML(value){this.markup=value;for(const match of value.matchAll(/id="([^"]+)"/g)){if(!nodes.has('#'+match[1]))nodes.set('#'+match[1],new Node(match[1]));}}
  get innerHTML(){return this.markup||'';}
  click(){downloads.push({filename:this.download,url:this.href});}
}
for(const match of html.matchAll(/id="([^"]+)"/g)){assert(!nodes.has('#'+match[1]),'Duplicate HTML id '+match[1]);nodes.set('#'+match[1],new Node(match[1]));}
const node=id=>{assert(nodes.has(id),'Missing HTML control '+id);return nodes.get(id);};
const app={id:'setup',name:'Hermes <script>fake</script>',protected:false};
const inventory={snapshot_captured_at:'2026-10-24T12:00:00Z',catalog:{apps:[app,{id:'codex',name:'Codex',protected:true}]},tools:[
  {id:'v2rayn',name:'v2rayN',state_label:'运行中',kind:'应用代理',action_label:'1 个可检测的代理入口',process_count:2,listener_count:1,proxy_options:[{proxy_url:'http://127.0.0.1:10808'}]},
  ...['UU','aTrust','ZeroTier'].map(name=>({name,state_label:'运行中',action_label:'通过网卡或专用规则工作',process_count:1,listener_count:1,proxy_options:[]}))]};
const report={app_id:'setup',app_name:app.name,check_id:'verified-id',recommendation:{title:'建议指定代理',reason:'TLS 未通过 / HTTP 200',action:'先关闭该软件，再按方案启动',profile:{proxy_url:'http://127.0.0.1:10808'}},results:[{name:'普通连接',label:'TLS 未通过',ok:false},{name:'v2rayN',label:'HTTP 200',ok:true}],scope:'仅检测请求',network_notice:'遵循系统路由'};
const profile={app_name:app.name,proxy_url:'http://127.0.0.1:10808',filename:'FlowDesk-setup.ps1',content:'# review only\n<script>literal</script>',steps:['关闭目标软件','点击按方案启动','重试原操作']};
let checkPending=null,launchFailure=false;
const response=(value,status=200)=>({ok:status<400,status,json:async()=>JSON.parse(JSON.stringify(value))});
const context={console,Blob,CustomEvent:class{constructor(type,options){this.type=type;this.detail=options?.detail;}},
  URL:{createObjectURL:()=>{events.push('blob-created');return 'blob:fixture';},revokeObjectURL:()=>{}},
  document:{querySelector:node,querySelectorAll:()=>[...nodes.values()],createElement:()=>new Node('download'),dispatchEvent:event=>events.push(event.type),addEventListener:(event,handler)=>{context.document.handlers[event]=handler;},handlers:{}},
  setInterval:callback=>{timers.push(callback);return 1;},setTimeout:callback=>callback(),
  fetch:async(endpoint,options={})=>{
    const body=options.body?JSON.parse(options.body):undefined;calls.push({endpoint,body});
    if(endpoint==='/api/session')return response({token:'fixture-token'});
    if(endpoint==='/api/troubleshoot')return response(inventory);
    if(endpoint==='/api/troubleshoot/check'){if(checkPending)return checkPending;return response(report);}
    if(endpoint==='/api/troubleshoot/profile')return response(profile);
    if(endpoint==='/api/troubleshoot/launch')return launchFailure?response({error:'目标软件还在运行'},400):response({pid:123,notice:'已创建新进程；请实际重试'});
    if(endpoint==='/api/troubleshoot/feedback')return response({outcome:body.outcome,message:body.outcome==='resolved'?'用户确认成功':'粘贴新的错误地址再检测'});
    if(endpoint==='/api/discover')return response({});
    throw new Error('Unexpected API '+endpoint);
  }};
vm.createContext(context);vm.runInContext(product,context);
const tick=()=>new Promise(resolve=>setImmediate(resolve));
const click=selector=>node('#guide-result').handlers.click({target:{closest:match=>match===selector?{}:null}});
async function check(name,callback){await callback();passed.push(name);}
(async()=>{
  await tick();
  await check('Default DOM has complete guide controls; initial load is observational and groups four network tools',async()=>{
    for(const match of product.matchAll(/\$\('(#[a-z0-9-]+)'\)/g)){if(!['#guide-prepare','#guide-action','#guide-feedback-message','#guide-launch-status'].includes(match[1]))node(match[1]);}
    for(const name of ['v2rayN','UU','aTrust','ZeroTier'])assert(node('#guide-tools').innerHTML.includes(name));
    assert.equal(calls.filter(call=>call.body).length,0);assert(node('#guide-app').innerHTML.includes('&lt;script&gt;'));
  });
  await check('Pasted error extracts URL and trims error punctuation; changing input invalidates old actions',async()=>{
    node('#guide-error-text').value='GET https://example.com/install.ps1): failed';node('#guide-error-text').handlers.input();
    assert.equal(node('#guide-url').value,'https://example.com/install.ps1');
    const before=calls.length;await click('#guide-launch');assert.equal(calls.length,before);
  });
  await check('One problem check disables duplicate requests and preserves the selected software',async()=>{
    node('#guide-app').value='setup';let resolve;checkPending=new Promise(done=>resolve=done);
    const pending=node('#guide-form').handlers.submit({preventDefault(){}});await tick();
    assert(node('#guide-check').disabled);assert.equal(node('#guide-step-2').attributes['aria-current'],'step');
    const before=calls.length;await node('#guide-form').handlers.submit({preventDefault(){}});assert.equal(calls.length,before);
    resolve(response(report));await pending;checkPending=null;
    assert.equal(node('#guide-app').value,'setup');assert.equal(node('#guide-step-3').attributes['aria-current'],'step');
    assert(node('#guide-result').innerHTML.includes('HTTP 200'));assert(!node('#guide-result').innerHTML.includes('<script>'));
  });
  await check('Prepare uses only server-issued check ID and shows one-click launch, not a separate technical settings task',async()=>{
    await click('#guide-prepare');assert.deepEqual(calls.at(-1).body,{check_id:'verified-id'});
    assert(node('#guide-action').innerHTML.includes('按方案启动'));assert(node('#guide-action').innerHTML.includes('&lt;script&gt;literal'));
  });
  await check('Download creates a local file without launching or changing network settings',async()=>{
    const before=calls.length;await click('#guide-download');assert.equal(calls.length,before);assert.equal(downloads.at(-1).filename,profile.filename);
  });
  await check('Launch requires an explicit click; existing-instance failure stays readable and retryable',async()=>{
    launchFailure=true;await click('#guide-launch');assert.equal(node('#guide-error').textContent,'目标软件还在运行');assert(!node('#guide-launch').disabled);
    launchFailure=false;await click('#guide-launch');assert.equal(calls.at(-1).endpoint,'/api/troubleshoot/launch');assert.deepEqual(calls.at(-1).body,{check_id:'verified-id'});
    assert(node('#guide-launch-status').textContent.includes('PID 123'));
  });
  await check('Feedback is sent only when user confirms an actual outcome',async()=>{
    assert(!calls.some(call=>call.endpoint.endsWith('/feedback')));
    await node('#guide-result').handlers.click({target:{closest:selector=>selector==='[data-guide-outcome]'?{dataset:{guideOutcome:'failed'}}:null}});
    assert.equal(calls.at(-1).body.outcome,'failed');assert(node('#guide-error-text').focused);
  });
  await check('Application changes clear stale recommendations and prevent using the old check',async()=>{
    node('#guide-app').value='codex';node('#guide-app').handlers.change();const before=calls.length;await click('#guide-launch');assert.equal(calls.length,before);
    assert(!node('#guide-result').innerHTML.includes('guide-prepare'));
  });
  await check('Missing application opens existing add dialog through the shared event',async()=>{
    node('#guide-add-app').handlers.click();assert(events.includes('flowdesk:add-app'));
  });
  const output={checked_at:new Date().toISOString(),method:'Actual guide.js event code with synthetic DOM/API; browser automation unavailable',passed,count:passed.length,source_sha256:{}};
  for(const name of ['guide.js','guide.css','app.js','index.html'])output.source_sha256['web/'+name]=crypto.createHash('sha256').update(fs.readFileSync(path.join(root,'web',name))).digest('hex');
  fs.mkdirSync(path.join(root,'artifacts'),{recursive:true});fs.writeFileSync(path.join(root,'artifacts/guide-ui-verification.json'),JSON.stringify(output,null,2)+'\n');
  console.log(JSON.stringify({passed:true,count:passed.length}));
})().catch(error=>{console.error(error);process.exitCode=1;});
