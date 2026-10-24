'use strict';
// Exercise the actual event functions against a tiny DOM and synthetic APIs.
// Browser rendering and the native picker are deliberately outside this test.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const product = fs.readFileSync(path.join(root, 'web/app.js'), 'utf8');
const html = fs.readFileSync(path.join(root, 'web/index.html'), 'utf8');
function sourceBetween(start, end) {
  const from = product.indexOf(start), to = product.indexOf(end, from + start.length);
  assert(from >= 0 && to > from, `Missing product function: ${start}`);
  return product.slice(from, to);
}
const eventSource = sourceBetween('  function catalogMutationBusy(', '  function addApp(');
const refreshSource = sourceBetween('  async function refreshCatalog(', '  function renderCatalog(');
const nodes = new Map();
function node(selector) {
  if (!nodes.has(selector)) nodes.set(selector, {
    value: '', checked: false, hidden: true, disabled: false, textContent: '', innerHTML: '', scrollTop: 0,
    attributes: {}, setAttribute(name, value) { this.attributes[name] = value; },
    focus() { this.focused = true; }, showModal() { this.open = true; }, close() { this.open = false; },
  });
  return nodes.get(selector);
}
const controls = ['#catalog-add-executable', '#catalog-add-name', '#catalog-add-submit', '#catalog-pick-executable', '#catalog-add-close'];
let routePlan, calls, notices, renderCount, resolver;
const state = {};
const context = {
  state, location: {protocol: 'http:'},
  $: node,
  $$: (selector) => selector === 'button,input' ? controls.map(node) : selector === '[data-catalog-remove]' ? [node('#remove')] : [],
  h: (value) => String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;'),
  catalogApps: () => state.catalog?.apps || [],
  catalogApp: () => state.catalog?.apps.find(app => app.id === state.catalogSelected),
  renderCatalog: () => { renderCount++; }, renderWorkspaceStatus: () => {},
  activity: (message) => notices.push(message), toast: (message) => notices.push(message),
  api: async (endpoint, method = 'GET', body) => {
    calls.push({endpoint, method, body: body === undefined ? undefined : JSON.parse(JSON.stringify(body))});
    return resolver(endpoint, method, body);
  },
};
vm.createContext(context);
vm.runInContext(eventSource + '\n' + refreshSource, context);
function reset() {
  nodes.clear(); calls = []; notices = []; renderCount = 0;
  routePlan = {name: 'kept route draft', targets: [{id: 'direct', type: 'direct'}], channels: []};
  Object.assign(state, {connected: true, busy: false, catalogMutationBusy: false, catalogLoading: false,
    catalogRevision: 0, catalogSignature: null, snapshot: {captured_at: 'fixture-time'},
    catalog: {apps: [{id: 'curl', name: 'curl'}]}, catalogSelected: 'curl', plan: routePlan, profileResult: null});
  node('#catalog-add-executable').value = '"C:\\Fixture\\Picked App.exe"';
  node('#catalog-add-name').value = ' My app ';
  node('#catalog-search').value = 'hidden by filter'; node('#catalog-running-only').checked = true;
  node('#catalog-add-form').reset = () => { node('#catalog-add-executable').value = ''; node('#catalog-add-name').value = ''; };
  resolver = () => { throw new Error('Unexpected API call'); };
}
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return {promise, resolve, reject}; }
const passed = [];
async function check(name, work) { reset(); await work(); assert.equal(state.plan, routePlan); passed.push(name); }

(async () => {
  await check('Picker cancel retains path/name/catalog and duplicate clicks are ignored while pending', async () => {
    const pending = deferred(); resolver = () => pending.promise;
    const originalPath = node('#catalog-add-executable').value, originalName = node('#catalog-add-name').value;
    const first = context.catalogPickExecutable(); await context.catalogPickExecutable();
    assert.equal(calls.length, 1); assert.equal(state.catalogMutationBusy, true); assert.equal(state.busy, false);
    assert(controls.every(selector => node(selector).disabled)); assert.equal(node('#discover-button').disabled, false);
    pending.resolve({cancelled: true}); await first;
    assert.equal(node('#catalog-add-executable').value, originalPath); assert.equal(node('#catalog-add-name').value, originalName);
    assert.equal(state.catalog.apps.length, 1); assert.equal(state.catalogMutationBusy, false); assert(controls.every(selector => !node(selector).disabled));
  });
  await check('Picker error is readable inline, retains input and offers pasted-path fallback', async () => {
    resolver = () => { throw new Error('程序选择窗口不可用'); };
    await context.catalogPickExecutable();
    assert.equal(node('#catalog-add-error').hidden, false); assert.match(node('#catalog-add-error').textContent, /程序选择窗口不可用.*粘贴/);
    assert.equal(node('#catalog-add-executable').value, '"C:\\Fixture\\Picked App.exe"'); assert.equal(node('#catalog-add-name').value, ' My app ');
    assert.equal(state.catalogMutationBusy, false); assert.equal(state.catalogRevision, 0);
  });
  await check('Successful picker fills only the path and does not register or run the application', async () => {
    resolver = () => ({cancelled: false, executable: 'C:\\Fixture\\Selected.exe'}); await context.catalogPickExecutable();
    assert.equal(node('#catalog-add-executable').value, 'C:\\Fixture\\Selected.exe'); assert.equal(node('#catalog-add-name').value, ' My app ');
    assert.equal(calls.length, 1); assert.equal(calls[0].endpoint, '/api/catalog/pick-executable'); assert.equal(state.catalog.apps.length, 1);
  });
  await check('Add validation error retains modal input and filters, then releases pending state', async () => {
    resolver = () => { throw new Error('程序不存在'); }; let prevented = false;
    await context.catalogAddSubmit({preventDefault() { prevented = true; }});
    assert(prevented); assert.equal(node('#catalog-add-executable').value, '"C:\\Fixture\\Picked App.exe"'); assert.equal(node('#catalog-add-name').value, ' My app ');
    assert.equal(node('#catalog-search').value, 'hidden by filter'); assert.equal(node('#catalog-running-only').checked, true);
    assert.equal(node('#catalog-add-error').textContent, '程序不存在'); assert.equal(node('#catalog-add-error').hidden, false); assert.equal(state.catalogMutationBusy, false);
    assert.equal(calls[0].body.executable, 'C:\\Fixture\\Picked App.exe'); assert.equal(calls[0].body.name, 'My app');
  });
  await check('Malformed success preserves form/filter rather than selecting an unrelated application', async () => {
    resolver = () => ({catalog: {apps: [{id: 'curl'}]}, app_id: 'not-in-result'});
    await context.catalogAddSubmit({preventDefault() {}});
    assert.equal(node('#catalog-search').value, 'hidden by filter'); assert.equal(node('#catalog-running-only').checked, true);
    assert.equal(state.catalogSelected, 'curl'); assert.equal(node('#catalog-add-error').hidden, false);
  });
  await check('Add selects returned app, clears filters, closes/reset form and never changes the route draft', async () => {
    const pending = deferred(); resolver = () => pending.promise;
    const first = context.catalogAddSubmit({preventDefault() {}}); await context.catalogAddSubmit({preventDefault() {}}); assert.equal(calls.length, 1);
    pending.resolve({catalog: {apps: [{id: 'curl'}, {id: 'manual-new', manual: true, manual_id: 'registry-new'}]}, app_id: 'manual-new', duplicate: false});
    await first;
    assert.equal(state.catalogSelected, 'manual-new'); assert.equal(state.catalogRevision, 1); assert.equal(node('#catalog-search').value, '');
    assert.equal(node('#catalog-running-only').checked, false); assert.equal(node('#catalog-add-dialog').open, false); assert.equal(node('#catalog-add-executable').value, '');
  });
  await check('Duplicate registration selects the existing entry without appending a duplicate', async () => {
    resolver = () => ({catalog: {apps: [{id: 'curl', manual: true, manual_id: 'registry-curl'}]}, app_id: 'curl', duplicate: true});
    await context.catalogAddSubmit({preventDefault() {}});
    assert.equal(state.catalogSelected, 'curl'); assert.equal(state.catalog.apps.length, 1); assert(notices.some(message => message.includes('已有')));
  });
  await check('Remove sends stable manual_id and preserves merged automatic records', async () => {
    state.catalog.apps[0].manual = true; state.catalog.apps[0].manual_id = 'registry-curl';
    resolver = () => ({catalog: {apps: [{id: 'curl', manual: false}]}}); await context.catalogRemoveRegistration();
    assert.equal(calls[0].endpoint, '/api/catalog/apps/remove'); assert.equal(calls[0].body.manual_id, 'registry-curl'); assert.equal(calls[0].body.app_id, undefined);
    assert.equal(state.catalogSelected, 'curl'); assert.equal(state.catalog.apps.length, 1); assert.equal(state.catalog.apps[0].manual, false);
    assert(notices.some(message => message.includes('不卸载软件或删除文件')));
  });
  await check('Late pre-registration catalog response cannot overwrite the new registration', async () => {
    const pending = deferred(); resolver = () => pending.promise;
    const refresh = context.refreshCatalog(true);
    context.catalogUseMutation({catalog: {apps: [{id: 'manual-new'}]}}, 'manual-new');
    pending.resolve({apps: [{id: 'stale-old'}]}); await refresh;
    assert.equal(state.catalogSelected, 'manual-new'); assert.equal(state.catalog.apps[0].id, 'manual-new'); assert.equal(state.catalogLoading, false);
  });
  await check('Late pre-registration catalog error cannot replace the successful new-list view', async () => {
    const pending = deferred(); resolver = () => pending.promise;
    const refresh = context.refreshCatalog(true); node('#catalog-app-list').innerHTML = 'new list';
    context.catalogUseMutation({catalog: {apps: [{id: 'manual-new'}]}}, 'manual-new');
    pending.reject(new Error('old read failed')); await refresh;
    assert.equal(state.catalogSelected, 'manual-new'); assert.equal(node('#catalog-app-list').innerHTML, 'new list');
  });
  await check('Older mutation snapshot does not suppress refreshing a newer observation', async () => {
    state.snapshot.captured_at = 'newer-observation';
    context.catalogUseMutation({catalog: {apps: [{id: 'manual-new'}], snapshot_captured_at: 'older-observation'}}, 'manual-new');
    resolver = () => ({apps: [{id: 'manual-new'}, {id: 'newly-observed'}], snapshot_captured_at: 'newer-observation'});
    await context.refreshCatalog(false);
    assert.equal(calls.length, 1); assert.equal(calls[0].endpoint, '/api/catalog');
    assert.equal(state.catalogSelected, 'manual-new'); assert.equal(state.catalog.apps.length, 2);
  });
  for (const id of ['catalog-add-button', 'catalog-add-dialog', 'catalog-add-form', 'catalog-add-executable', 'catalog-pick-executable', 'catalog-add-name', 'catalog-add-error', 'catalog-add-submit']) assert(html.includes(`id="${id}"`), id);
  assert(product.includes("api('/api/catalog/apps/remove','POST',{manual_id:app.manual_id})"));
  const report = {checked_at: new Date().toISOString(), method: 'Node VM actual product event functions with synthetic DOM/API; not a browser rendering or native-picker test',
    browser_available_in_child: false, passed, count: passed.length, no_real_process_or_network_setting_changed: true,
    source_sha256: Object.fromEntries(['web/app.js', 'web/index.html', 'web/styles.css'].map(file => [file, crypto.createHash('sha256').update(fs.readFileSync(path.join(root, file))).digest('hex')]))};
  fs.mkdirSync(path.join(root, 'artifacts'), {recursive: true});
  fs.writeFileSync(path.join(root, 'artifacts/manual-app-ui-verification.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify({passed: true, count: passed.length, report: 'artifacts/manual-app-ui-verification.json'}));
})().catch(error => { console.error(error); process.exitCode = 1; });
