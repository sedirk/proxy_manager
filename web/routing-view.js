/* Readable descriptions only: this module never changes or executes a route. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.FlowDeskRouting = factory();
})(globalThis, function () {
  'use strict';
  function domains(rule) {
    const patterns = [...new Set((rule.domains || []).map(String))];
    if (patterns.includes('*')) return ['所有网站'];
    const combined = new Set(patterns.filter(value => !value.startsWith('*.') && patterns.includes('*.' + value)));
    return patterns.filter(value => !value.startsWith('*.') || !combined.has(value.slice(2))).map(value =>
      combined.has(value) ? value + ' 及其子域名' : value.startsWith('*.') ? value.slice(2) + ' 的子域名（不含它本身）' : value);
  }
  function ruleTitle(rule) {
    const items = domains(rule);
    return items.length ? items[0] + (items.length > 1 ? ` 等 ${items.length} 组网站` : '') : '尚未填写网站';
  }
  function targetLabel(target) {
    if (!target) return '尚未选择';
    if (target.type === 'direct') return target.interface_index ? '普通网络 · 指定网卡' : '普通网络';
    if (target.type === 'block') return '不允许访问';
    return '代理 · ' + (target.name || (target.host ? `${target.host}:${target.port || '?'}` : '尚未填写地址'));
  }
  function explanation(rule, target) {
    const items = domains(rule);
    if (!items.length) return '先填写网站，这条例外才能参与判断。';
    return `访问 ${items.join('、')} 时，使用${targetLabel(target)}。`;
  }
  function edgeLabel(rule) {
    if (!rule) return '其他网站';
    if (!rule.domains?.length) return '尚未填写网站';
    if (rule.domains.includes('*')) return '所有网站';
    const name = String(rule.domains[0]).replace(/^\*\./, '');
    return name.slice(0, 24) + (name.length > 24 || domains(rule).length > 1 ? '…' : '');
  }
  function status(channel, runtime, matches, connected = true) {
    const entry = connected && runtime.running && (runtime.channels || []).find(item => item.id === channel.id);
    if (!connected) return {label:'运行状态未同步', detail:'工作台未连接，暂时无法确认分流入口的状态。', live:false, loaded:false, entry:null};
    if (!entry) return {label:'分流入口未启动', detail:'当前只是分流方案，需先预览并启动入口。', live:false, loaded:false, entry:null};
    if (!matches) return {label:'改动尚未应用', detail:'入口仍按上次的规则运行。停止入口后，预览并重新启动才能应用当前图。', live:true, loaded:false, entry};
    return {label:'分流入口运行中', detail:'当前规则已由分流入口加载；目标软件是否实际使用这个入口仍待验证。', live:true, loaded:true, entry};
  }
  return {domains, ruleTitle, targetLabel, explanation, edgeLabel, status};
});
