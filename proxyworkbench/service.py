"""Application state; startup and discovery are read-only toward the host."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import threading
from urllib.parse import urlsplit

from . import __version__
from . import discovery, probes
from .changes import compare
from .policy import Policy, validate_plan
from .privacy import redact
from .relay import RelayManager
from .store import Store, default_plan, now
from .system_proxy import SystemLease, fingerprint


def design_plan(value):
    if not isinstance(value, dict) or value.get('version', 1) != 1:
        raise ValueError('仅支持 version: 1 的方案，请先转换新版方案格式')
    result = validate_plan(value)
    result['version'] = 1
    name = value.get('name', result['id'])
    if not isinstance(name, str) or not 1 <= len(name) <= 100:
        raise ValueError('方案名称需要 1–100 个字符')
    result['name'] = name
    layout = value.get('layout', {})
    if not isinstance(layout, dict) or len(json.dumps(layout)) > 65536:
        raise ValueError('画布布局过大或格式无效')
    result['layout'] = copy.deepcopy(layout)
    notes = value.get('notes', [])
    if not isinstance(notes, list) or len(notes) > 32 or any(not isinstance(n, str) or len(n) > 1000 for n in notes):
        raise ValueError('方案说明格式无效')
    result['notes'] = notes
    by_id = {c['id']: c for c in value['channels']}
    for channel in result['channels']:
        app_id = by_id[channel['id']].get('app_id')
        if app_id is not None:
            if not isinstance(app_id, str) or len(app_id) > 64:
                raise ValueError('应用标签格式无效')
            channel['app_id'] = app_id
    return result


def _endpoint(text):
    parsed = urlsplit(text if '://' in text else 'http://' + text)
    host = parsed.hostname
    return host, parsed.port or 80


def preserves_default(current, target):
    """Conservative comparison, not a claim about existing app connections."""
    if not current['flags'] & 2:
        return target['type'] == 'direct' and not target.get('interface_index')
    if target['type'] != 'http':
        return False
    try:
        original = current.get('server', '')
        if '@' in original:
            return False
        entries = dict(part.split('=', 1) for part in original.split(';') if '=' in part)
        servers = [entries.get('http'), entries.get('https')] if entries else [original]
        expected = _endpoint(f"http://[{target['host']}]:{target['port']}" if ':' in target['host'] else f"http://{target['host']}:{target['port']}")
        return all(server and _endpoint(server) == expected for server in servers)
    except (ValueError, KeyError):
        return False


class Service:
    def __init__(self, root, control_port=0, *, discover=True, lease=None):
        self.root = Path(root)
        self.store = Store(self.root / '.local')
        self.lock = threading.RLock()
        self.scan_lock = threading.Lock()
        self.probe_slots = threading.BoundedSemaphore(2)
        self.control_port = control_port
        self.relay = RelayManager(deny_ports=(control_port,) if control_port else ())
        self.lease = lease or SystemLease(self.root / '.local' / 'recovery')
        self.snapshot = self.store.read('snapshot.json', {})
        saved = self.store.read('plan.json')
        self.plan = design_plan(saved or default_plan(self.snapshot))
        self.seed_pending = saved is None
        self.snapshot_stale = bool(self.snapshot)
        self.discovering = False
        self.discovery_error = None
        self.running_plan = None
        self.preview_runtime = {}
        self.closed = False
        self.closing = False
        self.audit_error = None
        if discover:
            threading.Thread(target=self.discover, daemon=True, name='host-discovery').start()

    def state(self):
        with self.lock:
            return {'version': __version__, 'snapshot': self.snapshot, 'plan': self.plan,
                    'runtime': self.relay.status(), 'running_plan': self.running_plan,
                    'history': self.store.read('history.json', [])[-80:], 'system': self.lease.status(),
                    'discovering': self.discovering, 'snapshot_stale': self.snapshot_stale,
                    'discovery_error': self.discovery_error,
                    'audit_error': self.audit_error,
                    'protection': {'codex': 'preserve_existing', 'proxy_core': 'no_restart',
                                   'environment': 'unchanged', 'tun_and_routes': 'unchanged'}}

    def _ensure_open(self):
        if self.closed or self.closing:
            raise RuntimeError('本机服务正在关闭或已经关闭，请重新启动工作台')

    def audit(self, event, detail=None):
        try:
            self.store.audit(event, detail)
            self.audit_error = None
        except OSError as exc:
            # Network state must not be misreported solely because audit storage failed.
            self.audit_error = '审计写入失败：' + type(exc).__name__

    def discover(self):
        if not self.scan_lock.acquire(blocking=False):
            return {'discovering': True}
        try:
            with self.lock:
                self._ensure_open()
                self.discovering = True
            found = discovery.snapshot()
            with self.lock:
                self._ensure_open()
                found['changes_since_previous'] = compare(self.snapshot, found)
                for change in found['changes_since_previous']['items']:
                    found.setdefault('findings', []).append({'id': 'changed_' + change['section'], 'severity': 'notice',
                        'title': change['name'] + '自上次检测后变化', 'detail': change['notice'],
                        'evidence_status': 'observed', 'affected_apps': []})
                self.snapshot = found
                self.snapshot_stale = False
                self.discovery_error = None
                self.store.write('snapshot.json', found)
                if self.seed_pending:
                    self.plan = design_plan(default_plan(found))
                    self.seed_pending = False
                    self.store.write('plan.json', self.plan)
                self.audit('只读检测完成', {'captured_at': found['captured_at'],
                                               'findings': len(found.get('findings', [])),
                                               'changes': found['changes_since_previous']['items']})
            return {'snapshot': found, 'plan': self.plan, 'discovering': False}
        except Exception as exc:
            with self.lock:
                self.discovery_error = type(exc).__name__
                self.snapshot_stale = bool(self.snapshot)
            return {'discovering': False, 'error': '只读检测未完成：' + type(exc).__name__}
        finally:
            with self.lock:
                self.discovering = False
            self.scan_lock.release()

    def save_plan(self, value):
        plan = design_plan(value)
        with self.lock:
            self._ensure_open()
            self.store.write('plan.json', plan)
            self.plan = plan
            self.seed_pending = False
            self.audit('保存设计方案', {'id': plan['id'], 'name': plan['name'],
                                             'running_unchanged': self.relay.status()['running']})
        return {'plan': plan}

    def preview(self, value):
        plan = design_plan(value)
        policy = Policy(plan)
        issues = []
        routes = []
        for channel in plan['channels']:
            for host in ('cdn.steamcontent.com', 'store.steampowered.com', 'chatgpt.com'):
                routes.append(policy.route(channel['id'], host, 443))
        if any(t['type'] == 'direct' for t in plan['targets']):
            issues.append({'severity': 'info', 'message': '直连仍遵循系统路由；有 TUN 时可能继续经过 TUN。指定物理网卡仅约束该出口的 TCP socket，DNS 单独处理。'})
        if self.relay.status()['running']:
            issues.append({'severity': 'warning', 'message': '已有入口运行。保存仅更新设计；需要停止后重新启动才能应用新接线。'})
        if any(t['type'] == 'block' and any(c['default_target'] == t['id'] for c in plan['channels']) for t in plan['targets']):
            issues.append({'severity': 'warning', 'message': '部分通道默认阻断。请连接有效出口后再让应用使用该入口。'})
        return {'valid': True, 'plan': plan, 'issues': issues, 'routes': routes,
                'impact': {'scope': '仅启动 127.0.0.1 上的本地 HTTP / SOCKS5 TCP 入口；应用须自行接入。',
                           'system_proxy': '不自动修改', 'environment': '不修改', 'tun': '不修改',
                           'codex': '保留现有进程和连接', 'active_apps_verified': False},
                'runtime': self.relay.status()}

    def start(self, value):
        plan = design_plan(value)
        with self.lock:
            self._ensure_open()
            if self.relay.status()['running']:
                raise RuntimeError('已有入口正在运行。请先停止，再应用新的方案。')
            if self.lease.status()['phase'] in ('armed', 'trial', 'confirmed', 'restore_failed', 'conflict'):
                raise RuntimeError('存在待恢复的系统代理接入记录，请先恢复或处理冲突。')
            self.relay.start(plan)
            self.running_plan = copy.deepcopy(plan)
            try:
                self.save_plan(plan)
            except Exception as exc:
                self.relay.stop()
                self.running_plan = None
                raise RuntimeError('方案保存失败，启动已回滚，本地入口已关闭：' + type(exc).__name__) from exc
            self.audit('启动本地入口', {'channels': self.relay.status()['channels'], 'system_proxy_changed': False})
            return {'runtime': self.relay.status(), 'system': self.lease.status()}

    def stop(self):
        with self.lock:
            system = self.lease.status()
            if system['phase'] not in ('detached', 'restored'):
                system = self.lease.restore()
                if system['phase'] != 'restored':
                    raise RuntimeError('系统代理恢复存在冲突，入口保持运行，避免中断。请先检查系统接入状态。')
            self.relay.stop()
            self.running_plan = None
            self.preview_runtime.clear()
            self.audit('停止本地入口', {'system': system['phase']})
            return {'runtime': self.relay.status(), 'system': system}

    def system_preview(self, channel_id):
        with self.lock:
            self._ensure_open()
            runtime = self.relay.status()
            channel = next((c for c in runtime['channels'] if c['id'] == channel_id), None)
            if not runtime['running'] or not channel:
                raise ValueError('请先启动所选本地入口')
            selected = next(c for c in self.running_plan['channels'] if c['id'] == channel_id)
            target = next(t for t in self.running_plan['targets'] if t['id'] == selected['default_target'])
            before = self.lease._adapter().read()
            result = self.lease.preview(channel_id, channel['actual_port'], safe_default=preserves_default(before, target))
            proposal = self.lease.previews.get(result['preview_id'])
            if not proposal or fingerprint(proposal['current']) != fingerprint(before):
                self.lease.previews.pop(result['preview_id'], None)
                raise RuntimeError('系统代理在生成预览时发生变化，请重新预览')
            result['rules'] = selected['rules']
            result['dns_overrides'] = self.running_plan.get('dns_overrides', {})
            result['notice'] += ' 默认出口需保留原系统代理；例外规则和 DNS 映射会影响所有使用此系统入口的应用，无法按进程区分，包括使用该系统入口的新工作连接。'
            self.preview_runtime[result['preview_id']] = {'channel_id': channel_id, 'config_id': channel['config_id']}
            return result

    def system_apply(self, preview_id):
        with self.lock:
            self._ensure_open()
            bound = self.preview_runtime.pop(preview_id, None)
            channels = self.relay.status()['channels']
            if not bound or not any(c['id'] == bound['channel_id'] and c['config_id'] == bound['config_id'] for c in channels):
                raise RuntimeError('入口状态已改变，请重新预览系统接入')
            result = self.lease.apply(preview_id)
            self.audit('试用系统代理接入', result)
            return {'system': result}

    def system_confirm(self, identifier):
        with self.lock:
            self._ensure_open()
            if not identifier or identifier != self.lease.status().get('id'):
                raise RuntimeError('系统接入会话已改变，请刷新后再确认')
            result = self.lease.confirm(identifier=identifier)
            self.audit('确认系统接入', result)
            return {'system': result}

    def system_restore(self, identifier):
        with self.lock:
            if self.lease.status().get('id') != identifier:
                raise RuntimeError('系统接入会话已改变，请刷新后再恢复')
            result = self.lease.restore(identifier=identifier)
            self.audit('恢复系统接入', result)
            return {'system': result}

    def probe(self, value):
        with self.lock:
            self._ensure_open()
        if not self.probe_slots.acquire(blocking=False):
            raise RuntimeError('已有两项检测进行中，请稍后再试')
        try:
            channel_id = value.get('channel_id')
            target_id = value.get('target_id')
            if channel_id:
                runtime = self.relay.status()
                channel = next((c for c in runtime['channels'] if c['id'] == channel_id), None)
                if not runtime['running'] or not channel:
                    raise ValueError('请先启动所选通道，才能验证经过该通道的连接')
                target = {'type': 'http', 'host': '127.0.0.1', 'port': channel['actual_port']}
                scope = '实际经过所选中继入口；仅此探测请求，不能证明其他应用已接入'
            else:
                source_plan = design_plan(value['plan']) if value.get('plan') is not None else self.plan
                target = next((t for t in source_plan['targets'] if t['id'] == target_id), None)
                if target is None:
                    raise ValueError('请选择通道或出口')
                scope = ('仅验证当前草稿出口' if value.get('plan') is not None else '仅验证已保存出口') + '，不经过通道规则或 DNS 映射，不证明应用已接入'
            result = probes.probe(value.get('url', value.get('target', '')), target,
                                  mode=value.get('mode', 'http'), forbidden_ports=(self.control_port,))
            result.update(channel_id=channel_id, target_id=target_id, scope=scope)
            self.audit('分层连接检测', result)
            return result
        finally:
            self.probe_slots.release()

    def export(self, kind, plan=None):
        if kind == 'plan':
            value = design_plan(plan) if plan is not None else self.plan
        elif kind == 'diagnostics':
            value = self.state()
            value['events'] = self.relay.events(limit=300)
            value['export_notice'] = '保留域名、端口、进程名、路径与 IP 以便诊断；不包含请求正文、认证、订阅或备份。分享前可自行检查。'
        else:
            raise ValueError('未知的导出类型')
        return {'filename': f'proxy-patchbay-{kind}.json', 'mime': 'application/json',
                'content': json.dumps(redact(value), ensure_ascii=False, indent=2)}

    def close(self):
        with self.lock:
            if self.closed:
                return
            self.closing = True
            try:
                self.stop()
                self.lease.close()
                self.closed = True
            finally:
                self.closing = False
