"""Application state; startup and discovery are read-only toward the host."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import threading
import time
import secrets
import uuid
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
        self._catalog_cache = None
        self.guide_slots = threading.BoundedSemaphore(1)
        self.guide_checks = {}
        self.route_sessions = {}
        from .app_connections import LaunchReviews
        self.launch_reviews = LaunchReviews(self.root)
        self.custom_apps_error = None
        from .catalog import manual_apps_document
        try:
            self.custom_apps = manual_apps_document(self.store.read('custom-apps.json', {'schema_version': 1, 'apps': []}))['apps']
        except (OSError, ValueError, TypeError):
            self.custom_apps = []
            self.custom_apps_error = '手动软件清单无法读取；原文件保留，请修复 .local/custom-apps.json 后重启，当前不会覆盖它。'
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
                self._catalog_cache = None
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

    def _catalog(self):
        from .catalog import Catalog
        self._ensure_open()
        if self._catalog_cache is None:
            self._catalog_cache = Catalog(copy.deepcopy(self.snapshot), data_root=self.root, manual_apps=self.custom_apps)
        return self._catalog_cache

    def catalog_state(self):
        with self.lock:
            value = self._catalog().describe()
            return {**value, 'snapshot_stale': self.snapshot_stale,
                    'snapshot_captured_at': self.snapshot.get('captured_at'),
                    'manual_registry_error': self.custom_apps_error,
                    'discovering': self.discovering, 'discovery_error': self.discovery_error}

    def catalog_add_app(self, value):
        from .catalog import application_executable_path, application_display_name, _key
        executable = application_executable_path(value.get('executable'))
        name = application_display_name(value.get('name'), executable)
        with self.lock:
            self._ensure_open()
            if self.custom_apps_error:
                raise RuntimeError(self.custom_apps_error)
            existing = next((item for item in self.custom_apps if _key(item['executable']) == _key(executable)), None)
            if existing:
                catalog = self.catalog_state()
                app = next(item for item in catalog['apps'] if item['manual_id'] == existing['id'])
                return {'catalog': catalog, 'app_id': app['id'], 'duplicate': True}
            if len(self.custom_apps) >= 256:
                raise ValueError('最多可手动登记 256 个软件，请先移除不需要的登记')
            record = {'id': 'manual-' + uuid.uuid4().hex, 'name': name,
                      'executable': executable, 'created_at': now()}
            updated = [*self.custom_apps, record]
            # Persist first; failed atomic storage must not create an in-memory
            # entry that disappears after restart.
            self.store.write('custom-apps.json', {'schema_version': 1, 'apps': updated})
            self.custom_apps = updated
            self._catalog_cache = None
            self.audit('手动登记本机软件（未执行）', {'manual_id': record['id'], 'name': name, 'executable': executable})
            catalog = self.catalog_state()
            app = next(item for item in catalog['apps'] if item['manual_id'] == record['id'])
            return {'catalog': catalog, 'app_id': app['id'], 'duplicate': False}

    def catalog_remove_app(self, value):
        manual_id = value.get('manual_id')
        if not isinstance(manual_id, str):
            raise ValueError('请提供所选手动登记的 manual_id')
        with self.lock:
            self._ensure_open()
            if self.custom_apps_error:
                raise RuntimeError(self.custom_apps_error)
            found = next((item for item in self.custom_apps if item['id'] == manual_id), None)
            if found is None:
                raise ValueError('手动登记不存在或已移除，请刷新清单')
            updated = [item for item in self.custom_apps if item['id'] != manual_id]
            self.store.write('custom-apps.json', {'schema_version': 1, 'apps': updated})
            self.custom_apps = updated
            self._catalog_cache = None
            self.audit('移除本机软件登记（保留程序与现有进程）', {'manual_id': manual_id})
            return {'catalog': self.catalog_state()}

    def catalog_resource(self, value):
        with self.lock:
            catalog = self._catalog()
            app_id, resource_id = value.get('app_id'), value.get('resource_id')
            action = value.get('action')
            if action == 'tail':
                return catalog.tail(app_id, resource_id, max_bytes=16384)
            if action == 'open':
                result = catalog.open_resource(app_id, resource_id)
                self.audit('打开已发现应用资源所在目录', {'app_id': app_id, 'resource_id': resource_id})
                return result
            raise ValueError('只支持查看日志尾部或打开已发现资源所在目录')

    def catalog_launch_profile(self, value):
        with self.lock:
            result = self._catalog().export_launch_profile(
                value.get('app_id'), value.get('mode'), value.get('proxy_url', ''),
                arguments=value.get('arguments'))
            self.audit('导出新进程启动配置（未执行）', {'app_id': value.get('app_id'), 'mode': value.get('mode')})
            return result

    def guide_state(self):
        with self.lock:
            return {'catalog': self.catalog_state(), 'tools': copy.deepcopy(self.snapshot.get('network_tools', [])),
                    'snapshot_captured_at': self.snapshot.get('captured_at'), 'snapshot_stale': self.snapshot_stale,
                    'discovering': self.discovering, 'discovery_error': self.discovery_error}

    def app_routes_state(self):
        from .app_routes import parse, describe, route_key
        with self.lock:
            catalog=self.catalog_state()
            error=None
            try:records=parse(self.store.read('app-routes.json',{'schema_version':1,'routes':[]}))['routes']
            except (ValueError,TypeError,OSError):
                records=[];error='保存的应用连接设置无法读取；原文件保留，请修复 app-routes.json 后重试。'
            by_key={item['key']:item for item in records}
            routes=[]
            for app in catalog['apps']:
                executable=app.get('executable') or app['launch_profile'].get('executable')
                item=describe(app,by_key.get(route_key(executable)) if executable else None)
                item['session']=self.route_sessions.get(item['key'])
                routes.append(item)
            return {'catalog':catalog,'routes':routes,'tools':copy.deepcopy(self.snapshot.get('network_tools',[])),
                    'error':error,'snapshot_captured_at':self.snapshot.get('captured_at')}

    def _app_route(self, value):
        from .app_routes import proxy_url, MODES
        from .hermes_adapter import describe as integration_for
        app=self._catalog()._apps.get(value.get('app_id'))
        if not app or app['protected'] or not app['launch_profile']['available']:
            raise ValueError('请先为该软件选择准确主程序；受保护组件不能在此重配')
        integration=integration_for(app['launch_profile']['executable'])
        if integration and integration['id']=='hermes_unsupported':
            raise ValueError(integration['notice'])
        mode=value.get('mode')
        if mode not in MODES:raise ValueError('请选择支持的连接方式')
        endpoint=proxy_url(value.get('proxy_url')) if mode=='http_environment' else ''
        if endpoint:
            allowed=[option['proxy_url'] for tool in self.snapshot.get('network_tools',[]) for option in tool['proxy_options'] if option['protocol']=='http']
            allowed += [item['proxy_url'] for item in self.relay.status()['channels'] if item.get('proxy_url')]
            if endpoint not in allowed:raise ValueError('该代理入口已变化或尚未被识别，请重新检测后连线')
        return app,mode,endpoint

    def app_route_save(self, value):
        from .app_routes import parse,route_key
        from .catalog import application_executable_path
        from .app_connections import launch_lock
        with self.lock:
            self._ensure_open()
            app,mode,endpoint=self._app_route(value)
            executable=application_executable_path(app['launch_profile']['executable'])
            document=parse(self.store.read('app-routes.json',{'schema_version':1,'routes':[]}))
            key=route_key(executable)
            document['routes']=[record for record in document['routes'] if record['key']!=key]
            document['routes'].append({'key':key,'executable':executable,'mode':mode,'proxy_url':endpoint,'updated_at':now()})
            if len(document['routes'])>256:raise ValueError('最多保存 256 个软件的连接设置')
            with launch_lock(self.root, key):
                self.store.write('app-routes.json',document)
            self.route_sessions.pop(key,None)
            self.audit('保存可视化应用连接设置',{'app_id':app['id'],'mode':mode,'proxy_url':endpoint})
            return self.app_routes_state()

    def app_route_launch(self, value):
        from .app_launch import launch
        from .app_routes import parse,route_key
        with self.lock:
            self._ensure_open()
            app=self._catalog()._apps.get(value.get('app_id'))
            if not app:raise ValueError('应用记录已变化，请重新检测')
            executable=app['launch_profile'].get('executable')
            records=parse(self.store.read('app-routes.json',{'schema_version':1,'routes':[]}))['routes']
            record=next((item for item in records if executable and item['key']==route_key(executable)),None)
            if not record:raise ValueError('请先保存该软件的连接设置')
            app,mode,endpoint=self._app_route({'app_id':app['id'],**record})
        from .hermes_adapter import installation
        if value.get('ticket'):
            result=self.launch_reviews.apply(record,value['ticket'])
        elif installation(executable):
            raise ValueError('请先预览 Hermes 后台的应用步骤，再确认执行。')
        else:
            result=launch(executable,endpoint,mode)
        with self.lock:
            current=next((item for item in parse(self.store.read('app-routes.json',{'schema_version':1,'routes':[]}))['routes'] if item['key']==record['key']),None)
            if current and current['mode']==mode and current['proxy_url']==endpoint:
                self.route_sessions[record['key']]={'pid':result['pid'],'started_at':now(),'mode':mode,'proxy_url':endpoint}
            self.audit('从可视化设置启动目标软件',{'app_id':app['id'],'pid':result['pid'],'mode':mode})
            return {'launch':result,**self.app_routes_state()}

    def _saved_app_record(self, value, *, required=True):
        from .app_routes import parse, route_key
        with self.lock:
            self._ensure_open()
            app = self._catalog()._apps.get(value.get('app_id'))
            if not app or app.get('protected') or not app.get('launch_profile', {}).get('available'):
                raise ValueError('请选择准确的应用主程序；受保护组件不能在此操作。')
            executable = app['launch_profile']['executable']
            records = parse(self.store.read('app-routes.json', {'schema_version': 1, 'routes': []}))['routes']
            record = next((r for r in records if r['key'] == route_key(executable)), None)
            if required and record is None:
                raise ValueError('请先保存该软件的连接设置。')
            return app, record or {'key': route_key(executable), 'executable': executable,
                                   'mode': 'inherit', 'proxy_url': '', 'updated_at': ''}

    def app_route_inspect(self, value):
        from .app_connections import inspect, public_check
        _, record = self._saved_app_record(value, required=False)
        return public_check(inspect(record))

    def app_route_prepare(self, value):
        app, record = self._saved_app_record(value)
        with self.lock:
            self._app_route({'app_id': app['id'], **record})
        return self.launch_reviews.prepare(record)

    def app_route_shortcut(self, value):
        from .app_shortcuts import create
        app, record = self._saved_app_record(value)
        result = create(self.root, record, app['name'])
        self.audit('创建应用桌面快捷方式（未启动）', {'app_id': app['id'], 'mode': record['mode']})
        return result

    def guide_check(self, value):
        from .troubleshoot import diagnose, problem_url
        problem_url(value)  # Reject private/invalid URLs before any collection or probe.
        if not self.guide_slots.acquire(blocking=False):
            raise RuntimeError('已有一项问题检测正在进行，请等待结果')
        try:
            with self.lock:
                if not any(app['id'] == value.get('app_id') for app in self._catalog().describe()['apps']):
                    raise ValueError('请先选择遇到问题的软件，找不到时可添加程序')
            scan = self.discover()
            if scan.get('discovering') or scan.get('error'):
                raise RuntimeError('本机识别还未完成，请稍后重新检测')
            with self.lock:
                snapshot = copy.deepcopy(self.snapshot)
                app = next((app for app in self._catalog().describe()['apps'] if app['id'] == value.get('app_id')), None)
                if app is None:
                    raise ValueError('该进程已退出，请把主程序添加到本机软件后重试')
            def runner(url, target, **kwargs):
                with self.probe_slots:
                    return probes.probe(url, target, forbidden_ports=(self.control_port,), **kwargs)
            result = diagnose(snapshot, app, value, runner)
            check_id = secrets.token_hex(16)
            with self.lock:
                self.guide_checks = {key: entry for key, entry in self.guide_checks.items() if time.monotonic() - entry['at'] < 600}
                while len(self.guide_checks) >= 8:
                    self.guide_checks.pop(next(iter(self.guide_checks)))
                self.guide_checks[check_id] = {'at': time.monotonic(), 'result': copy.deepcopy(result),
                                             'executable': app.get('executable') or app.get('launch_profile', {}).get('executable')}
                self.audit('引导式连接对照检测', {'app_id': app['id'], 'result': result['recommendation']['status']})
            return {**result, 'check_id': check_id}
        finally:
            self.guide_slots.release()

    def _guide_checked(self, value):
        entry = self.guide_checks.get(value.get('check_id'))
        if not entry or time.monotonic() - entry['at'] >= 600:
            raise ValueError('本次检测已过期，请重新检测后操作')
        return entry

    def guide_profile(self, value):
        with self.lock:
            entry = self._guide_checked(value)
            result = entry['result']
            profile = result['recommendation']['profile']
            if not profile:
                raise ValueError('本次没有适合该软件的代理启动方案，请按检测建议操作')
            app = self._catalog()._apps.get(result['app_id'])
            if not app or app.get('executable') != entry['executable']:
                raise ValueError('程序记录已经变化，请重新检测')
            available = [option['proxy_url'] for tool in self.snapshot.get('network_tools', []) for option in tool.get('proxy_options', [])]
            if profile['proxy_url'] not in available:
                raise ValueError('代理入口已经变化，请重新识别与检测')
            exported = self.catalog_launch_profile({'app_id': result['app_id'], **profile})
            return {**exported, 'app_name': result['app_name'], 'proxy_url': profile['proxy_url'],
                    'steps': ['核对上方的软件名称与代理入口。', '关闭当前目标软件窗口，保留代理客户端运行。',
                              '点击“按方案启动”，在软件里重试原来的操作。', '回到此页确认结果；出现新错误时粘贴新地址再检测。']}

    def guide_feedback(self, value):
        with self.lock:
            entry = self._guide_checked(value)
            if value.get('outcome') not in {'resolved', 'failed'}:
                raise ValueError('请选择实际操作成功或仍然失败')
            self.audit('用户反馈引导操作结果', {'app_id': entry['result']['app_id'], 'outcome': value['outcome'], 'source': 'user_report'})
            return {'outcome': value['outcome'], 'source': 'user_report',
                    'message': '已记录你确认本次操作成功。' if value['outcome'] == 'resolved' else '请粘贴新的错误地址再检测；后续安装阶段可能访问不同目标。'}

    def guide_launch(self, value):
        from .app_launch import launch
        with self.lock:
            self.guide_profile(value)  # Same app protection, expiry and entrance validation as export.
            entry = self._guide_checked(value)
            app = self._catalog()._apps[entry['result']['app_id']]
            if app['protected']:
                raise ValueError('该工作连接受保护，请在软件自己的设置中操作')
            executable = app['launch_profile']['executable']
            proxy_url = entry['result']['recommendation']['profile']['proxy_url']
        result = launch(executable, proxy_url)
        self.audit('用户按检测方案启动目标新进程', {'app_id': entry['result']['app_id'], 'pid': result['pid'], 'proxy_url': proxy_url})
        return result

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
            value['application_catalog'] = self.catalog_state()
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
