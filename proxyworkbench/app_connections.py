"""Reviewable application launch operations, shared by the GUI and shortcuts."""
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import time
import threading
from urllib.parse import urlsplit

from . import app_launch, hermes_adapter, process_proxy
from .app_routes import parse, proxy_url, route_key
from .catalog import application_executable_path, _PROTECTED_EXES
from .proxy_environment import child_environment, PROXY_NAMES


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _identity(item):
    return [item.get('ProcessId'), item.get('Started'), item.get('ExecutablePath')]


def _proxy_comparison(observed, expected):
    observed = {k.upper(): v for k, v in observed.items()}
    expected = {k.upper(): v for k, v in expected.items()}
    keys = tuple(k for k in PROXY_NAMES if k not in {'NO_PROXY', 'GLOBAL_AGENT_NO_PROXY'})
    if any(observed.get(k, '') != expected.get(k, '') for k in keys):
        return 'different' if any(observed.get(k) for k in keys) else 'missing'
    if observed.get('GLOBAL_AGENT_NO_PROXY', '') != expected.get('GLOBAL_AGENT_NO_PROXY', ''):
        return 'different'
    actual = set(filter(None, observed.get('NO_PROXY', '').lower().split(',')))
    wanted = set(filter(None, expected.get('NO_PROXY', '').lower().split(',')))
    if not wanted.issubset(actual):
        return 'different'
    for extra in actual - wanted:
        try:
            # Hermes can append a particular LAN model IP to its range-based bypass.
            address = ipaddress.ip_address(extra)
            if not (address.is_private or address.is_loopback):
                return 'different'
        except ValueError:
            return 'different'
    return 'matches'


def _safe_proxy_summary(values):
    rows = []
    for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'):
        value = values.get(key)
        if not value:
            continue
        try:
            address = urlsplit(value)
            # Never expose authentication, URL paths or arbitrary variable values.
            host = address.hostname
            if not host:
                raise ValueError()
            host = '[' + host + ']' if ':' in host else host
            rows.append(f'{key}={address.scheme}://{host}' + (f':{address.port}' if address.port else ''))
        except ValueError:
            rows.append(key + '=已设置（格式未确认）')
    return '；'.join(rows) if rows else '未设置 HTTP_PROXY、HTTPS_PROXY、ALL_PROXY'


def _expected(record, install):
    if install:
        return hermes_adapter.environment(os.environ, record['mode'], record['proxy_url'], install)
    return child_environment(os.environ, record['mode'], record['proxy_url'])


def inspect(record):
    executable = application_executable_path(record['executable'])
    if Path(executable).name.casefold() in _PROTECTED_EXES:
        raise ValueError('该网络组件或工作连接受保护')
    install = hermes_adapter.installation(executable)
    integration = hermes_adapter.describe(executable)
    if integration and integration['id'] == 'hermes_unsupported':
        raise ValueError(integration['notice'])
    items = process_proxy.records()
    selected = process_proxy.matching(items, executable)
    backend = hermes_adapter.backend(install, items) if install else {'state': 'unsupported'}
    ids = {p['ProcessId'] for p in selected}
    main = next((p for p in selected if p.get('ParentProcessId') not in ids), None)
    subject = backend.get('_process') if install else main
    checks = [{'label': '所选程序', 'status': 'ok', 'detail': executable}]
    env_status = 'not_running'
    if install:
        checks.append({'label': '模型请求后台', 'status': 'ok' if backend['state'] == 'running' else 'unknown',
                       'detail': f"后台运行中 · PID {backend['pid']}" if backend['state'] == 'running' else backend.get('detail', '后台尚未运行')})
    gui_status, home_matches = 'not_running', True
    if install and not main:
        try:
            inherited = {k.upper(): v for k, v in os.environ.items() if k.upper() in process_proxy.IDENTITY_NAMES}
            home_matches = os.path.normcase(os.path.abspath(hermes_adapter.desktop_home(inherited))) == os.path.normcase(os.path.abspath(install['home']))
        except (ValueError, OSError):
            home_matches = False
    if install and main:
        try:
            gui_values = process_proxy.proxy_values(main)
            home_matches = os.path.normcase(os.path.abspath(hermes_adapter.desktop_home(gui_values))) == os.path.normcase(os.path.abspath(install['home']))
            gui_status = _proxy_comparison(gui_values, _expected(record, install))
        except (ValueError, OSError):
            gui_status, home_matches = 'unknown', False
        checks.append({'label': '窗口启动环境', 'status': 'ok' if gui_status == 'matches' and home_matches else 'warning',
                       'detail': '窗口环境已一致，可复用。' if gui_status == 'matches' and home_matches else
                       '需先从 Hermes 菜单退出旧窗口，再应用；否则它可能自动拉起旧代理环境的后台。' if home_matches else
                       '无法确认窗口的数据目录与此安装一致，当前不支持自动重配这个后台。'})
    proxy_fingerprint = None
    if subject:
        try:
            values = process_proxy.proxy_values(subject)
            env_status = _proxy_comparison(values, _expected(record, install))
            proxy_fingerprint = _digest(values)
            checks.append({'label': '后台代理环境' if install else '当前进程代理环境',
                           'status': 'ok' if env_status == 'matches' else 'warning',
                           'detail': _safe_proxy_summary(values) + ('；与保存设置一致' if env_status == 'matches' else '；与本次设置不一致')})
        except (ValueError, OSError, TypeError):
            env_status = 'unknown'
            checks.append({'label': '代理环境', 'status': 'unknown', 'detail': '权限或进程变化导致无法读取；不能判断当前软件是否采用代理。'})
    else:
        checks.append({'label': '代理环境', 'status': 'unknown', 'detail': '尚无可核对的运行进程，保存的设置会用于下次启动。'})
    if install:
        checks.append({'label': '局域网与多配置', 'status': 'unknown',
                       'detail': '应用后本机与私网 IP 地址绕过代理，供局域网 Qwen 使用；局域网主机名未自动覆盖。各 profile 私有配置仍可能覆盖，实际模型回复待验证。'})
    checks.append({'label': '验证范围', 'status': 'unknown',
                   'detail': '环境一致不等于模型、登录或下载已成功；仍需在目标软件重试。系统代理开关也不能证明软件采用它。'})
    summary = '当前进程代理与设置一致，实际业务连接待验证。' if env_status == 'matches' else '尚未确认目标软件采用此设置。'
    if install and env_status == 'missing' and record['mode'] == 'http_environment':
        summary = 'Hermes 后台缺少代理环境。只开系统代理或给安装器设置代理，可能无法覆盖模型请求。'
    return {'summary': summary, 'checks': checks, 'backend': {k: v for k, v in backend.items() if not k.startswith('_')},
            'application': {'executable': executable, 'running': bool(selected), 'integration': 'hermes' if install else None},
            '_install': install, '_selected': selected, '_environment': env_status,
            '_identity': [_identity(p) for p in selected] + ([_identity(subject)] if subject and install else []),
            '_proxy_fingerprint': proxy_fingerprint, '_gui_status': gui_status, '_home_matches': home_matches,
            '_pending': bool(install and hermes_adapter.lifecycle_pending(install, items))}


def public_check(report):
    return {key: value for key, value in report.items() if not key.startswith('_')}


def _fingerprint(record, report):
    return _digest([record, report['_identity'], report['_proxy_fingerprint'], report['backend'],
                    report['_gui_status'], report['_home_matches'], report['_pending']])


def plan(record):
    report = inspect(record)
    install, backend = report['_install'], report['backend']
    blocked = None
    restart = bool(install and backend['state'] == 'running' and report['_environment'] != 'matches')
    if report['_pending']:
        blocked = 'Hermes 的上一项后台操作仍在进行，请等待结束后再检查。'
    elif install and not report['_home_matches']:
        blocked = 'Hermes 使用的数据目录与此安装不一致或不可确认；请使用原启动方式，当前适配不支持自动重配。'
    elif install and report['_gui_status'] not in {'not_running', 'matches'}:
        blocked = '请先从 Hermes 菜单退出旧窗口，再点“应用并打开”。后台将由 FlowDesk 检查和处理；只关窗口右上角可能仍在托盘运行。'
    elif install and backend['state'] == 'unknown':
        blocked = backend.get('detail', '无法核对后台身份')
    elif restart and backend.get('active_agents', 0) > 0:
        blocked = 'Hermes 还有进行中的任务；请等待任务结束后再应用。'
    elif not install and report['application']['running']:
        blocked = '软件仍在运行，请正常退出后再启动；已有实例保留旧环境。'
    if record['mode'] == 'http_environment':
        address = urlsplit(proxy_url(record['proxy_url']))
        try:
            with socket.create_connection((address.hostname, address.port), timeout=2):
                pass
        except OSError:
            blocked = '已保存的代理入口没有响应。请先打开代理软件；端口变化后重新检测、选择并保存。'
    steps = []
    if restart:
        steps.append('通过 Hermes 官方命令重启默认后台；它承载的所有 profile 会短暂重连。')
        steps.append('保留 Hermes 的任务检查，不强制中断任务；重新核对后台采用的代理。')
    elif install and backend['state'] == 'stopped':
        steps.append('以保存的代理设置启动 Hermes 默认后台，等待它就绪。')
    elif install:
        steps.append('后台代理环境已一致，复用现有后台。')
    steps.append('保留已打开的 Hermes 窗口。' if install and report['application']['running'] else '按保存设置打开软件。')
    return {'can_launch': not blocked, 'requires_confirmation': restart and not blocked,
            'summary': blocked or ('需要把代理应用到 Hermes 后台。' if restart else '可以使用保存的连接设置。'),
            'steps': steps, 'notice': '仅控制所选软件及适配的后台；不修改 Windows 持久代理变量、TUN 或其他软件。',
            '_restart': restart, '_report': report, '_fingerprint': _fingerprint(record, report)}


@contextmanager
def launch_lock(root, key):
    directory = Path(root) / '.local' / 'launch-locks'
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / (key + '.lock')).open('a+b') as handle:
        if not handle.tell():
            handle.write(b'0'); handle.flush()
        handle.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise ValueError('该软件已有启动或应用操作正在进行，请稍候。') from None
        yield


def execute(root, record, prepared):
    with launch_lock(root, record['key']):
        stored = parse(json.loads((Path(root) / '.local/app-routes.json').read_text(encoding='utf-8')))
        if next((r for r in stored['routes'] if r['key'] == record['key']), None) != record:
            raise ValueError('保存的设置已变化，请重新检查并应用。')
        current = plan(record)
        if current['_fingerprint'] != prepared['_fingerprint']:
            raise ValueError('软件或后台状态已变化，请重新点击应用，核对新的影响范围。')
        if not current['can_launch']:
            raise ValueError(current['summary'])
        report, install = current['_report'], current['_report']['_install']
        if not install:
            return app_launch.launch(record['executable'], record['proxy_url'], record['mode'])
        env = _expected(record, install)
        hermes_adapter.apply(install, env, restart=current['_restart'])
        verified = inspect(record)
        if verified['backend']['state'] != 'running' or verified['_environment'] != 'matches':
            raise ValueError('Hermes 后台已响应，但尚未确认采用所选代理。可能存在 profile 私有覆盖，请查看“检查此软件”；没有标记为成功。')
        if not verified['application']['running']:
            app_launch.launch(record['executable'], record['proxy_url'], record['mode'], environment=env)
        return {'pid': verified['backend']['pid'], 'executable': record['executable'],
                'notice': 'Hermes 后台已就绪，代理环境与设置一致。请在原聊天重试；实际模型回复尚未验证。'}


class LaunchReviews:
    def __init__(self, root):
        self.root = root
        self.tickets = {}
        self.lock = threading.Lock()

    def prepare(self, record):
        prepared = plan(record)
        now = time.monotonic()
        ticket = secrets.token_urlsafe(24)
        with self.lock:
            self.tickets = {k: v for k, v in self.tickets.items() if v[0] > now}
            if len(self.tickets) >= 32:
                self.tickets.clear()
            self.tickets[ticket] = (now + 180, record, prepared)
        return {**{k: v for k, v in prepared.items() if not k.startswith('_')}, 'ticket': ticket}

    def apply(self, record, ticket):
        with self.lock:
            entry = self.tickets.pop(ticket, None) if isinstance(ticket, str) else None
        if not entry or entry[0] < time.monotonic() or entry[1] != record:
            raise ValueError('启动预览已过期或设置改变，请重新点击应用。')
        if not entry[2]['can_launch']:
            raise ValueError(entry[2]['summary'])
        return execute(self.root, record, entry[2])
