"""Per-application proxy evidence, bounded log access and reviewable launch files.

This module changes no proxy setting and launches no application.  The only
interactive host action is opening a registered resource's existing directory.
Config resources are locations only: their contents are never returned.
"""
from __future__ import annotations

from datetime import datetime, timezone
from copy import deepcopy
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PureWindowsPath
import re
import stat
import subprocess
import unicodedata
from urllib.parse import urlsplit

from .privacy import redact
from .proxy_environment import PROXY_NAMES as _PROXY_NAMES, assignments as proxy_assignments

_PROTECTED = {'codex', 'v2rayn', 'xray', 'v2ray', 'sing_box', 'clash', 'mihomo',
              'clash_verge', 'mihomo_party', 'ssr', 'surge', 'nekobox', 'hiddify',
              'proxifier', 'proxycap', 'uu', 'atrust', 'zerotier', 'flowdesk'}
_PROTECTED_EXES = {'codex.exe', 'codex-app-server.exe', 'app-server.exe',
                   'v2rayn.exe', 'xray.exe', 'v2ray.exe', 'sing-box.exe',
                   'singbox.exe', 'mihomo.exe', 'clash.exe', 'clash-verge.exe',
                   'verge-mihomo.exe', 'uu.exe', 'uu_neths_helper.exe',
                   'proxifier.exe', 'proxycap.exe', 'flowdesk.exe', 'atrust.exe', 'atrustagent.exe',
                   'atrustxtunnel.exe', 'atrusttray.exe', 'zerotier-one_x64.exe', 'zerotier-one_x86.exe',
                   'zerotier-one.exe', 'zerotier_desktop_ui.exe', 'uu_launcher.exe', 'uu_cloudsyn.exe'}
_CLI_EXES = {'curl.exe', 'git.exe', 'python.exe', 'pythonw.exe', 'python3.exe',
             'pip.exe', 'pip3.exe', 'node.exe', 'npm.exe'}
_MAIN_EXES = {
    'steam': ('steam.exe',), 'wgc': ('wgc.exe',), 'wgc_cn360': ('wgc.exe',),
    'git': ('git.exe',), 'curl': ('curl.exe',), 'vscode': ('code.exe',),
    'python': ('python.exe', 'python3.exe', 'pythonw.exe'), 'node': ('node.exe',),
    'chrome': ('chrome.exe',), 'edge': ('msedge.exe',), 'firefox': ('firefox.exe',),
    'rustdesk': ('rustdesk.exe',), 'codex': ('codex.exe',),
    'v2rayn': ('v2rayn.exe',), 'xray': ('xray.exe',), 'v2ray': ('v2ray.exe',),
    'sing_box': ('sing-box.exe', 'singbox.exe'),
    'clash': ('clash.exe', 'clash-meta.exe', 'clash-win64.exe', 'clash-windows-amd64.exe'),
    'mihomo': ('mihomo.exe', 'verge-mihomo.exe'),
    'clash_verge': ('clash-verge.exe', 'clashverge.exe'),
    'mihomo_party': ('mihomo-party.exe',), 'ssr': ('shadowsocks.exe', 'shadowsocksr.exe', 'ssr.exe', 'sslocal.exe'),
    'surge': ('surge.exe',), 'nekobox': ('nekobox.exe', 'nekoray.exe'),
    'hiddify': ('hiddify.exe',), 'proxifier': ('proxifier.exe',),
    'proxycap': ('proxycap.exe',), 'uu': ('uu.exe', 'uu_ball.exe', 'uubooster.exe'),
    'flowdesk': ('flowdesk.exe',),
}
_MAX_BYTES = 65536
_REPARSE = 0x400
_MANUAL_ID = re.compile(r'manual-[0-9a-f]{32}\Z')
_MAX_MANUAL_APPS = 256


def _now():
    return datetime.now(timezone.utc).isoformat()


def _text(value, limit=500):
    return str(redact(str(value or ''))).replace('\x00', '')[:limit]


def _key(path):
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _identity(info):
    return info.st_dev, info.st_ino


def _checked(path, *, missing=False):
    path = Path(os.path.abspath(path))
    if any(ord(char) < 32 for char in str(path)):
        raise ValueError('资源路径包含控制字符')
    # No NTFS alternate streams.  A drive letter's colon is the sole exception.
    if any(':' in part for part in path.parts[1:]):
        raise ValueError('资源路径包含备用数据流')
    for component in reversed((path, *path.parents)):
        try:
            info = component.lstat()
        except FileNotFoundError:
            if missing:
                continue
            raise
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & _REPARSE:
            raise ValueError('资源路径含符号链接或重解析点，请在原应用中查看')
    return path


def _path_record(path):
    try:
        checked = _checked(path)
        info = checked.lstat()
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError('不是普通文件或目录')
        return True, info, None
    except FileNotFoundError:
        return False, None, None
    except (OSError, ValueError) as exc:
        return False, None, _text(exc, 160)


def application_executable_path(value, *, require_exists=True):
    """Validate an exact local program path; never accept a command line."""
    if (not isinstance(value, str) or not value or len(value) > 32767
            or value != value.strip() or any(unicodedata.category(char).startswith('C') for char in value)):
        raise ValueError('请选择完整的本地 .exe 路径，不包含控制字符、引号或启动参数')
    if value.startswith(('\\\\', '//', '\\??\\')) or PureWindowsPath(value).drive.startswith('\\\\'):
        raise ValueError('仅支持本机磁盘上的 .exe，不支持 UNC、网络共享或设备路径')
    path = Path(value)
    if not path.is_absolute() or path.suffix.casefold() != '.exe' or any(part == '..' for part in path.parts):
        raise ValueError('需要绝对本地 .exe 路径；不要填写目录、相对路径或拼接启动参数')
    if any(':' in part for part in path.parts[1:]) or '"' in value:
        raise ValueError('程序路径不能包含备用数据流、引号或启动参数')
    if require_exists:
        if os.name == 'nt':
            import ctypes
            from ctypes import wintypes
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
            kernel.GetDriveTypeW.restype = wintypes.UINT
            if kernel.GetDriveTypeW(path.anchor) == 4:
                raise ValueError('所选盘符指向网络共享，请选择本机磁盘上的 .exe')
        try:
            path = _checked(path)
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError('所选路径不是普通 .exe 文件')
        except OSError as exc:
            raise ValueError('所选程序不存在或不可读取，请重新选择') from exc
    return str(path)


def application_display_name(value, executable):
    if value is None or value == '' or (isinstance(value, str) and not value.strip()):
        return Path(executable).stem[:100]
    if (not isinstance(value, str) or len(value.strip()) > 100
            or any(unicodedata.category(char).startswith('C') for char in value)):
        raise ValueError('软件名称最多 100 个字符，不包含控制字符')
    return value.strip()


def manual_apps_document(value):
    """Parse stored metadata without dropping programs that have gone missing."""
    if not isinstance(value, dict) or value.get('schema_version') != 1 or not isinstance(value.get('apps'), list):
        raise ValueError('手动软件清单格式无效')
    if len(value['apps']) > _MAX_MANUAL_APPS:
        raise ValueError('手动登记软件数量超过 256 项')
    result, identifiers, paths = [], set(), set()
    for item in value['apps']:
        if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not _MANUAL_ID.fullmatch(item['id']):
            raise ValueError('手动软件登记标识无效')
        path = application_executable_path(item.get('executable'), require_exists=False)
        if item['id'] in identifiers or _key(path) in paths:
            raise ValueError('手动软件清单包含重复登记')
        identifiers.add(item['id'])
        paths.add(_key(path))
        record = {'id': item['id'], 'name': application_display_name(item.get('name'), path), 'executable': path}
        if isinstance(item.get('created_at'), str):
            record['created_at'] = item['created_at'][:80]
        result.append(record)
    return {'schema_version': 1, 'apps': result}


def _capability_id(executable):
    # Reuse the discovery classification, including recognized helper images.
    # Display names never participate in protection or capability decisions.
    from .discovery import _app_id
    return _app_id(Path(executable).name, executable)


def _matches_manual_path(app, executable):
    registered = _key(executable)
    if any(entry.get('executable') and _key(entry['executable']) == registered
           for entry in app.get('running_processes', [])):
        return True
    expected_main = _MAIN_EXES.get(app.get('_capability_id') or app['id'], ())
    for item in app.get('installed_locations', []):
        path = item.get('path')
        if not isinstance(path, str) or not Path(path).is_absolute():
            continue
        if _key(path) == registered:
            return True
        # Registry installation directories are location evidence, not launch
        # commands.  Only a known exact main-image name at that exact directory
        # can merge with the automatic application.
        if (Path(executable).name.casefold() in expected_main
                and _key(Path(executable).parent) == _key(path)):
            return True
    return False


def _application_executable(app_id, processes):
    """A helper's image is a location clue, never a known app's launch target."""
    observed = [entry['executable'] for entry in processes if entry.get('executable')
                and str(entry['executable']).lower().endswith('.exe')]
    main_names = _MAIN_EXES.get(app_id)
    if main_names is None:
        executable = observed[0] if observed else None
        return executable, Path(executable).parent if executable else None, False
    for name in main_names:
        executable = next((path for path in observed if Path(path).name.casefold() == name), None)
        if executable:
            return executable, Path(executable).parent, False
    # Helpers may live several levels below the application's main directory.
    # A fixed-depth existing-file check can locate logs/config without making
    # that unobserved main program a launch target.
    for executable in observed:
        for parent in list(Path(executable).parents)[:5]:
            for name in main_names:
                exists, info, _ = _path_record(parent / name)
                if exists and info and stat.S_ISREG(info.st_mode):
                    return None, parent, True
    return None, Path(observed[0]).parent if observed else None, bool(observed)


def _connection_summary(app, processes):
    connections, endpoint_ids, total, truncated = [], set(), 0, False
    for process in processes:
        total += max(0, int(process.get('tcp_count', 0) or 0))
        truncated = truncated or bool(process.get('connections_truncated'))
        for connection in process.get('connections', [])[:32]:
            if connection.get('hidden'):
                continue
            peers = list(connection.get('proxy_endpoint_ids') or [])
            endpoint_ids.update(peers)
            connections.append({key: value for key, value in {
                'pid': process.get('pid'), 'remote_address': connection.get('remote_address'),
                'remote_port': connection.get('remote_port'),
                'local_address': connection.get('local_address'),
                'local_port': connection.get('local_port'), 'proxy_endpoint_ids': peers,
                'remote_redacted': bool(connection.get('remote_redacted')),
                'remote_scope': connection.get('remote_scope'),
            }.items() if value is not None})
    if not processes:
        observed = app.get('observed_connections', {})
        total = max(0, int(observed.get('tcp_count', 0) or 0))
        endpoint_ids.update(observed.get('to_proxy_endpoints') or [])
    count = sum(bool(item['proxy_endpoint_ids']) for item in connections)
    status = 'proxy_peer_observed' if endpoint_ids else 'connections_observed' if total else 'none'
    return {'tcp_count': total, 'proxy_peer_count': count,
            'proxy_endpoint_ids': sorted(endpoint_ids), 'connections': connections[:128],
            'connections_truncated': truncated or len(connections) > 128,
            'status': status,
            'label': ('观察到本地代理候选连接' if endpoint_ids else '观察到 TCP 对端，路径待确认' if total else '本次未观察到已建立 TCP 连接'),
            'notice': '连接快照只证明此时的 TCP 对端。候选入口、其他公网对端均不能证明全部流量使用哪个代理、绕过 TUN 或 UDP/QUIC 路径。'}


def _settings(snapshot, app_id):
    layers = snapshot.get('layers', {})
    win, http, environment = (layers.get(key, {}) for key in ('wininet', 'winhttp', 'environment'))
    result = [
        {'layer': 'wininet', 'label': '当前用户系统代理 / PAC',
         'value': {'enabled': win.get('enabled'), 'proxy': win.get('proxy_server'),
                   'pac': win.get('auto_config_url'), 'auto_detect': win.get('auto_detect')},
         'status': win.get('evidence_status', 'unknown'), 'source': win.get('source', 'Windows Internet Settings'),
         'notice': '这是系统配置；应用是否采用、PAC 对当前 URL 的结果仍需验证。'},
        {'layer': 'winhttp', 'label': 'WinHTTP 默认代理',
         'value': {'mode': http.get('access_type', 'unknown'), 'proxy': http.get('proxy')},
         'status': http.get('evidence_status', 'unknown'), 'source': http.get('source', 'WinHTTP'),
         'notice': '应用可创建自己的 WinHTTP 会话；默认配置不等于该应用当前设置。'},
    ]
    for scope, label in (('user', '用户代理环境变量'), ('machine', '机器代理环境变量')):
        section = environment.get(scope, {})
        result.append({'layer': 'environment_' + scope, 'label': label,
                       'value': redact(section.get('values', {})),
                       'status': section.get('evidence_status', 'unknown'),
                       'source': section.get('source', 'Windows 环境注册表'),
                       'notice': '新进程可继承此层；未读取该已运行应用的环境块，也不假定它支持这些变量。'})
    native = {
        'firefox': 'Firefox 设置 → 常规 → 网络设置；可独立选择系统代理、手动代理或不使用代理。',
        'chrome': 'Chrome 常规会采用系统代理；策略、扩展或启动参数可能覆盖。打开 chrome://policy 与系统代理核对。',
        'edge': 'Edge 常规会采用系统代理；策略、扩展或启动参数可能覆盖。打开 edge://policy 与系统代理核对。',
        'vscode': 'VS Code 设置中查找 http.proxy；扩展和终端可分别采用其他代理层。',
        'git': 'Git 的 http.proxy / 按 URL 配置与环境变量均可能生效；本版只定位配置，不改动 Git 配置。',
        'curl': 'curl 支持显式 --proxy / --noproxy 与代理环境变量；本次未读取正在运行进程参数。',
        'python': 'Python 的代理行为取决于 urllib、Requests 等具体库；同一 python.exe 可以运行完全不同的应用。',
        'node': 'Node.js 的代理行为取决于运行版本、启动选项和使用的网络库；不能仅凭进程名认定支持。',
        'steam': 'Steam 社区、登录和内容下载的代理行为可能不同；先看实际连接，再判断下载是否经过候选入口。',
        'wgc': 'WGC 下载与登录可采用不同网络组件；先恢复 WoWS 资源独立，再按官方客户端设置验证。',
        'wgc_cn360': '国服 WGC 下载与登录可采用不同网络组件；先恢复 WoWS 资源独立，再按客户端设置验证。',
        'rustdesk': 'RustDesk 可配置其自身网络/代理；TCP 对端不能验证打洞、UDP 或完整远程会话。',
    }.get(app_id, '未内置此应用的专有代理适配器。请结合官方设置、进程连接与日志确认；系统代理或环境变量并不约束任意 Windows 应用。')
    result.append({'layer': 'application', 'label': '应用自身配置', 'value': '未读取专有配置',
                   'status': 'unknown', 'source': '能力说明 / 已发现配置位置', 'notice': native})
    result.append({'layer': 'tun', 'label': 'TUN / 加速器 / 系统路由', 'value': '按网卡和路由证据另行核对',
                   'status': layers.get('default_routes', {}).get('evidence_status', 'unknown'),
                   'source': '默认路由快照', 'notice': '清除代理变量或使用 DIRECT 仍遵循系统路由，可能经过 TUN、VPN 或加速器。'})
    return result


def _log_redact(text):
    if re.search(r'-----(?:BEGIN|END)\s+(?:[A-Z]+\s+)?PRIVATE\s+KEY-----', text):
        return '[包含私钥块的日志片段已隐藏]'
    lines = []
    sensitive_line = re.compile(r'''(?ix)(?:["']?\b(?:password|passwd|passphrase|secret|token|access[_-]?token|refresh[_-]?token|api[_-]?key|authorization|cookie|subscription|private[_-]?key|username)["']?\s*[:=])|-----BEGIN\s+(?:[A-Z]+\s+)?PRIVATE\s+KEY-----''')
    for line in text.splitlines():
        if sensitive_line.search(line):
            lines.append('[含认证或私有配置字段，整行已隐藏]')
            continue
        try:
            parsed = json.loads(line)
        except (ValueError, TypeError):
            parsed = None
        clean = json.dumps(redact(parsed), ensure_ascii=False) if isinstance(parsed, (dict, list)) else str(redact(line))
        clean = re.sub(r'\bsk-[A-Za-z0-9_-]{12,}\b', '<已隐藏的密钥>', clean)
        clean = re.sub(r'(?<![A-Za-z0-9_])[A-Za-z0-9+/]{48,}={0,2}(?![A-Za-z0-9_])', '<已隐藏的长编码值>', clean)
        lines.append(clean)
    return '\n'.join(lines)


class Catalog:
    def __init__(self, snapshot, *, data_root=None, environ=None, manual_apps=None):
        self.snapshot = snapshot if isinstance(snapshot, dict) else {}
        self.data_root = Path(data_root) if data_root else None
        env = os.environ if environ is None else environ
        self.roots = {name: Path(env[name]) for name in ('APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA', 'USERPROFILE')
                      if env.get(name) and Path(env[name]).is_absolute()}
        self._resources = {}
        self._apps = {}
        self.manual_apps = manual_apps_document({'schema_version': 1, 'apps': manual_apps or []})['apps']
        self._build()

    def _resource(self, app, path, kind, name):
        path = Path(os.path.abspath(path))
        identifier = 'res-' + hashlib.sha256((app['id'] + '\0' + _key(path) + '\0' + kind).encode()).hexdigest()[:24]
        if identifier in self._resources:
            return
        exists, info, error = _path_record(path)
        is_directory = bool(info and stat.S_ISDIR(info.st_mode))
        is_regular = bool(info and stat.S_ISREG(info.st_mode))
        can_tail = bool(kind == 'log' and is_regular and info.st_nlink == 1)
        public = {'id': identifier, 'name': name, 'kind': kind, 'path': str(path),
                  'exists': exists, 'can_tail': can_tail, 'can_open': exists,
                  'status': 'blocked' if error else 'observed' if exists else 'candidate',
                  'notice': error or ('候选位置，当前未发现；便携版或自定义目录可能不同。' if not exists else
                                      '已存在；配置只定位，不返回内容。' if kind == 'config' else
                                      '已存在；目录位置可打开，日志内容按需脱敏读取。')}
        self._resources[identifier] = {'app_id': app['id'], 'path': path, 'public': public,
                                       'identity': _identity(info) if info else None,
                                       'is_directory': is_directory}
        app['resources'].append(public)
        if is_directory and kind == 'log_directory':
            # One directory level, bounded count.  Never descend into user data.
            try:
                children = []
                for index, child in enumerate(path.iterdir()):
                    if index >= 512:
                        break
                    if child.suffix.lower() not in ('.log', '.txt'):
                        continue
                    valid, child_info, _ = _path_record(child)
                    if valid and child_info and stat.S_ISREG(child_info.st_mode) and child_info.st_nlink == 1:
                        children.append((child_info.st_mtime_ns, child))
                for _, child in sorted(children, reverse=True)[:12]:
                    self._resource(app, child, 'log', child.name)
            except OSError:
                pass

    def _locations(self, app, base=None, capability_id=None):
        app_id = capability_id or app['id']
        exe = app['launch_profile'].get('executable')
        base = Path(base) if base is not None else Path(exe).parent if exe else None
        env = self.roots
        if base:
            for folder in ('logs', 'log'):
                self._resource(app, base / folder, 'log_directory', '程序目录 / ' + folder)
        if app_id == 'steam' and base:
            self._resource(app, base / 'config' / 'config.vdf', 'config', 'Steam 配置位置')
        if app_id in {'wgc', 'wgc_cn360'} and base:
            self._resource(app, base / 'preferences.xml', 'config', 'WGC 设置位置')
        if app_id == 'v2rayn' and base:
            self._resource(app, base / 'guiLogs', 'log_directory', 'v2rayN 界面日志')
            self._resource(app, base / 'guiConfigs' / 'guiNConfig.json', 'config', 'v2rayN 设置位置')
        if app_id in {'xray', 'v2ray', 'sing_box', 'mihomo', 'clash'}:
            for config in self.snapshot.get('layers', {}).get('core_configs', []):
                if config.get('app_id') == app_id and config.get('path'):
                    self._resource(app, Path(config['path']), 'config', '已发现核心配置引用')
        if 'APPDATA' in env:
            root = env['APPDATA']
            paths = {
                'rustdesk': [('RustDesk/log', 'log_directory', 'RustDesk 日志目录'), ('RustDesk/config/RustDesk2.toml', 'config', 'RustDesk 配置位置')],
                'vscode': [('Code/logs', 'log_directory', 'VS Code 日志目录'), ('Code/User/settings.json', 'config', 'VS Code 用户设置')],
                'firefox': [('Mozilla/Firefox/profiles.ini', 'config', 'Firefox 配置入口')],
                'clash_verge': [('io.github.clash-verge-rev.clash-verge-rev/logs', 'log_directory', 'Clash Verge Rev 日志候选目录')],
            }
            for relative, kind, label in paths.get(app_id, []):
                self._resource(app, root / relative, kind, label)
        if 'LOCALAPPDATA' in env:
            root = env['LOCALAPPDATA']
            for browser, relative in (('chrome', 'Google/Chrome/User Data'), ('edge', 'Microsoft/Edge/User Data')):
                if app_id == browser:
                    self._resource(app, root / relative / 'chrome_debug.log', 'log', '浏览器调试日志（需应用启用）')
                    self._resource(app, root / relative / 'Local State', 'config', '浏览器配置位置')
        if app_id == 'git' and 'USERPROFILE' in env:
            self._resource(app, env['USERPROFILE'] / '.gitconfig', 'config', 'Git 用户配置位置')
        if app_id == 'flowdesk' and self.data_root:
            self._resource(app, self.data_root / '.local' / 'history.json', 'log', '流向操作审计')
            self._resource(app, self.data_root / '.local' / 'plan.json', 'config', '流向保存方案')

    def _build(self):
        known = {str(app['id']): dict(app) for app in self.snapshot.get('apps', []) if isinstance(app, dict) and app.get('id')}
        if self.snapshot.get('platform') == 'windows':
            from .hermes_adapter import default_desktop
            desktop = default_desktop({k: str(v) for k, v in self.roots.items()})
            if desktop:
                known.setdefault('hermes', {'id': 'hermes', 'name': 'Hermes', 'category': 'application',
                                            'running_processes': [], 'installed_locations': []})
                known['hermes']['_installed_main'] = desktop
        groups = {}
        for process in self.snapshot.get('network_processes', [])[:512]:
            if not isinstance(process, dict):
                continue
            app_id = process.get('app_id')
            if not app_id:
                identity = _key(process['executable']) if process.get('executable') else str(process.get('name', '')).casefold()
                app_id = 'process-' + hashlib.sha256(identity.encode()).hexdigest()[:16]
            app_id = str(app_id)
            groups.setdefault(app_id, []).append(process)
            if app_id not in known:
                known[app_id] = {'id': app_id, 'name': process.get('name') or '未知联网进程',
                                 'category': 'application', 'running_processes': [], 'installed_locations': []}
            seen = {entry.get('pid') for entry in known[app_id].get('running_processes', [])}
            if process.get('pid') not in seen:
                known[app_id].setdefault('running_processes', []).append({key: process.get(key) for key in ('pid', 'name', 'executable', 'parent_pid')})
        for record in self.manual_apps:
            candidates = [app_id for app_id, app in known.items() if _matches_manual_path(app, record['executable'])]
            matched = next((app_id for app_id in candidates if not known[app_id].get('_manual_record')), None)
            if matched is None:
                matched = record['id']
                if candidates:
                    source_id, registered = candidates[0], _key(record['executable'])
                    source = known[source_id]
                    known[matched] = {'id': matched, 'name': record['name'],
                                      'category': source.get('category', 'application'),
                                      'running_processes': [entry for entry in source.get('running_processes', [])
                                                            if entry.get('executable') and _key(entry['executable']) == registered],
                                      'installed_locations': list(source.get('installed_locations', [])),
                                      '_capability_id': source.get('_capability_id') or source_id}
                    groups[matched] = [entry for entry in groups.get(source_id, [])
                                       if entry.get('executable') and _key(entry['executable']) == registered]
                else:
                    known[matched] = {'id': matched, 'name': record['name'], 'category': 'application',
                                      'running_processes': [], 'installed_locations': [],
                                      '_capability_id': _capability_id(record['executable'])}
            known[matched]['_manual_record'] = record
            known[matched]['_detected_name'] = known[matched].get('name')
            known[matched]['name'] = record['name']
        if self.data_root:
            known.setdefault('flowdesk', {'id': 'flowdesk', 'name': '流向 · 本工具', 'category': 'tool', 'running_processes': [], 'installed_locations': []})
        for app_id, original in sorted(known.items(), key=lambda pair: str(pair[1].get('name', pair[0])).casefold()):
            processes = original.get('running_processes', [])[:256]
            manual = original.get('_manual_record')
            capability_id = original.get('_capability_id') or app_id
            executable, resource_base, helpers_only = _application_executable(capability_id, processes)
            if not executable and original.get('_installed_main'):
                executable = original['_installed_main']
                resource_base, helpers_only = Path(executable).parent, False
            if capability_id == 'hermes' and not manual:
                from .hermes_adapter import installation
                desktop = next((entry.get('executable') for entry in processes
                                if entry.get('executable') and installation(entry['executable'])), None)
                desktop = desktop or original.get('_installed_main')
                executable = desktop
                resource_base = Path(desktop).parent if desktop else resource_base
                helpers_only = not bool(desktop)
            if manual:
                selected = manual['executable']
                main_names = _MAIN_EXES.get(capability_id)
                if main_names and Path(selected).name.casefold() not in main_names:
                    executable, resource_base, helpers_only = None, Path(selected).parent, True
                else:
                    executable, resource_base, helpers_only = selected, Path(selected).parent, False
            protected = (app_id in _PROTECTED or capability_id in _PROTECTED
                         or original.get('category') in ('proxy', 'accelerator', 'tunnel')
                         or any(Path(str(entry.get('executable') or entry.get('name') or '')).name.casefold() in _PROTECTED_EXES for entry in processes)
                         or bool(manual and Path(manual['executable']).name.casefold() in _PROTECTED_EXES))
            available = bool(executable and not protected)
            if executable:
                exists, info, _ = _path_record(executable)
                available = available and exists and bool(info and stat.S_ISREG(info.st_mode))
            modes = [{'id': 'clear_environment', 'label': '仅清除新进程代理环境', 'notice': '只清理新进程的代理变量，应用自身代理、系统代理与 TUN 仍可能生效。'},
                     {'id': 'http_environment', 'label': '设置新进程 HTTP 代理环境', 'notice': '同时启用 Electron 下载器代理兼容；仅影响新进程及继承环境的子进程，是否采用由具体软件决定。'}]
            if Path(executable or '').name.casefold() in {'curl.exe', 'git.exe'}:
                modes.append({'id': 'socks_environment', 'label': '设置新进程 SOCKS 环境', 'notice': '通过 ALL_PROXY 提供 SOCKS5h；仅为支持该变量的 curl/Git 传输提供入口。'})
            app = {'id': app_id, 'name': _text(original.get('name') or app_id, 140),
                   'manual': bool(manual), 'manual_id': manual['id'] if manual else None,
                   'executable': manual['executable'] if manual else executable,
                   'detected_name': original.get('_detected_name') if manual else None,
                   'category': original.get('category', 'application'), 'protected': protected,
                   'running_processes': [{key: item.get(key) for key in ('pid', 'name', 'executable', 'parent_pid') if item.get(key) is not None} for item in processes],
                   'installed_locations': [{key: _text(item.get(key), 500) if isinstance(item.get(key), str) else item.get(key)
                                            for key in ('display_name', 'path', 'version', 'source', 'execution_verified') if key in item}
                                           for item in original.get('installed_locations', [])[:16] if isinstance(item, dict)],
                   'connection_summary': _connection_summary(original, groups.get(app_id, [])),
                   'effective_proxy': 'unknown', 'capabilities': ['查看分层设置线索', '查看 TCP 对端证据', '定位配置与日志'],
                   'settings': redact(_settings(self.snapshot, capability_id)), 'resources': [],
                   'launch_profile': {'available': available, 'executable': executable,
                                      'modes': modes if available else [],
                                      'notice': ('当前工作连接或网络基础组件受保护，不生成重新启动脚本。' if protected else
                                                 '仅观察到辅助进程，尚未确认主程序；先启动主程序并重新检测。' if helpers_only else
                                                 '已登记的程序路径当前失效或不可读取；登记仍保留，可移除后重新添加。' if manual and not available else
                                                 '尚未发现可验证的程序路径；先启动目标应用并重新检测。' if not available else
                                                 '只下载可审查脚本，不会执行；脚本只为新进程设置环境。')},
                   'limitations': ['未读取此进程的私有环境、代理参数或认证；当前有效代理保持未知。',
                                   '未内置专有适配器的应用需使用其原生设置，或另行选择支持进程规则的代理工具。']}
            self._apps[app_id] = app
            self._locations(app, base=resource_base, capability_id=capability_id)

    def describe(self):
        apps = deepcopy(list(self._apps.values()))
        for app in apps:
            if app['manual']:
                exists, info, _ = _path_record(app['executable'])
                if not exists or not info or not stat.S_ISREG(info.st_mode):
                    app['launch_profile'].update(available=False, modes=[],
                        notice='已登记的程序路径当前失效或不可读取；登记仍保留，可移除后重新添加。')
        return {'schema_version': 1, 'generated_at': _now(), 'apps': apps,
                'limitations': ['设置来源、TCP 观察、日志与实际出口分别展示，未确定项不会判定为直连或代理成功。',
                                '本页不修改 WinHTTP、持久环境、应用配置、TUN 或现有进程。日志/配置候选位置不代表应用正在使用。']}

    def _registered(self, app_id, resource_id):
        entry = self._resources.get(resource_id) if isinstance(resource_id, str) else None
        if not isinstance(app_id, str) or not entry or entry['app_id'] != app_id:
            raise ValueError('资源不属于当前应用或已过期，请重新检测后选择')
        try:
            path = _checked(entry['path'])
            info = path.lstat()
        except OSError as exc:
            raise ValueError('资源已消失或不可读取，请重新检测') from exc
        if _identity(info) != entry['identity']:
            raise ValueError('资源已轮转或被替换，请重新检测后选择')
        return entry, path, info

    def tail(self, app_id, resource_id, max_bytes=16384):
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or not 1 <= max_bytes <= _MAX_BYTES:
            raise ValueError('日志读取范围必须为 1–65536 字节')
        entry, path, info = self._registered(app_id, resource_id)
        if not entry['public']['can_tail'] or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('此资源仅允许定位，不返回配置内容或非独立日志')
        with path.open('rb') as stream:
            opened = os.fstat(stream.fileno())
            if _identity(opened) != _identity(info) or opened.st_nlink != 1:
                raise ValueError('日志在打开时改变，请重新检测')
            offset = max(0, opened.st_size - max_bytes)
            stream.seek(offset)
            data = stream.read(max_bytes)
            final = _checked(path).lstat()
            if _identity(final) != _identity(opened) or final.st_nlink != 1:
                raise ValueError('日志在读取时轮转，请重新检测')
        if b'\0' in data:
            raise ValueError('该日志不是可安全展示的普通文本')
        if offset:
            # A fragment can begin inside a credential value whose field name
            # is outside this bounded read.  Return only complete log lines.
            data = data.split(b'\n', 1)[1] if b'\n' in data else b''
        content = _log_redact(data.decode('utf-8-sig', errors='replace'))
        return {'app_id': app_id, 'resource_id': resource_id, 'path': str(path),
                'content': content, 'text': content, 'truncated': bool(offset), 'redacted': True,
                'notice': '有界读取并隐藏常见认证字段、节点链接和查询参数；配置文件不在日志读取范围。日志只作排查线索，不证明完整出口。'}

    def open_resource(self, app_id, resource_id, opener=None):
        entry, path, info = self._registered(app_id, resource_id)
        if not entry['public']['can_open']:
            raise ValueError('候选资源尚未发现，不能打开')
        directory = path if stat.S_ISDIR(info.st_mode) else path.parent
        directory = _checked(directory)
        if not directory.is_dir():
            raise ValueError('资源所在目录不可用')
        if opener is None:
            if os.name != 'nt':
                raise ValueError('打开本机目录仅支持 Windows')
            os.startfile(str(directory), 'explore')
        else:
            opener(str(directory))
        return {'opened': True, 'app_id': app_id, 'resource_id': resource_id, 'path': str(directory),
                'notice': '已打开资源所在目录，没有执行配置文件、日志文件或目标应用。'}

    def export_launch_profile(self, app_id, mode, proxy_url='', arguments=None):
        app = self._apps.get(app_id)
        if not app or not app['launch_profile']['available']:
            raise ValueError('此应用没有可用的新进程环境脚本，或受当前连接保护')
        if mode not in {item['id'] for item in app['launch_profile']['modes']}:
            raise ValueError('所选模式不受此应用支持')
        if arguments is None:
            arguments = []
        if not isinstance(arguments, list) or len(arguments) > 32 or any(not isinstance(item, str) or len(item) > 2048 or any(ord(char) < 32 for char in item) for item in arguments):
            raise ValueError('启动参数必须为最多 32 项的纯文本数组，不含控制字符')
        try:
            executable = _checked(app['launch_profile']['executable'])
        except OSError as exc:
            raise ValueError('发现的程序路径已失效，请重新检测') from exc
        if not executable.is_file() or executable.suffix.casefold() != '.exe':
            raise ValueError('发现的程序路径已失效，请重新检测')
        endpoint = ''
        if mode != 'clear_environment':
            if not isinstance(proxy_url, str) or len(proxy_url) > 500 or any(ord(char) < 33 for char in proxy_url):
                raise ValueError('请提供不含空白或认证信息的代理 URL')
            parsed = urlsplit(proxy_url)
            allowed = {'http'} if mode == 'http_environment' else {'socks5', 'socks5h'}
            try:
                port = parsed.port
                host = parsed.hostname
            except ValueError as exc:
                raise ValueError('代理地址或端口无效') from exc
            if parsed.scheme not in allowed or not host or not port or parsed.username is not None or parsed.password is not None or parsed.path not in ('', '/') or parsed.query or parsed.fragment:
                raise ValueError('只接受显式端口的 HTTP 或 SOCKS5 入口，不含用户名、密码、路径、查询参数或片段')
            try:
                ipaddress.ip_address(host)
            except ValueError:
                if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', host):
                    raise ValueError('代理主机名无效')
            endpoint = parsed.scheme + '://' + ('[' + host + ']' if ':' in host else host) + ':' + str(port)
        quote = lambda value: "'" + value.replace("'", "''") + "'"
        lines = [
            '# FlowDesk: reviewable new-process environment profile. Windows PowerShell 5.1+.',
            '# Only this newly created process receives the environment below.',
            '# Existing app instances, system proxy, TUN and persistent environment remain unchanged.',
            'param([switch]$Launch)', "$ErrorActionPreference = 'Stop'",
            '$taskExe = ' + quote(str(executable)),
            '$taskArguments = ' + quote(subprocess.list2cmdline(arguments)),
            'if (-not $Launch) {',
            "    Write-Host 'Review this file, then run it with -Launch to start the selected application.'",
            '    Write-Host $taskExe', '    return', '}',
            "if (-not (Test-Path -LiteralPath $taskExe -PathType Leaf)) { throw 'Application path no longer exists.' }",
        ]
        if executable.name.casefold() not in _CLI_EXES:
            lines += [
                '$taskExisting = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {',
                '    try { $_.Path -and $_.Path.Equals($taskExe, [System.StringComparison]::OrdinalIgnoreCase) } catch { $false }',
                '})',
                "if ($taskExisting.Count) { throw 'Close the selected application yourself before starting a new instance. No process was stopped.' }",
            ]
        lines += [
            '$taskStart = New-Object System.Diagnostics.ProcessStartInfo',
            '$taskStart.FileName = $taskExe', '$taskStart.Arguments = $taskArguments',
            '$taskStart.WorkingDirectory = Split-Path -Parent $taskExe', '$taskStart.UseShellExecute = $false',
        ]
        lines += ["$taskStart.EnvironmentVariables.Remove(" + quote(name) + ')' for name in _PROXY_NAMES]
        if mode == 'http_environment':
            lines += ['# Enable proxy support in Electron downloaders, including older global-agent versions.']
        lines += ["$taskStart.EnvironmentVariables[" + quote(name) + '] = ' + quote(value)
                  for name, value in proxy_assignments(mode, endpoint).items()]
        lines += ['$taskProcess = [System.Diagnostics.Process]::Start($taskStart)',
                  'Write-Host ("Started selected app. PID: " + $taskProcess.Id)',
                  "Write-Host 'Environment only. Verify the application connection and logs separately.'", '']
        return {'filename': 'FlowDesk-' + re.sub(r'[^A-Za-z0-9_-]', '_', app_id)[:48] + '-' + mode + '.ps1',
                'mime': 'text/plain; charset=utf-8', 'content': '\r\n'.join(lines),
                'notice': '已生成脚本供审查和下载，没有执行。脚本默认只显示说明；使用 -Launch 才创建目标新进程。',
                'limitations': ['清除或设置环境变量不等于强制任意程序直连/代理；应用配置、系统代理和 TUN 仍可能生效。',
                                '不会停止现有进程；可能复用旧实例的应用必须先自行退出。',
                                '目标进程仍需按应用支持方式验证代理入口和实际请求。']}
