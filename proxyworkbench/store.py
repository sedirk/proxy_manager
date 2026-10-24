from datetime import datetime, timezone
import json
from pathlib import Path
import threading
from urllib.parse import urlsplit
from .system_proxy import atomic_json
from .privacy import redact


def now():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()

    def read(self, name, default=None):
        path = self.root / name
        with self.lock:
            return json.loads(path.read_text(encoding='utf-8')) if path.exists() else default

    def write(self, name, value):
        if name not in ('plan.json', 'snapshot.json', 'history.json', 'custom-apps.json', 'app-routes.json'):
            raise ValueError('未支持的状态文件')
        with self.lock:
            atomic_json(self.root / name, value)

    def audit(self, event, detail=None):
        with self.lock:
            history = self.read('history.json', [])
            history.append({'time': now(), 'event': event, 'detail': redact(detail or {})})
            self.write('history.json', history[-500:])


def default_plan(snapshot=None):
    """Templates are hypotheses until a real app uses the running channel."""
    endpoints = (snapshot or {}).get('endpoints', [])
    candidates = [e for e in endpoints if e.get('declared_protocol') in ('http', 'mixed', 'socks', 'socks5')
                  and e.get('address') in ('127.0.0.1', '::1', '0.0.0.0', '::')]
    current = (snapshot or {}).get('layers', {}).get('wininet', {}).get('proxy_server', '') or ''
    preferred_host, preferred_port = None, None
    try:
        first = current.split(';', 1)[0].split('=', 1)[-1]
        parsed = urlsplit(first if '://' in first else 'http://' + first)
        preferred_host, preferred_port = parsed.hostname, parsed.port
    except ValueError:
        pass
    candidates.sort(key=lambda e: (e.get('port') != preferred_port,
                                  e.get('declared_protocol') not in ('http', 'mixed'), e.get('port', 65536)))
    upstream = None
    targets = [
        {'id': 'direct', 'name': '直连 · 系统路由', 'type': 'direct'},
        {'id': 'block', 'name': '阻断', 'type': 'block'},
    ]
    if candidates:
        found = candidates[0]
        upstream = 'local-proxy'
        host = '::1' if found['address'] == '::1' else '127.0.0.1'
        if found['address'] == '::' and preferred_host == '::1':
            host = '::1'
        targets.append({'id': upstream, 'name': f"已有代理 · {found.get('owner', '本机')}:{found['port']}",
                        'type': 'http' if found['declared_protocol'] in ('http', 'mixed') else 'socks5',
                        'host': host, 'port': found['port']})
    proxy = upstream or 'block'
    return {'version': 1, 'id': 'default', 'name': '游戏直连 · 工作连接保留', 'targets': targets,
            'channels': [
                {'id': 'system', 'name': '系统 / 浏览器', 'app_id': 'browser', 'default_target': proxy,
                 'rules': [{'id': 'steam-download', 'domains': ['steamcontent.com', '*.steamcontent.com'], 'target': 'direct'}]},
                {'id': 'steam', 'name': 'Steam 社区与下载', 'app_id': 'steam', 'default_target': proxy,
                 'rules': [{'id': 'steam-download', 'domains': ['steamcontent.com', '*.steamcontent.com'], 'target': 'direct'}]},
                {'id': 'wows-wg', 'name': 'WoWS · WG 更新', 'app_id': 'wows_wg', 'default_target': 'direct', 'rules': []},
                {'id': 'wows-cn', 'name': 'WoWS · 国服更新', 'app_id': 'wows_cn360', 'default_target': 'direct', 'rules': []},
                {'id': 'wows-steam', 'name': 'WoWS · Steam 更新', 'app_id': 'wows_steam', 'default_target': 'direct', 'rules': []},
                {'id': 'rustdesk', 'name': 'RustDesk · 兼容通道', 'app_id': 'rustdesk', 'default_target': 'direct', 'rules': []},
            ], 'layout': {},
            'notes': ['Codex 当前进程、环境变量和代理核心保持不变。',
                      'Steam 下载域名是起始模板；新 CDN 需结合活动记录补充，不代表全部下载已直连。',
                      'WoWS 更新前仍需在资源切换器完成文件隔离。',
                      'RustDesk 的 UDP/打洞和真实远程会话未由 TCP 中继验证。']}
