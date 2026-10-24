"""Self-contained browser fixture. Uses synthetic data and no OS settings."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from proxyworkbench.store import default_plan

TOKEN = 'fixture-token-no-authentication-material'
CALLS = []
SNAPSHOT = {'captured_at': '2026-10-24T12:00:00Z', 'apps': [], 'interfaces': [], 'endpoints': [],
            'layers': {'wininet': {'enabled': True, 'proxy_server': '127.0.0.1:10808', 'evidence_status': 'observed'},
                       'winhttp': {'access_type': 'direct', 'evidence_status': 'observed'},
                       'environment': {'process': {'values': {'HTTPS_PROXY': 'http://127.0.0.1:10808'}}}}}


def app(identifier, name, *, running=True, protected=False):
    return {'id': identifier, 'name': name, 'protected': protected,
            'running_processes': [{'pid': 321, 'name': name + '.exe', 'executable': r'C:\Fixture\curl.exe'}] if running else [],
            'installed_locations': [{'path': r'C:\Fixture', 'display_name': name}],
            'connection_summary': {'tcp_count': 1 if running else 0, 'proxy_peer_count': 0,
                'status': 'connections_observed' if running else 'none',
                'label': '观察到 TCP 连接 · 实际代理待确认' if running else '没有当前连接记录',
                'notice': '公网连接不代表已经绕过 TUN。',
                'connections': [{'pid': 321, 'remote_address': '203.0.113.10', 'remote_port': 443, 'proxy_endpoint_ids': []}] if running else []},
            'effective_proxy': 'unknown',
            'capabilities': ['应用专用设置参考', '新进程代理环境'] if not protected else ['保留当前连接'],
            'settings': [{'layer': 'wininet', 'label': 'Windows 系统代理',
                          'value': {'enabled': True, 'proxy': '127.0.0.1:10808', 'pac': 'http://127.0.0.1:8080/pac.js', 'auto_detect': False},
                          'status': 'observed', 'source': 'fixture WinINet', 'notice': '这里只观察设置，不认定该应用使用它。'},
                         {'layer': 'winhttp', 'label': 'WinHTTP 默认代理', 'value': {'mode': 'direct', 'proxy': None},
                          'status': 'observed', 'source': 'fixture WinHTTP', 'notice': '应用自己的会话可使用其他代理配置。'},
                         {'layer': 'environment_user', 'label': '用户代理环境变量', 'value': {},
                          'status': 'observed', 'source': 'fixture 用户环境', 'notice': '只说明新进程可继承的设置。'},
                         {'layer': 'environment_machine', 'label': '机器代理环境变量', 'value': {'HTTPS_PROXY': 'http://127.0.0.1:10808', 'NO_PROXY': 'localhost,127.0.0.1'},
                          'status': 'observed', 'source': 'fixture 机器环境', 'notice': '未读取正在运行的软件环境。'},
                         {'layer': 'application', 'label': '应用私有设置', 'value': '未确认',
                          'status': 'unknown', 'source': '软件自身设置', 'notice': '可结合应用日志核对。'}],
            'resources': [{'id': 'fixture-log', 'name': '应用日志', 'kind': 'log', 'path': r'C:\Fixture\logs\application.log',
                           'exists': True, 'can_tail': True, 'can_open': True},
                          {'id': 'candidate-config', 'name': '候选设置文件', 'kind': 'config', 'path': r'C:\Fixture\not-present.json',
                           'exists': False, 'can_tail': False, 'can_open': False}],
            'launch_profile': {'available': not protected, 'executable': r'C:\Fixture\curl.exe', 'modes': [
                {'id': 'clear_environment', 'label': '清除新进程的代理环境', 'notice': '只清除环境；仍可能使用系统或私有代理。'},
                {'id': 'http_environment', 'label': '指定 HTTP 代理环境', 'notice': '需要软件支持 HTTP_PROXY / HTTPS_PROXY。'}]},
            'limitations': ['未确认实际节点出口。', '不强制接管其他进程。']}


CATALOG = {'schema_version': 1, 'generated_at': SNAPSHOT['captured_at'],
           'apps': [app('curl', 'curl'), app('codex', 'Codex', protected=True),
                    app('git', 'Git', running=False), app('network-observer', '任意联网软件')],
           'limitations': ['此处全部为隔离验收样本。']}
CATALOG['apps'][-1]['settings'] = [
    {'layer': 'wininet', 'label': 'Windows 系统代理', 'value': {'enabled': None, 'proxy': None, 'pac': None, 'auto_detect': None}, 'status': 'unknown', 'source': 'fixture 采集失败', 'notice': '没有把未知读成关闭。'},
    {'layer': 'winhttp', 'label': 'WinHTTP 默认代理', 'value': {'mode': 'unknown', 'proxy': None}, 'status': 'unknown', 'source': 'fixture 采集失败', 'notice': '没有把未知读成直连。'},
    {'layer': 'environment_user', 'label': '用户代理环境变量', 'value': {}, 'status': 'unknown', 'source': 'fixture 采集失败', 'notice': '没有把未读取等同于未设置。'}]
PLAN = default_plan(None)
PLAN['name'] = '应用总览隔离验收'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, value, *, status=200, mime='application/json; charset=utf-8'):
        data = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path in ('/', '/index.html', '/app.js', '/styles.css'):
            name = 'index.html' if path == '/' else path[1:]
            mime = {'index.html': 'text/html; charset=utf-8', 'app.js': 'text/javascript; charset=utf-8', 'styles.css': 'text/css; charset=utf-8'}[name]
            self.reply((ROOT / 'web' / name).read_bytes(), mime=mime)
        elif path == '/api/session':
            self.reply({'token': TOKEN, 'version': 'fixture'})
        elif path == '/api/state':
            self.reply({'plan': PLAN, 'snapshot': SNAPSHOT, 'runtime': {'running': False, 'channels': []}, 'history': [], 'system': {'state': 'detached'}})
        elif path == '/api/catalog':
            self.reply(CATALOG)
        elif path == '/api/events':
            self.reply({'events': [], 'runtime': {'running': False, 'channels': []}})
        elif path == '/fixture/calls':
            self.reply(CALLS)
        else:
            self.reply({'error': 'fixture 接口不存在'}, status=404)

    def do_POST(self):
        if self.headers.get('X-Session-Token') != TOKEN:
            self.reply({'error': 'fixture token missing'}, status=403)
            return
        body = json.loads(self.rfile.read(min(int(self.headers.get('Content-Length', 0)), 1_048_576)))
        CALLS.append({'path': self.path, 'body': body})
        if self.path == '/api/catalog/resource':
            if body.get('action') == 'tail':
                self.reply({'content': 'Connected to 127.0.0.1:10808\nAuthorization=<已隐藏>\n<script>fixture_untrusted_log()</script>', 'notice': '隔离样本 · 只显示脱敏日志尾部', 'redacted': True})
            else:
                self.reply({'opened': True, 'notice': '隔离样本，没有调用资源管理器'})
        elif self.path == '/api/catalog/launch-profile':
            self.reply({'filename': 'fixture-launch.ps1', 'mime': 'text/plain; charset=utf-8',
                        'content': '# 隔离验收脚本，仅用于预览\n# 不执行任何启动操作\n',
                        'notice': '已生成脚本；本次没有启动或修改现有软件。', 'limitations': ['新进程环境不等于强制代理。']})
        elif self.path == '/api/discover':
            self.reply({'snapshot': SNAPSHOT, 'discovering': False})
        elif self.path == '/api/shutdown':
            self.reply({'closed': True})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
        else:
            self.reply({'error': '隔离样本禁止运行网络或设置操作'}, status=409)


if __name__ == '__main__':
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    details = {'port': server.server_port, 'url': f'http://127.0.0.1:{server.server_port}', 'isolated': True}
    (ROOT / 'artifacts').mkdir(exist_ok=True)
    (ROOT / 'artifacts/catalog-ui-fixture.json').write_text(json.dumps(details), encoding='utf-8')
    print(json.dumps(details), flush=True)
    try:
        server.serve_forever(poll_interval=.2)
    finally:
        server.server_close()
