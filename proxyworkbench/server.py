"""Loopback-only control plane. No cross-origin API and no arbitrary files."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
from pathlib import Path
import secrets
import threading
from urllib.parse import urlsplit, parse_qs

from . import __version__
from .service import Service
from . import probes


class ControlServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address, root, *, discover=True, service=None):
        if address[0] != '127.0.0.1':
            raise ValueError('Control API must bind only to 127.0.0.1')
        super().__init__(address, Handler)
        self.root = Path(root)
        self.token = secrets.token_urlsafe(32)
        self.instance_id = secrets.token_hex(16)
        self.service = service or Service(root, self.server_port, discover=discover)
        self.api_slots = threading.BoundedSemaphore(24)


class Handler(BaseHTTPRequestHandler):
    server_version = 'ProxyPatchbay'
    sys_version = ''
    protocol_version = 'HTTP/1.0'

    def setup(self):
        super().setup()
        self.connection.settimeout(12)

    def log_message(self, *args):
        pass

    def reply(self, status, value, mime='application/json; charset=utf-8'):
        data = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; connect-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def authorized(self, path):
        allowed = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
        host = self.headers.get('Host', '')
        if host not in allowed:
            self.reply(403, {'error': '无效的本机控制地址'})
            return False
        origin = self.headers.get('Origin')
        if origin and origin != 'http://' + host:
            self.reply(403, {'error': '禁止跨站控制'})
            return False
        if self.headers.get('Sec-Fetch-Site') == 'cross-site':
            self.reply(403, {'error': '禁止跨站访问'})
            return False
        public = self.command == 'GET' and path in ('/', '/index.html', '/app.js', '/styles.css', '/api/session', '/api/health')
        if not public and not hmac.compare_digest(self.headers.get('X-Session-Token', ''), self.server.token):
            self.reply(403, {'error': '会话已失效，请重新打开页面'})
            return False
        return True

    def do_GET(self):
        self.dispatch()

    def do_POST(self):
        self.dispatch()

    def do_PUT(self):
        self.dispatch()

    def dispatch(self):
        parsed = urlsplit(self.path)
        path = parsed.path
        if not self.authorized(path):
            return
        if not self.server.api_slots.acquire(blocking=False):
            self.reply(429, {'error': '本机服务繁忙，请稍后重试'})
            return
        try:
            if self.command == 'GET' and path in ('/', '/index.html', '/styles.css', '/app.js'):
                filename = 'index.html' if path == '/' else path[1:]
                mime = {'index.html': 'text/html; charset=utf-8', 'app.js': 'text/javascript; charset=utf-8', 'styles.css': 'text/css; charset=utf-8'}[filename]
                self.reply(200, (self.server.root / 'web' / filename).read_bytes(), mime)
                return
            value = {}
            if self.command in ('POST', 'PUT'):
                if self.headers.get('Transfer-Encoding'):
                    raise ValueError('控制 API 不接受分块请求')
                if self.headers.get_content_type() != 'application/json':
                    raise ValueError('请求必须使用 application/json')
                lengths = self.headers.get_all('Content-Length', [])
                if len(lengths) != 1:
                    raise ValueError('请求必须有唯一的 Content-Length')
                length = int(lengths[0])
                if not 0 < length <= 1048576:
                    raise ValueError('请求必须小于 1 MiB')
                value = json.loads(self.rfile.read(length))
                if not isinstance(value, dict):
                    raise ValueError('请求必须是 JSON 对象')
            service = self.server.service
            key = (self.command, path)
            if key == ('GET', '/api/session'):
                result = {'token': self.server.token, 'version': __version__}
            elif key == ('GET', '/api/health'):
                result = {'app': 'proxy-patchbay', 'version': __version__, 'instance_id': self.server.instance_id}
            elif key == ('GET', '/api/state'):
                result = service.state()
            elif key == ('GET', '/api/events'):
                after = int(parse_qs(parsed.query).get('after_id', ['0'])[0])
                result = {'events': service.relay.events(after_id=after), 'runtime': service.relay.status()}
            elif key == ('POST', '/api/discover'):
                result = service.discover()
            elif key == ('PUT', '/api/plan'):
                result = service.save_plan(value.get('plan', value))
            elif key == ('POST', '/api/preview'):
                result = service.preview(value.get('plan', service.plan))
            elif key == ('POST', '/api/runtime/start'):
                result = service.start(value.get('plan', service.plan))
            elif key == ('POST', '/api/runtime/stop'):
                result = service.stop()
            elif key == ('POST', '/api/probe'):
                result = service.probe(value)
            elif key == ('POST', '/api/resolve'):
                result = probes.resolve(value.get('host', ''))
            elif key == ('POST', '/api/export'):
                result = service.export(value.get('kind', 'diagnostics'), value.get('plan'))
            elif key == ('POST', '/api/system/preview'):
                result = service.system_preview(value.get('channel_id'))
            elif key == ('POST', '/api/system/apply'):
                result = service.system_apply(value.get('preview_id'))
            elif key == ('POST', '/api/system/confirm'):
                result = service.system_confirm(value.get('lease_id'))
            elif key == ('POST', '/api/system/restore'):
                result = service.system_restore(value.get('lease_id'))
            elif key == ('POST', '/api/shutdown'):
                service.close()
                result = {'closed': True}
                threading.Thread(target=self.server.shutdown, daemon=True).start()
            else:
                self.reply(404, {'error': '接口不存在'})
                return
            self.reply(200, result)
        except (ValueError, KeyError, TypeError) as exc:
            self.reply(400, {'error': str(exc)[:300]})
        except RuntimeError as exc:
            self.reply(409, {'error': str(exc)[:300]})
        except Exception as exc:
            self.reply(500, {'error': '本机操作未完成：' + type(exc).__name__})
        finally:
            self.server.api_slots.release()
