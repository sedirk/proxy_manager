"""Explicit, bounded HTTP proxy checks against an observed local listener.

The only destination is a temporary loopback challenge server owned by this
check. No internet target, application launch, or proxy configuration changes.
"""
import copy
from contextlib import contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import secrets
import socket
import threading
import time

from .network_tools import PROFILES, PROXIES, _local


def candidates(tool, deny_ports=()):
    from .discovery import _app_id
    if tool.get('id') not in PROXIES:
        return []
    result = []
    for entry in tool.get('endpoints', []):
        host, port = _local(entry.get('address')), entry.get('port')
        if (entry.get('app_id') in PROFILES or _app_id(entry.get('owner')) in PROFILES
                or entry.get('transport') != 'tcp' or not host or not isinstance(port, int)
                or isinstance(port, bool) or not 1 <= port <= 65535 or port in deny_ports
                or not entry.get('pid') or not entry.get('id')):
            continue
        result.append({**entry, 'host': host, 'tool_id': tool['id'], 'tool_name': tool['name']})
    return result[:8]


def identity(entry):
    return tuple(entry.get(key) for key in ('tool_id', 'id', 'pid', 'owner', 'address', 'port'))


def decorate(tools, verified=(), deny_ports=()):
    result = copy.deepcopy(tools)
    verified = {identity(item): item for item in verified}
    for tool in result:
        eligible = candidates(tool, deny_ports)
        tool['can_check_http'] = bool(eligible)
        options = tool.setdefault('proxy_options', [])
        for entry in eligible:
            passed = verified.get(identity(entry))
            if not passed:
                continue
            host = '[' + entry['host'] + ']' if ':' in entry['host'] else entry['host']
            url = f"http://{host}:{entry['port']}"
            option = next((item for item in options if item['proxy_url'] == url), None)
            if option is None:
                option = {'id': entry['id'], 'tool_id': tool['id'], 'tool_name': tool['name'],
                          'protocol': 'http', 'host': entry['host'], 'port': entry['port'], 'proxy_url': url}
                options.append(option)
            option.update(verified=True, source='本次 HTTP CONNECT 本机转发验证', checked_at=passed['checked_at'])
    return result


@contextmanager
def _connection(entry, deadline):
    with socket.create_connection((entry['host'], entry['port']), timeout=max(.05, min(2.5, deadline-time.monotonic()))) as stream:
        def expire():
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            stream.close()
        # HTTPResponse's per-recv timeout alone cannot stop a trickle response.
        timer = threading.Timer(max(.01, deadline-time.monotonic()), expire)
        timer.daemon = True
        timer.start()
        try:
            yield stream
        finally:
            timer.cancel()


def _forward(entry, destination, token, deadline):
    remaining = lambda: max(.05, min(2.5, deadline - time.monotonic()))
    with _connection(entry, deadline) as stream:
        stream.settimeout(remaining())
        stream.sendall(f'CONNECT 127.0.0.1:{destination} HTTP/1.1\r\nHost: 127.0.0.1:{destination}\r\n\r\n'.encode('ascii'))
        header = bytearray()
        while not header.endswith(b'\r\n\r\n') and len(header) < 8192:
            stream.settimeout(remaining())
            part = stream.recv(1)
            if not part:
                raise ValueError('端口没有完成 HTTP CONNECT 握手。')
            header.extend(part)
            if time.monotonic() >= deadline:
                raise TimeoutError()
        first = bytes(header).split(b'\r\n', 1)[0].split(b' ')
        if len(first) < 2 or first[0] not in {b'HTTP/1.0', b'HTTP/1.1'}:
            raise ValueError('此端口未返回 HTTP 代理响应；可能是 SOCKS 或专用端口。')
        if first[1] == b'407':
            raise ValueError('此代理要求身份认证；当前应用连接不支持带账号密码的入口。')
        if not header.endswith(b'\r\n\r\n') or not first[1].isdigit() or not 200 <= int(first[1]) < 300:
            raise ValueError('HTTP 握手未允许本机转发；请核对 HTTP/混合端口及代理访问规则。')
        stream.settimeout(remaining())
        stream.sendall(f'GET /{token} HTTP/1.1\r\nHost: 127.0.0.1:{destination}\r\nConnection: close\r\n\r\n'.encode('ascii'))
        response = http.client.HTTPResponse(stream)
        try:
            response.begin()
            if response.status != 200 or response.read(len(token) + 1) != token.encode('ascii'):
                raise ValueError('端口没有转发本次检测的完整响应，不能确认为可用代理。')
        finally:
            response.close()


def check(tool, deny_ports=()):
    entries = candidates(tool, deny_ports)
    if not entries:
        raise ValueError('没有可检测的本机代理监听。请先打开代理软件并点击自动检测；加速器和组网管理端口不作代理探测。')
    class Challenge(BaseHTTPRequestHandler):
        def setup(self):
            self.request.settimeout(2)
            super().setup()

        def do_GET(self):
            token, seen = self.server.challenge
            body = token.encode('ascii') if self.path == '/' + token else b''
            if body:
                seen.set()
            self.send_response(200 if body else 404)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Challenge)
    server.daemon_threads = True
    server.challenge = ('', threading.Event())
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=.05), daemon=True)
    thread.start()
    checks, passed = [], []
    deadline = time.monotonic() + 12
    try:
        for entry in entries:
            label = f"{entry['owner'] or tool['name']} · {entry['host']}:{entry['port']}"
            try:
                if time.monotonic() >= deadline:
                    raise TimeoutError()
                token = secrets.token_hex(24)
                seen = threading.Event()
                server.challenge = (token, seen)
                _forward(entry, server.server_port, token, deadline)
                if not seen.is_set():
                    raise ValueError('未观察到请求经过本机检测服务，不能确认代理转发。')
                passed.append({**entry, 'checked_at': time.time()})
                checks.append({'label': label, 'status': 'ok', 'detail': 'HTTP CONNECT 本机转发验证通过。可以作为应用代理入口；实际网站和模型回复仍需验证。'})
            except (OSError, ValueError, http.client.HTTPException) as error:
                detail = str(error) if isinstance(error, ValueError) else '本机代理转发未完成或超时。请检查代理软件的 HTTP/混合端口与访问规则。'
                checks.append({'label': label, 'status': 'warning', 'detail': detail})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    return passed, checks
