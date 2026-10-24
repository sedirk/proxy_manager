"""User-triggered, bounded probes. Never use ambient proxy environment."""
import base64
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import hashlib
import ipaddress
import math
import os
from pathlib import Path
import secrets
import re
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit
from .policy import normalize_host

_dns = ThreadPoolExecutor(max_workers=4, thread_name_prefix='bounded-dns')
_dns_slots = threading.BoundedSemaphore(8)
_TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")


def host_name(value):
    try:
        return normalize_host(value)
    except (TypeError, ValueError, UnicodeError):
        raise ValueError('请输入单独域名或 IP，不包含 URL、端口或命令') from None


def resolve(host, *, timeout=6):
    host = host_name(host)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not .05 <= timeout <= 30:
        raise ValueError('DNS timeout must be between .05 and 30 seconds')
    started = time.monotonic()
    entries = []
    hosts_file = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/drivers/etc/hosts' if os.name == 'nt' else Path('/etc/hosts')
    try:
        with hosts_file.open('rb') as stream:
            content = stream.read(2 * 1024 * 1024 + 1)
        if len(content) > 2 * 1024 * 1024:
            raise ValueError('hosts file too large')
        for line in content.decode('utf-8-sig', errors='replace').splitlines():
            fields = line.split('#', 1)[0].split()
            if len(fields) > 1 and host in [v.lower().rstrip('.') for v in fields[1:]]:
                try:
                    entries.append(str(ipaddress.ip_address(fields[0])))
                except ValueError:
                    continue
    except (OSError, ValueError):
        pass
    if not _dns_slots.acquire(blocking=False):
        addresses, status, error = [], 'failed', 'ResolverBusy'
    else:
        try:
            future = _dns.submit(socket.getaddrinfo, host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            future.add_done_callback(lambda _: _dns_slots.release())
            addresses = sorted({item[4][0] for item in future.result(timeout=timeout)})
            status, error = ('passed', None) if addresses else ('failed', 'NoAddresses')
        except (OSError, TimeoutError) as exc:
            future.cancel()
            addresses, status, error = [], 'failed', type(exc).__name__
    return {'host': host, 'status': status, 'addresses': addresses, 'hosts_entries': sorted(set(entries)),
            'elapsed_ms': round((time.monotonic()-started)*1000), 'error': error,
            'scope': '当前进程使用的系统解析；代理端解析结果未知',
            'notice': 'HTTP CONNECT / SOCKS5 按域名交给代理端解析时，可能不使用本机 hosts。可把指定 hosts 项加入本方案的静态 DNS 映射。'}


def _response(sock, remaining, buffered=b''):
    data = bytearray(buffered)
    while True:
        boundary = data.find(b'\r\n\r\n')
        if boundary >= 0:
            if boundary + 4 > 32768:
                raise ValueError('response_header_limit')
            break
        if len(data) >= 32768:
            raise ValueError('response_header_limit')
        sock.settimeout(remaining())
        block = sock.recv(min(4096, 32768 - len(data)))
        if not block:
            raise ConnectionError('incomplete_response_headers')
        data.extend(block)
    lines = bytes(data[:boundary]).split(b'\r\n')
    status = re.fullmatch(rb'HTTP/1\.[01] ([1-5][0-9]{2})(?: [^\x00-\x1f\x7f]*)?', lines[0])
    if not status:
        raise ValueError('invalid_http_status')
    headers = {}
    for line in lines[1:]:
        if b':' not in line or line.startswith((b' ', b'\t')):
            raise ValueError('malformed_response_header')
        name, value = line.split(b':', 1)
        if not _TOKEN.fullmatch(name) or any(byte < 32 and byte != 9 or byte == 127 for byte in value):
            raise ValueError('malformed_response_header')
        headers.setdefault(name.lower(), []).append(value.strip(b' \t'))
    if (len(headers.get(b'content-length', [])) > 1 or len(headers.get(b'transfer-encoding', [])) > 1
            or (b'content-length' in headers and b'transfer-encoding' in headers)
            or (b'content-length' in headers and not re.fullmatch(rb'[0-9]{1,20}', headers[b'content-length'][0]))):
        raise ValueError('ambiguous_response_framing')
    return int(status[1]), headers, bytes(data[boundary+4:])


def probe(url, target, *, timeout=8, mode='http', forbidden_ports=()):
    from .relay import RelayError, connect_target
    if not isinstance(url, str) or any(ord(character) < 33 for character in url):
        raise ValueError('探测 URL 无效')
    parsed = urlsplit(url)
    if parsed.scheme not in ('http', 'https', 'ws', 'wss') or not parsed.hostname:
        raise ValueError('探测目标需要 http(s):// 或 ws(s):// URL')
    if parsed.username is not None or parsed.password is not None or '?' in url or '#' in url:
        raise ValueError('探测 URL 不接受认证信息、查询参数或片段；不会读取应用登录令牌')
    host = host_name(parsed.hostname)
    port = parsed.port if parsed.port is not None else (443 if parsed.scheme in ('https', 'wss') else 80)
    if not 1 <= port <= 65535:
        raise ValueError('探测端口需在 1–65535 之间')
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not .05 <= timeout <= 30:
        raise ValueError('探测总超时需在 .05–30 秒内')
    if mode not in ('http', 'websocket'):
        raise ValueError('探测模式无效')
    path = parsed.path or '/'
    if len(path) > 2048 or not path.isascii():
        raise ValueError('探测路径需使用不超过 2048 字符的 ASCII URL 编码')
    websocket = mode == 'websocket' or parsed.scheme in ('ws', 'wss')
    result = {'host': host, 'port': port, 'route': target.get('id', target.get('type')),
              'layers': [], 'application': 'unknown', 'long_lived_connection': 'not_tested',
              'scope': '此探测进程，不代表目标应用当前已使用同一路径'}
    sock = None
    stage, started = 'tcp', time.monotonic()
    probe_started = started
    deadline = started + timeout
    def remaining():
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError('probe_deadline')
        return left
    try:
        sock = connect_target(target, host, port, timeout=remaining(), forbidden_ports=forbidden_ports)
        result['layers'].append({'layer': 'tcp', 'status': 'passed', 'elapsed_ms': round((time.monotonic()-started)*1000),
                                 'peer': list(sock.getpeername()[:2]), 'local': list(sock.getsockname()[:2])})
        if parsed.scheme in ('https', 'wss'):
            stage, started = 'tls', time.monotonic()
            sock.settimeout(remaining())
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
            result['layers'].append({'layer': 'tls', 'status': 'passed', 'elapsed_ms': round((time.monotonic()-started)*1000),
                                     'version': sock.version(), 'certificate_verification': True})
        stage, started = 'websocket' if websocket else 'http', time.monotonic()
        authority = f'[{host}]' if ':' in host else host
        default_port = 443 if parsed.scheme in ('https', 'wss') else 80
        authority += f':{port}' if port != default_port else ''
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        if websocket:
            request = f'GET {path} HTTP/1.1\r\nHost: {authority}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n'
        else:
            request = f'HEAD {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: ProxyPatchbay-Probe/0.1\r\nConnection: close\r\n\r\n'
        sock.settimeout(remaining())
        sock.sendall(request.encode('ascii'))
        buffered = b''
        for _ in range(9):
            code, headers, buffered = _response(sock, remaining, buffered)
            if code >= 200 or code == 101:
                break
        else:
            raise ValueError('too_many_interim_responses')
        valid = code != 101
        if websocket:
            # RFC 6455 section 4.1 also requires Connection: Upgrade and rejects
            # duplicate accept values or unrequested extensions/subprotocols.
            expected = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
            accepts, upgrades = headers.get(b'sec-websocket-accept', []), headers.get(b'upgrade', [])
            tokens = {token.strip().lower() for value in headers.get(b'connection', []) for token in value.split(b',')}
            valid = (code == 101 and len(accepts) == 1 and accepts[0] == expected
                     and len(upgrades) == 1 and upgrades[0].lower() == b'websocket' and b'upgrade' in tokens
                     and b'sec-websocket-protocol' not in headers and b'sec-websocket-extensions' not in headers)
            if valid:
                sock.settimeout(remaining())
                sock.sendall(b'\x88\x80' + secrets.token_bytes(4))
        result['layers'].append({'layer': stage, 'status': 'passed' if valid else 'failed', 'http_status': code,
                                 'elapsed_ms': round((time.monotonic()-started)*1000),
                                 'meaning': '只确认升级握手，不代表持续连接或应用功能' if websocket else '收到 HTTP 响应；401/403/405 等不代表业务功能成功'})
    except Exception as exc:
        if isinstance(exc, RelayError):
            stage, error_code = exc.stage, exc.code
        elif isinstance(exc, (TimeoutError, socket.timeout)):
            error_code = 'probe_timeout'
        elif isinstance(exc, ssl.SSLCertVerificationError):
            error_code = 'tls_certificate_verification_failed'
        elif isinstance(exc, ssl.SSLError):
            error_code = 'tls_handshake_failed'
        elif isinstance(exc, ValueError):
            error_code = 'malformed_protocol_response'
        else:
            error_code = 'connection_closed_or_failed'
        result['layers'].append({'layer': stage, 'status': 'failed', 'error_type': type(exc).__name__,
                                 'error_code': error_code, 'message': '该层探测未通过；未记录响应内容、URL 路径或认证信息'})
    finally:
        if sock:
            sock.close()
    result['transport_passed'] = bool(result['layers']) and all(item['status'] == 'passed' for item in result['layers'])
    result['elapsed_ms'] = round((time.monotonic() - probe_started) * 1000)
    return result
