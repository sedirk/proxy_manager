"""Only local mock HTTP/echo/proxy sockets are used; no external services."""
import contextlib
import http.server
import ipaddress
import json
import select
import socket
import socketserver
import struct
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from proxyworkbench.relay import RelayError, RelayManager, _bind_interface, connect_target


def exact(sock, size):
    data = bytearray()
    while len(data) < size:
        block = sock.recv(size - len(data))
        if not block:
            raise EOFError()
        data.extend(block)
    return bytes(data)


def headers(sock):
    data = bytearray()
    while not data.endswith(b"\r\n\r\n"):
        data.extend(exact(sock, 1))
    return bytes(data)


def bridge(left, right):
    while True:
        ready, _, _ = select.select([left, right], [], [], 3)
        if not ready:
            return
        for source in ready:
            data = source.recv(65536)
            if not data:
                return
            (right if source is left else left).sendall(data)


class TCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    def handle_error(self, request, client_address):
        pass


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(65536):
            self.request.sendall(data)


class HTTP(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *args):
        pass
    def do_GET(self):
        if self.path == "/chunked":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.write(b"5\r\nhello\r\n0\r\nX-Fixture: trailer\r\n\r\n")
            return
        self.send_response(200)
        self.send_header("Content-Length", "5")
        self.end_headers()
        self.wfile.write(b"hello")
    def do_POST(self):
        if self.headers.get("Transfer-Encoding") == "chunked":
            body = bytearray()
            while True:
                size = int(self.rfile.readline().split(b";", 1)[0], 16)
                if not size:
                    while self.rfile.readline() != b"\r\n":
                        pass
                    break
                body.extend(self.rfile.read(size))
                assert self.rfile.read(2) == b"\r\n"
            body = bytes(body)
        else:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.received.append({"body": body, "path": self.path,
                                     "host": self.headers.get("Host"),
                                     "authorization": self.headers.get("Authorization"),
                                     "proxy_auth": self.headers.get("Proxy-Authorization")})
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class HTTPProxy(socketserver.BaseRequestHandler):
    def handle(self):
        header = headers(self.request)
        first, _, rest = header.partition(b"\r\n")
        method, target, version = first.split(b" ")
        self.server.received.append(header)
        if method == b"CONNECT":
            host, port = target.decode().rsplit(":", 1)
            peer = socket.create_connection((host.strip("[]"), int(port)), timeout=2)
            self.request.sendall(b"HTTP/1.1 200 Connected\r\n\r\n")
        else:
            parsed = urlsplit(target.decode())
            peer = socket.create_connection((parsed.hostname, parsed.port or 80), timeout=2)
            peer.sendall(method + b" " + (parsed.path or "/").encode() + b" " + version + b"\r\n" + rest)
        with peer:
            bridge(self.request, peer)


class SOCKSProxy(socketserver.BaseRequestHandler):
    def handle(self):
        assert exact(self.request, 3) == b"\x05\x01\x00"
        self.request.sendall(b"\x05\x00")
        request = exact(self.request, 4)
        if request[3] == 1:
            host = socket.inet_ntop(socket.AF_INET, exact(self.request, 4))
        elif request[3] == 4:
            host = socket.inet_ntop(socket.AF_INET6, exact(self.request, 16))
        else:
            host = exact(self.request, exact(self.request, 1)[0]).decode()
        port = struct.unpack("!H", exact(self.request, 2))[0]
        self.server.received.append((host, port))
        with socket.create_connection((host, port), timeout=2) as peer:
            self.request.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            bridge(self.request, peer)


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.servers, self.managers = [], []
        self.echo = self.server(Echo)
        self.http = http.server.ThreadingHTTPServer(("127.0.0.1", 0), HTTP)
        self.http.daemon_threads = True
        self.http.received = []
        self.run_server(self.http)
    def tearDown(self):
        for manager in self.managers:
            manager.stop()
        for server in self.servers:
            server.shutdown()
            server.server_close()
    def run_server(self, server):
        self.servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server
    def server(self, handler):
        server = TCPServer(("127.0.0.1", 0), handler)
        server.received = []
        return self.run_server(server)
    def start(self, target=None, channels=None, deny_ports=(), limits=None, dns_overrides=None):
        target = target or {"id": "route", "type": "direct"}
        plan = {"id": "fixture", "targets": [target], "channels": channels or [{"id": "app", "default_target": target["id"]}],
                "limits": {"connect_timeout": 1, "header_timeout": 1, "idle_timeout": 2, **(limits or {})},
                "dns_overrides": dns_overrides or {}}
        manager = RelayManager(deny_ports=deny_ports)
        self.managers.append(manager)
        ports = manager.start(plan)
        return manager, ports[plan["channels"][0]["id"]]
    def client(self, port):
        return socket.create_connection(("127.0.0.1", port), timeout=3)
    def request(self, port, request):
        with self.client(port) as connection:
            connection.sendall(request)
            result = bytearray()
            while block := connection.recv(65536):
                result.extend(block)
            return bytes(result)
    def http_request(self, method="GET", body=b"", extra=b"", path="/"):
        port = self.http.server_address[1]
        return (f"{method} http://127.0.0.1:{port}{path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n".encode()
                + extra + b"\r\n" + body)
    def wait_events(self, manager):
        for _ in range(100):
            if manager.events():
                return manager.events()
            time.sleep(0.01)
        self.fail("No relay event recorded")

    def test_disabled_until_start_and_per_channel_identity(self):
        dormant = RelayManager()
        self.assertFalse(dormant.status()["running"])
        self.assertEqual(dormant.status()["channels"], [])
        channels = [{"id": "one", "default_target": "route"}, {"id": "two", "default_target": "route"}]
        manager, port = self.start(channels=channels)
        info = manager.status()["channels"]
        self.assertNotEqual(info[0]["actual_port"], info[1]["actual_port"])
        self.assertNotEqual(info[0]["config_id"], info[1]["config_id"])
        self.assertTrue(all(item["listen_host"] == "127.0.0.1" for item in info))
        with self.assertRaises(RuntimeError):
            manager.start({"targets": [{"id": "a", "type": "direct"}], "channels": [{"id": "a", "default_target": "a"}]})

    def test_http_direct_content_length_and_chunked_are_preserved(self):
        manager, port = self.start()
        self.assertTrue(self.request(port, self.http_request()).endswith(b"hello"))
        response = self.request(port, self.http_request("POST", b"hello payload", b"Content-Length: 13\r\n"))
        self.assertTrue(response.endswith(b"hello payload"))
        chunked = b"5\r\nhello\r\n6\r\n world\r\n0\r\nX-Fixture: trailer\r\n\r\n"
        response = self.request(port, self.http_request("POST", chunked, b"Transfer-Encoding: chunked\r\n"))
        self.assertTrue(response.endswith(b"hello world"))
        self.assertEqual(self.http.received[-1]["body"], b"hello world")
        response = self.request(port, self.http_request(path="/chunked"))
        self.assertTrue(response.endswith(b"5\r\nhello\r\n0\r\nX-Fixture: trailer\r\n\r\n"))
        self.assertIn(b"Connection: close\r\n", response)

    def test_http_connect_and_socks_inbound_opaque_echo(self):
        for protocol in ("connect", "socks"):
            with self.subTest(protocol=protocol):
                manager, port = self.start()
                with self.client(port) as client:
                    echo_port = self.echo.server_address[1]
                    if protocol == "connect":
                        client.sendall(f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: fixture\r\n\r\n".encode())
                        self.assertIn(b" 200 ", headers(client))
                    else:
                        client.sendall(b"\x05\x01\x00")
                        self.assertEqual(exact(client, 2), b"\x05\x00")
                        client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", echo_port))
                        self.assertEqual(exact(client, 10)[:2], b"\x05\x00")
                    payload = b"opaque TLS-looking bytes\x00\x16\x03\x03" * 128
                    client.sendall(payload)
                    self.assertEqual(exact(client, len(payload)), payload)

    def test_http_and_socks_upstream_forward_and_tunnel(self):
        for handler, kind in ((HTTPProxy, "http"), (SOCKSProxy, "socks5")):
            proxy = self.server(handler)
            target = {"id": "route", "type": kind, "host": "127.0.0.1", "port": proxy.server_address[1]}
            manager, port = self.start(target)
            self.assertTrue(self.request(port, self.http_request()).endswith(b"hello"))
            with self.client(port) as client:
                client.sendall(f"CONNECT 127.0.0.1:{self.echo.server_address[1]} HTTP/1.1\r\n\r\n".encode())
                self.assertIn(b" 200 ", headers(client))
                client.sendall(b"via-upstream")
                self.assertEqual(exact(client, 12), b"via-upstream")
            self.assertTrue(proxy.received)

    def test_public_connector_direct_http_and_socks(self):
        targets = [{"id": "route", "type": "direct"}]
        for handler, kind in ((HTTPProxy, "http"), (SOCKSProxy, "socks5")):
            proxy = self.server(handler)
            targets.append({"id": kind, "type": kind, "host": "127.0.0.1", "port": proxy.server_address[1]})
        for target in targets:
            with connect_target(target, "127.0.0.1", self.echo.server_address[1], timeout=2) as connected:
                connected.sendall(b"probe")
                self.assertEqual(exact(connected, 5), b"probe")

    def test_public_connector_dns_timeouts_cannot_create_unbounded_resolver_threads(self):
        release = threading.Event()
        finished, condition = [], threading.Condition()
        def delayed(*args, **kwargs):
            release.wait(3)
            with condition:
                finished.append(True)
                condition.notify_all()
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 1234))]
        with patch("proxyworkbench.relay.socket.getaddrinfo", side_effect=delayed):
            try:
                for _ in range(8):
                    with self.assertRaises(RelayError) as failure:
                        connect_target({"type": "direct"}, "fixture.invalid", 1234, timeout=.01)
                    self.assertEqual(failure.exception.code, "dns_timeout")
                with self.assertRaises(RelayError) as failure:
                    connect_target({"type": "direct"}, "fixture.invalid", 1234, timeout=.01)
                self.assertEqual(failure.exception.code, "dns_resolver_busy")
            finally:
                release.set()
                with condition:
                    self.assertTrue(condition.wait_for(lambda: len(finished) == 8, timeout=2))

    def test_dns_override_changes_real_dial_preserves_host_and_tunnel_bytes(self):
        targets = [{"id": "route", "type": "direct"}]
        for handler, kind in ((HTTPProxy, "http"), (SOCKSProxy, "socks5")):
            proxy = self.server(handler)
            targets.append({"id": "route", "type": kind, "host": "127.0.0.1", "port": proxy.server_address[1]})
        for target in targets:
            manager, port = self.start(target, dns_overrides={"fixture.invalid": "127.0.0.1"})
            request = self.http_request("POST", b"hello", b"Content-Length: 5\r\n").replace(b"127.0.0.1", b"fixture.invalid")
            self.assertTrue(self.request(port, request).endswith(b"hello"))
            self.assertEqual(self.http.received[-1]["host"], f"fixture.invalid:{self.http.server_address[1]}")
            with self.client(port) as client:
                client.sendall(f"CONNECT fixture.invalid:{self.echo.server_address[1]} HTTP/1.1\r\n\r\n".encode())
                self.assertIn(b" 200 ", headers(client))
                client.sendall(b"opaque SNI fixture.invalid")
                self.assertEqual(exact(client, 26), b"opaque SNI fixture.invalid")
            event = self.wait_events(manager)[0]
            self.assertEqual(event["host"], "fixture.invalid")
            self.assertEqual(event["dial_host"], "127.0.0.1")
            self.assertEqual(event["dns_source"], "plan_override")

    def test_connection_limit_closes_extra_clients_without_breaking_existing_tunnel(self):
        manager, port = self.start(limits={"max_connections": 1})
        with self.client(port) as first:
            first.sendall(f"CONNECT 127.0.0.1:{self.echo.server_address[1]} HTTP/1.1\r\n\r\n".encode())
            self.assertIn(b" 200 ", headers(first))
            with self.client(port) as extra:
                extra.sendall(self.http_request())
                try:
                    self.assertEqual(extra.recv(1), b"")
                except (ConnectionResetError, ConnectionAbortedError):
                    pass
            first.sendall(b"alive")
            self.assertEqual(exact(first, 5), b"alive")
        self.assertTrue(any(event.get("code") == "connection_limit" for event in manager.events()))

    def test_open_tunnel_emits_connection_evidence_before_completion(self):
        manager, port = self.start(dns_overrides={"fixture.invalid": "127.0.0.1"})
        with self.client(port) as client:
            client.sendall(f"CONNECT fixture.invalid:{self.echo.server_address[1]} HTTP/1.1\r\n\r\n".encode())
            self.assertIn(b" 200 ", headers(client))
            event = self.wait_events(manager)[0]
            self.assertEqual((event["status"], event["stage"]), ("connected", "established"))
            self.assertEqual((event["host"], event["dial_host"], event["dns_source"]),
                             ("fixture.invalid", "127.0.0.1", "plan_override"))
            self.assertTrue(event["connection_id"])
            self.assertFalse(any(item["status"] == "completed" for item in manager.events()))
            client.sendall(b"still open")
            self.assertEqual(exact(client, 10), b"still open")
        for _ in range(100):
            final = [item for item in manager.events() if item["status"] == "completed"]
            if final:
                break
            time.sleep(.01)
        self.assertTrue(final)
        self.assertEqual(final[0]["connection_id"], event["connection_id"])
        self.assertGreater(final[0]["bytes_up"], 0)

    def test_block_rules_and_control_or_relay_loops(self):
        blocked, port = self.start({"id": "route", "type": "block"})
        self.assertIn(b" 403 ", self.request(port, self.http_request()))
        manager, port = self.start(deny_ports=[self.http.server_address[1]])
        self.assertIn(b" 403 ", self.request(port, self.http_request()))
        own = f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n".encode()
        self.assertIn(b" 403 ", self.request(port, own))
        with self.assertRaises(RelayError):
            connect_target({"type": "direct"}, "127.0.0.1", self.http.server_address[1], forbidden_ports=[self.http.server_address[1]])

    def test_conflicting_framing_bad_host_and_upgrade_are_explicitly_rejected(self):
        manager, port = self.start()
        requests = [self.http_request("POST", extra=b"Content-Length: 1\r\nTransfer-Encoding: chunked\r\n"),
                    self.http_request("POST", extra=b"Content-Length: 1\r\nContent-Length: 1\r\n"),
                    self.http_request().replace(b"Host: 127.0.0.1", b"Host: wrong.example"),
                    self.http_request(extra=b"Connection: upgrade\r\nUpgrade: websocket\r\n"),
                    b"GET http://127.0.0.1:0/ HTTP/1.1\r\nHost: 127.0.0.1:0\r\n\r\n"]
        for request in requests:
            self.assertRegex(self.request(port, request).split(b"\r\n")[0], rb"HTTP/1.1 (400|501)")
        self.assertEqual(self.http.received, [])

    def test_socks_udp_and_auth_are_rejected(self):
        manager, port = self.start()
        with self.client(port) as client:
            client.sendall(b"\x05\x01\x02")
            self.assertEqual(exact(client, 2), b"\x05\xff")
        with self.client(port) as client:
            client.sendall(b"\x05\x01\x00")
            self.assertEqual(exact(client, 2), b"\x05\x00")
            client.sendall(b"\x05\x03\x00\x01")
            self.assertEqual(exact(client, 10)[:2], b"\x05\x07")

    def test_events_never_contain_path_payload_or_credentials(self):
        manager, port = self.start()
        request = self.http_request("POST", b"secretpayload", b"Content-Length: 13\r\nAuthorization: Bearer secretauth\r\nProxy-Authorization: Basic secretproxy\r\n", "/secretpath?token=secretquery")
        self.assertTrue(self.request(port, request).endswith(b"secretpayload"))
        events = self.wait_events(manager)
        encoded = json.dumps(events)
        for secret in ("secretpayload", "secretauth", "secretproxy", "secretpath", "secretquery", "Bearer", "Authorization"):
            self.assertNotIn(secret, encoded)
        self.assertIsNone(self.http.received[-1]["proxy_auth"])
        self.assertEqual(events[-1]["host"], "127.0.0.1")
        self.assertGreater(events[-1]["bytes_up"], 13)

    def test_header_timeout_and_graceful_stop_with_open_tunnel(self):
        manager, port = self.start(limits={"header_timeout": 0.1})
        with self.client(port) as client:
            client.sendall(b"GET ")
            self.assertIn(b" 504 ", headers(client))
        with self.client(port) as client:
            client.sendall(f"CONNECT 127.0.0.1:{self.echo.server_address[1]} HTTP/1.1\r\n\r\n".encode())
            self.assertIn(b" 200 ", headers(client))
            started = time.monotonic()
            self.assertFalse(manager.stop()["running"])
            self.assertLess(time.monotonic() - started, 2)
            self.assertEqual(client.recv(1), b"")

    def test_interface_option_byte_order_is_explicit_not_guessed(self):
        class Fake:
            def __init__(self, family):
                self.family, self.options = family, []
            def setsockopt(self, level, name, value):
                self.options.append((level, name, value))
            def getsockopt(self, level, name, length):
                return struct.pack("=I", 19)
        with patch("proxyworkbench.relay.os.name", "nt"):
            ipv4, ipv6 = Fake(socket.AF_INET), Fake(socket.AF_INET6)
            _bind_interface(ipv4, 19)
            _bind_interface(ipv6, 19)
        self.assertEqual(ipv4.options[0], (socket.IPPROTO_IP, 31, struct.pack("!I", 19)))
        self.assertEqual(ipv6.options[0], (socket.IPPROTO_IPV6, 31, struct.pack("=I", 19)))


if __name__ == "__main__":
    unittest.main()
