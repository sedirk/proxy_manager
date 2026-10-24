"""Probes use loopback fixtures only; no real service or proxy is contacted."""
import base64
import hashlib
import json
import socket
import socketserver
import ssl
import threading
import time
import unittest
from unittest.mock import patch

from proxyworkbench import probes
from proxyworkbench.relay import RelayError, RelayManager


class LocalServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    def handle_error(self, request, client_address):
        pass


class Response(socketserver.BaseRequestHandler):
    def handle(self):
        data = bytearray()
        while not data.endswith(b'\r\n\r\n'):
            block = self.request.recv(1)
            if not block:
                return
            data.extend(block)
        self.server.received.append(bytes(data))
        path = bytes(data).split(b' ')[1]
        fields = {line.split(b':', 1)[0].lower(): line.split(b':', 1)[1].strip()
                  for line in bytes(data).split(b'\r\n')[1:] if b':' in line}
        if path == b'/slow':
            for byte in b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n':
                self.request.sendall(bytes([byte]))
                time.sleep(.03)
            return
        if path == b'/malformed':
            self.request.sendall(b'HTTP/1.1 200 OK\r\n X-Secret: response-secret\r\n\r\n')
            return
        if path == b'/duplicate-length':
            self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n')
            return
        if path == b'/bad-status':
            self.request.sendall(b'HTTP/1.9 200 OK\r\n\r\n')
            return
        if b'sec-websocket-key' in fields:
            accept = base64.b64encode(hashlib.sha1(fields[b'sec-websocket-key'] + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
            response = b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
            if path != b'/no-connection':
                response += b'Connection: keep-alive, Upgrade\r\n'
            response += b'Sec-WebSocket-Accept: ' + (b'wrong' if path == b'/wrong-accept' else accept) + b'\r\n'
            if path == b'/duplicate-accept':
                response += b'Sec-WebSocket-Accept: ' + accept + b'\r\n'
            if path == b'/unsolicited-protocol':
                response += b'Sec-WebSocket-Protocol: never-requested\r\n'
            if path == b'/unsolicited-extension':
                response += b'Sec-WebSocket-Extensions: permessage-deflate\r\n'
            self.request.sendall(response + b'\r\n')
            if path == b'/ws':
                self.server.close_frame = self.request.recv(6)
            return
        response = b'HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
        if path == b'/interim':
            response = b'HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </fixture>\r\n\r\n' + response
        self.request.sendall(response)


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.server = LocalServer(('127.0.0.1', 0), Response)
        self.server.received, self.server.close_frame = [], None
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_address[1]
        self.managers = []
    def tearDown(self):
        for manager in self.managers:
            manager.stop()
        self.server.shutdown()
        self.server.server_close()
    def url(self, path='/', scheme='http', host='127.0.0.1'):
        return f'{scheme}://{host}:{self.port}{path}'
    def run_probe(self, path='/', scheme='http', target=None, **kwargs):
        return probes.probe(self.url(path, scheme), target or {'id': 'local', 'type': 'direct'}, **kwargs)

    def test_http_response_is_evidence_not_application_success_and_handles_interim(self):
        for path in ('/', '/interim'):
            report = self.run_probe(path)
            self.assertTrue(report['transport_passed'])
            self.assertEqual(report['layers'][-1]['http_status'], 405)
            self.assertEqual(report['application'], 'unknown')
            self.assertEqual(report['long_lived_connection'], 'not_tested')
        self.assertTrue(self.server.received[0].startswith(b'HEAD / HTTP/1.1\r\n'))

    def test_websocket_requires_complete_rfc_handshake(self):
        report = self.run_probe('/ws', 'ws')
        self.assertTrue(report['transport_passed'])
        self.assertEqual(report['layers'][-1]['layer'], 'websocket')
        self.assertEqual(report['long_lived_connection'], 'not_tested')
        for path in ('/no-connection', '/wrong-accept', '/duplicate-accept',
                     '/unsolicited-protocol', '/unsolicited-extension'):
            with self.subTest(path=path):
                self.assertFalse(self.run_probe(path, 'ws')['transport_passed'])

    def test_http_malformed_headers_or_status_cannot_pass_or_leak_response(self):
        for path in ('/malformed', '/duplicate-length', '/bad-status'):
            report = self.run_probe(path)
            self.assertFalse(report['transport_passed'])
            self.assertEqual(report['layers'][-1]['error_code'], 'malformed_protocol_response')
            self.assertNotIn('response-secret', json.dumps(report))
            self.assertNotIn(path, json.dumps(report))

    def test_overall_deadline_is_not_reset_by_incremental_headers(self):
        started = time.monotonic()
        report = self.run_probe('/slow', timeout=.15)
        elapsed = time.monotonic() - started
        self.assertFalse(report['transport_passed'])
        self.assertEqual(report['layers'][-1]['error_code'], 'probe_timeout')
        self.assertLess(elapsed, .6)
        self.assertGreaterEqual(report['elapsed_ms'], 100)

    def test_invalid_or_sensitive_urls_rejected_before_connect(self):
        urls = [self.url('/?token=secret'), self.url('/#secret'),
                f'http://user:secret@127.0.0.1:{self.port}/',
                f'http://@127.0.0.1:{self.port}/', 'http://127.0.0.1:0/',
                self.url('/bad\r\nInjected: value'), self.url('/中文')]
        with patch('proxyworkbench.relay.connect_target') as connect:
            for url in urls:
                with self.subTest(url=url), self.assertRaises(ValueError):
                    probes.probe(url, {'type': 'direct'})
            connect.assert_not_called()

    def test_connector_and_tls_failures_keep_accurate_stage_without_raw_error(self):
        with patch('proxyworkbench.relay.connect_target', side_effect=RelayError('name_resolution_failed', 'dns')):
            report = self.run_probe()
        self.assertEqual(report['layers'][-1]['layer'], 'dns')
        self.assertEqual(report['layers'][-1]['error_code'], 'name_resolution_failed')
        with patch('proxyworkbench.probes.ssl.create_default_context') as factory:
            factory.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError('secret-error-host/path')
            report = self.run_probe(scheme='https')
        self.assertEqual(report['layers'][-1]['layer'], 'tls')
        self.assertEqual(report['layers'][-1]['error_code'], 'tls_certificate_verification_failed')
        self.assertNotIn('secret-error-host', json.dumps(report))
        factory.return_value.wrap_socket.assert_called_once()
        self.assertEqual(factory.return_value.wrap_socket.call_args.kwargs['server_hostname'], '127.0.0.1')

    def test_real_channel_uses_selected_rule_dns_override_and_original_host(self):
        plan = {'id': 'fixture', 'targets': [{'id': 'allow', 'type': 'direct'}, {'id': 'deny', 'type': 'block'}],
                'channels': [{'id': 'app', 'default_target': 'deny', 'rules': [
                    {'id': 'exact', 'domains': ['fixture.invalid'], 'target': 'allow'}]}],
                'dns_overrides': {'fixture.invalid': '127.0.0.1'}}
        manager = RelayManager()
        self.managers.append(manager)
        port = manager.start(plan)['app']
        target = {'id': 'channel', 'type': 'http', 'host': '127.0.0.1', 'port': port}
        for scheme, path in (('http', '/'), ('ws', '/ws')):
            report = probes.probe(self.url(path, scheme, 'fixture.invalid'), target, timeout=2)
            self.assertTrue(report['transport_passed'], report)
        self.assertIn(f'Host: fixture.invalid:{self.port}\r\n'.encode(), self.server.received[0])
        established = [event for event in manager.events() if event['stage'] == 'established']
        self.assertEqual(len(established), 2)
        self.assertTrue(all(event['rule_id'] == 'exact' and event['target_id'] == 'allow'
                            and event['dial_host'] == '127.0.0.1' for event in established))

    def test_dns_errors_and_timeout_are_bounded_without_external_resolution(self):
        with patch('proxyworkbench.probes.socket.getaddrinfo', side_effect=socket.gaierror('secret-dns-message')):
            report = probes.resolve('fixture.invalid', timeout=.1)
        self.assertEqual(report['status'], 'failed')
        self.assertNotIn('secret-dns-message', json.dumps(report))
        release, finished = threading.Event(), threading.Event()
        def delayed(*args):
            release.wait(2)
            finished.set()
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 0))]
        with patch('proxyworkbench.probes.socket.getaddrinfo', side_effect=delayed):
            try:
                started = time.monotonic()
                report = probes.resolve('fixture.invalid', timeout=.05)
                self.assertEqual(report['status'], 'failed')
                self.assertLess(time.monotonic() - started, .4)
            finally:
                release.set()
                self.assertTrue(finished.wait(2))
        with patch('proxyworkbench.probes._dns_slots') as slots, patch('proxyworkbench.probes._dns.submit') as submit:
            slots.acquire.return_value = False
            self.assertEqual(probes.resolve('fixture.invalid')['error'], 'ResolverBusy')
            submit.assert_not_called()


if __name__ == '__main__':
    unittest.main()
