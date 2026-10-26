"""Real loopback fixtures only; no installed proxy or user app is contacted."""
from copy import deepcopy
import json
import http.client
from pathlib import Path
import socketserver
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from proxyworkbench import proxy_check
from proxyworkbench.relay import RelayManager
from proxyworkbench.network_tools import inventory
from proxyworkbench.service import Service


def tool(port, tool_id='v2rayn', address='127.0.0.1', **extra):
    return {'id': tool_id, 'name': tool_id, 'proxy_options': [],
            'endpoints': [{'id': 'ep-fixture', 'pid': 12345, 'owner': 'xray.exe',
                           'address': address, 'port': port, 'transport': 'tcp', **extra}]}


class ProxyCheckTests(unittest.TestCase):
    def setUp(self):
        self.relay = RelayManager()
        self.port = self.relay.start({'targets': [{'id': 'plain', 'type': 'direct'}],
            'channels': [{'id': 'fixture', 'default_target': 'plain', 'listen_port': 0, 'rules': []}]})['fixture']

    def tearDown(self):
        self.relay.stop()

    def test_unknown_protocol_is_confirmed_by_real_connect_and_local_forwarding(self):
        source = tool(self.port)
        passed, checks = proxy_check.check(source)
        self.assertEqual(len(passed), 1)
        self.assertEqual(checks[0]['status'], 'ok')
        self.assertEqual(source['proxy_options'], [])
        decorated = proxy_check.decorate([source], passed)[0]
        self.assertEqual(decorated['proxy_options'][0]['proxy_url'], f'http://127.0.0.1:{self.port}')
        self.assertTrue(decorated['proxy_options'][0]['verified'])
        self.assertIn('实际网站', checks[0]['detail'])
        self.assertEqual(len(proxy_check.decorate([decorated], passed)[0]['proxy_options']), 1)

    def test_nonproxy_lan_udp_and_control_ports_never_get_probed(self):
        invalid = [tool(self.port, name) for name in ('uu','zerotier','atrust','system-proxy','codex')]
        invalid += [tool(self.port, address='192.0.2.3'), tool(self.port, transport='udp'), tool(self.port, pid=None),
                    tool(self.port, owner='uu.exe'), tool(self.port, app_id='atrust')]
        with patch.object(proxy_check.socket, 'create_connection') as connect:
            for item in invalid:
                with self.subTest(item=item), self.assertRaises(ValueError):
                    proxy_check.check(item)
            with self.assertRaises(ValueError):proxy_check.check(tool(self.port), (self.port,))
            connect.assert_not_called()

    def test_accelerator_launched_by_proxy_manager_remains_ineligible(self):
        apps=[{'id':'v2rayn','name':'v2rayN','running_processes':[{'pid':10,'name':'v2rayN.exe'}]},
              {'id':'uu','name':'UU','running_processes':[{'pid':20,'name':'uu.exe','parent_pid':10}]}]
        endpoint={'id':'ep-uu','pid':20,'owner':'uu.exe','app_id':'uu','address':'127.0.0.1',
                  'port':self.port,'transport':'tcp'}
        tools=inventory(apps,[endpoint],[],{})
        self.assertFalse(any(proxy_check.candidates(item) for item in tools))
        self.assertEqual(next(item for item in tools if item['id']=='uu')['listener_count'],1)

    def test_ipv6_unspecified_is_a_candidate_without_assuming_ipv4_or_http(self):
        source = tool(self.port, address='::')
        candidate = proxy_check.candidates(source)[0]
        self.assertEqual(candidate['host'], '::1')
        self.assertFalse(proxy_check.decorate([source])[0]['proxy_options'])
        changed = tool(self.port + 1)
        passed, _ = proxy_check.check(tool(self.port))
        self.assertFalse(proxy_check.decorate([changed], passed)[0]['proxy_options'])
        changed = tool(self.port, pid=99999)
        self.assertFalse(proxy_check.decorate([changed], passed)[0]['proxy_options'])

    def test_plain_http_status_or_echo_cannot_impersonate_a_forwarding_proxy(self):
        class Fake(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(2)
                def headers():
                    result = bytearray()
                    while not result.endswith(b'\r\n\r\n'):
                        part = self.request.recv(1)
                        if not part:return result
                        result.extend(part)
                    return result
                headers()
                self.request.sendall(b'HTTP/1.1 200 OK\r\n\r\n')
                request = headers()
                body = bytes(request).split(b' ')[1].strip(b'/')
                self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)
        with socketserver.ThreadingTCPServer(('127.0.0.1', 0), Fake) as server:
            server.daemon_threads = True
            worker = threading.Thread(target=lambda: server.serve_forever(poll_interval=.05), daemon=True)
            worker.start()
            try:
                passed, checks = proxy_check.check(tool(server.server_address[1]))
                self.assertFalse(passed)
                self.assertIn('未观察到请求', checks[0]['detail'])
            finally:
                server.shutdown();worker.join(2)

    def test_service_adds_only_rechecked_entrance_without_saving_or_launching_application(self):
        with tempfile.TemporaryDirectory() as directory:
            service = Service(Path(directory), discover=False)
            source = tool(self.port)
            service.snapshot = {'network_tools': [source]}
            baseline = deepcopy(service.plan)
            try:
                with patch.object(service, 'discover', return_value={}),patch('proxyworkbench.app_launch.launch') as launch:
                    output = service.network_tool_check({'tool_id': 'v2rayn', 'host': 'evil.example', 'port': 999})
                    launch.assert_not_called()
                self.assertIn('已确认 1', output['summary'])
                self.assertTrue(output['app_routes']['tools'][0]['proxy_options'])
                self.assertEqual(service.plan, baseline)
                self.assertFalse((Path(directory)/'.local/app-routes.json').exists())
                # This endpoint remains explicit evidence only for its current identity.
                service.snapshot = {'network_tools': [tool(self.port, pid=99999)]}
                self.assertFalse(service.app_routes_state()['tools'][0]['proxy_options'])
            finally:
                service.close()

    def test_slow_response_headers_cannot_extend_the_total_probe_deadline(self):
        class Slow(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(1)
                def headers():
                    data = bytearray()
                    while not data.endswith(b'\r\n\r\n'):
                        part = self.request.recv(1)
                        if not part:return
                        data.extend(part)
                try:
                    headers();self.request.sendall(b'HTTP/1.1 200 OK\r\n\r\n');headers()
                    for byte in b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n':
                        self.request.sendall(bytes([byte]));time.sleep(.03)
                except OSError:pass
        with socketserver.ThreadingTCPServer(('127.0.0.1', 0), Slow) as server:
            server.daemon_threads = True
            worker = threading.Thread(target=lambda: server.serve_forever(poll_interval=.05), daemon=True)
            worker.start()
            try:
                entry = proxy_check.candidates(tool(server.server_address[1]))[0]
                started = time.monotonic()
                with self.assertRaises((OSError, ValueError, http.client.HTTPException)):
                    proxy_check._forward(entry, 12345, 'fixture', started+.15)
                self.assertLess(time.monotonic()-started, .8)
            finally:
                server.shutdown();worker.join(2)

    def test_listener_change_or_unsupported_tool_does_not_publish_probe_success(self):
        with tempfile.TemporaryDirectory() as directory:
            service = Service(Path(directory), discover=False)
            service.snapshot = {'network_tools': [tool(self.port), tool(self.port, 'uu')]}
            try:
                with patch.object(proxy_check, 'check') as probe, self.assertRaises(ValueError):
                    service.network_tool_check({'tool_id': 'uu'})
                probe.assert_not_called()
                calls = []
                def scan():
                    calls.append(True)
                    if len(calls) == 2:service.snapshot = {'network_tools': [tool(self.port, pid=99999)]}
                    return {}
                with patch.object(service, 'discover', side_effect=scan):
                    result = service.network_tool_check({'tool_id': 'v2rayn'})
                self.assertFalse(result['app_routes']['tools'][0]['proxy_options'])
                self.assertIn('监听归属', json.dumps(result['checks'], ensure_ascii=False))
            finally:service.close()

    def test_failed_recheck_with_busy_discovery_revokes_old_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            service=Service(Path(directory),discover=False)
            source=tool(self.port);service.snapshot={'network_tools':[source]}
            service.verified_proxy_entrances=proxy_check.check(source)[0]
            try:
                self.assertTrue(service.app_routes_state()['tools'][0]['proxy_options'])
                with patch.object(service,'discover',side_effect=[{}, {'discovering':True}]),patch.object(proxy_check,'check',return_value=([],[])):
                    with self.assertRaisesRegex(ValueError,'重新核对'):
                        service.network_tool_check({'tool_id':'v2rayn'})
                self.assertFalse(service.app_routes_state()['tools'][0]['proxy_options'])
            finally:service.close()


if __name__ == '__main__':unittest.main()
