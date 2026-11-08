"""Real UI/API fixture with simulated target processes; loopback only.

Never launches a user program, reads a host snapshot, or changes OS proxies.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
from urllib.parse import urlsplit
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from proxyworkbench.server import ControlServer
from proxyworkbench.relay import RelayManager
from proxyworkbench.proxy_environment import child_environment, PROXY_NAMES
from proxyworkbench import probes


class Origin(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def log_message(self, *args):
        pass


def main():
    with tempfile.TemporaryDirectory(prefix='flowdesk-workflow-ui-') as folder:
        root = Path(folder)
        exe = root / 'DemoEditor.exe'
        exe.write_bytes(b'fixture, never executed')
        server = ControlServer(('127.0.0.1', 0), root, discover=False)
        server.root = ROOT
        origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        relay = RelayManager()
        relay.start({'version': 1, 'name': 'Fixture proxy', 'targets': [{'id': 'direct', 'type': 'direct'}],
                     'channels': [{'id': 'fixture', 'default_target': 'direct', 'rules': []}]})
        channel = relay.status()['channels'][0]
        endpoint = channel['proxy_url']; parsed = urlsplit(endpoint)
        service = server.service
        service.snapshot = {'captured_at': '2026-11-08T00:00:00Z', 'apps': [], 'layers': {}, 'network_tools': [{
            'id': 'fixture', 'name': '隔离样例代理', 'kind': '应用代理', 'running': True,
            'state_label': '隔离样例', 'proxy_options': [{'id': 'fixture', 'protocol': 'http',
            'host': parsed.hostname, 'port': parsed.port, 'tool_id': 'fixture', 'tool_name': '隔离样例代理',
            'proxy_url': endpoint}]}]}
        service.discover = lambda: {}
        app_id = service.catalog_add_app({'executable': str(exe), 'name': '隔离样例编辑器'})['app_id']
        state = {'items': [], 'values': {}}
        def launch(executable, proxy_url, mode, **kwargs):
            if executable != str(exe): raise ValueError('Fixture refuses other executables')
            state['items'] = [{'ProcessId': 987654, 'ParentProcessId': 0, 'Started': 1, 'ExecutablePath': str(exe)}]
            env = child_environment(os.environ, mode, proxy_url)
            state['values'] = {k.upper(): v for k, v in env.items() if k.upper() in PROXY_NAMES}
            return {'pid': 987654, 'notice': '隔离样例：已模拟应用设置；没有启动任何真实程序。'}
        def denied(*args, **kwargs):
            raise ValueError('隔离样例禁止系统写入、打开目录或创建桌面快捷方式')
        service.system_apply = service.catalog_resource = service.app_route_shortcut = denied
        real_probe = probes.probe
        def local_probe(url, target, **kwargs):
            address = urlsplit(url)
            if address.hostname != '127.0.0.1' or address.port != origin.server_port:
                raise ValueError('隔离样例仅允许指定本机测试地址')
            return real_probe(url, target, **kwargs)
        details = {'port': server.server_port, 'app_id': app_id,
                   'probe_url': f'http://127.0.0.1:{origin.server_port}/', 'isolated': True}
        (ROOT / 'artifacts').mkdir(exist_ok=True)
        (ROOT / 'artifacts/workflow-ui-fixture.json').write_text(json.dumps(details), encoding='utf-8')
        print(json.dumps(details), flush=True)
        try:
            with patch('proxyworkbench.process_proxy.records', side_effect=lambda: state['items']), \
                    patch('proxyworkbench.process_proxy.proxy_values', side_effect=lambda item: state['values']), \
                    patch('proxyworkbench.app_launch.launch', side_effect=launch), \
                    patch('proxyworkbench.service.probes.probe', side_effect=local_probe):
                server.serve_forever(poll_interval=.2)
        finally:
            service.close(); server.server_close()
            relay.stop(); origin.shutdown(); origin.server_close()


if __name__ == '__main__': main()
