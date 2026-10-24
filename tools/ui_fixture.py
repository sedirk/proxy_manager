"""Isolated UI acceptance fixture. All test traffic remains on loopback."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from proxyworkbench.server import ControlServer
from proxyworkbench.store import default_plan
from proxyworkbench.system_proxy import atomic_json


class Origin(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def log_message(self, *args):
        pass


def main():
    with tempfile.TemporaryDirectory(prefix='patchbay-ui-') as folder:
        origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        server = ControlServer(('127.0.0.1', 0), folder, discover=False)
        server.root = ROOT
        saved = ROOT / '.local/snapshot.json'
        if saved.exists():
            server.service.snapshot = json.loads(saved.read_text(encoding='utf-8'))
        plan = default_plan(server.service.snapshot)
        plan['name'] = '隔离验收 · 仅本机请求'
        plan['dns_overrides'] = {'patchbay.test': '127.0.0.1'}
        for channel in plan['channels']:
            channel['rules'].insert(0, {'id': 'local-fixture', 'domains': ['patchbay.test'], 'target': 'direct'})
        server.service.save_plan(plan)
        # Any accidental attempt to attach the real OS proxy is explicitly denied.
        def no_system(*args, **kwargs):
            raise RuntimeError('隔离验收实例禁止系统代理写入')
        server.service.system_apply = no_system
        details = {'port': server.server_port, 'origin_port': origin.server_port,
                   'probe_url': f'http://patchbay.test:{origin.server_port}/', 'isolated': True}
        atomic_json(ROOT / 'artifacts/ui-fixture.json', details)
        try:
            server.serve_forever(poll_interval=.3)
        finally:
            server.service.close()
            server.server_close()
            origin.shutdown()
            origin.server_close()


if __name__ == '__main__':
    main()
