"""Exercise the actual Windows executable without Python on its PATH.

Uses temporary user data, loopback requests and a completed guardian journal.
Never applies system proxy settings. Python is only the external test harness.
"""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from proxyworkbench import __version__
from proxyworkbench.system_proxy import WinInet, fingerprint


class Origin(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def log_message(self, *args):
        pass


def wait_ready(process, local, opener):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError('Executable exited before readiness: ' + str(process.returncode))
        try:
            record = json.loads((local / 'server.json').read_text(encoding='utf-8'))
            url = 'http://127.0.0.1:' + str(record['port'])
            with opener.open(url + '/api/health', timeout=1) as response:
                health = json.load(response)
            if record['instance_id'] == health['instance_id']:
                return record, url
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(.1)
    raise RuntimeError('Executable startup timed out')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('exe')
    parser.add_argument('--report', default=str(ROOT / 'artifacts/exe-smoke.json'))
    args = parser.parse_args()
    binary = Path(args.exe).resolve()
    before = fingerprint(WinInet().read())
    report = {'version': __version__, 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}
    with tempfile.TemporaryDirectory(prefix='flowdesk-exe-') as folder:
        base = Path(folder)
        copy = base / '中文目录 with spaces' / binary.name
        copy.parent.mkdir()
        shutil.copy2(binary, copy)
        environment = os.environ.copy()
        environment['LOCALAPPDATA'] = str(base / 'user-data')
        system32 = Path(os.environ['SystemRoot']) / 'System32'
        environment['PATH'] = os.pathsep.join([str(system32), os.environ['SystemRoot'], str(system32 / 'WindowsPowerShell/v1.0')])
        environment.pop('PYTHONHOME', None)
        environment.pop('PYTHONPATH', None)
        environment['PYINSTALLER_RESET_ENVIRONMENT'] = '1'
        assert shutil.which('python', path=environment['PATH']) is None
        report['python_on_child_path'] = False
        local = base / 'user-data/FlowDesk/.local'
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        launch = [str(copy), '--no-browser', '--no-discovery', '--port', '0']
        process = None
        url = None
        token = None
        origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
        threading.Thread(target=origin.serve_forever, daemon=True).start()

        def api(path, value=None, method=None):
            request = urllib.request.Request(url + path,
                data=None if value is None else json.dumps(value).encode('utf-8'),
                headers={'X-Session-Token': token or '', 'Content-Type': 'application/json'},
                method=method or ('GET' if value is None else 'POST'))
            with opener.open(request, timeout=20) as response:
                return json.load(response)

        try:
            process = subprocess.Popen(launch, cwd=base, env=environment, creationflags=subprocess.CREATE_NO_WINDOW)
            record, url = wait_ready(process, local, opener)
            token = api('/api/session')['token']
            state = api('/api/state')
            assert state['version'] == __version__
            assert not state['runtime']['running'] and state['system']['phase'] == 'detached'
            for name in ('index.html', 'app.js', 'styles.css'):
                with opener.open(url + '/' + name) as response:
                    assert response.read() == (ROOT / 'web' / name).read_bytes()
            report['bundled_web_assets'] = True
            second = subprocess.run(launch, cwd=base, env=environment,
                                    creationflags=subprocess.CREATE_NO_WINDOW, timeout=45)
            assert second.returncode == 0
            assert api('/api/health')['instance_id'] == record['instance_id']
            report['repeat_launch_reuses_instance'] = True
            plan = state['plan']
            plan['name'] = '打包验收持久化'
            api('/api/plan', {'plan': plan}, 'PUT')
            assert api('/api/preview', {'plan': plan})['valid']
            api('/api/runtime/start', {'plan': plan})
            probe = api('/api/probe', {'url': 'http://127.0.0.1:' + str(origin.server_port) + '/',
                                     'channel_id': 'wows-wg', 'mode': 'http'})
            report['relay_probe'] = probe
            assert probe['transport_passed'] and any(step.get('layer') == 'http' and step.get('http_status') == 200 for step in probe['layers']), probe
            api('/api/runtime/stop', {})
            assert not api('/api/state')['runtime']['running']
            api('/api/shutdown', {})
            assert process.wait(timeout=30) == 0
            process = subprocess.Popen(launch, cwd=base, env=environment, creationflags=subprocess.CREATE_NO_WINDOW)
            _, url = wait_ready(process, local, opener)
            token = api('/api/session')['token']
            assert api('/api/state')['plan']['name'] == plan['name']
            report['persistent_state_survives_restart'] = True
            api('/api/discover', {})
            observed = api('/api/state')['snapshot']
            assert observed['platform'] == 'windows'
            assert observed['layers']['wininet']['evidence_status'] == 'observed'
            assert observed['capabilities']['sections']['processes']['status'] == 'observed', observed['capabilities']['errors']
            report['read_only_discovery'] = {'windows': True, 'processes': True, 'wininet': True}
            # Exercise frozen imports and actual dispatch, with no active lease.
            journal = base / 'finished-lease.json'
            journal.write_text(json.dumps({'id': 'a' * 32, 'phase': 'restored'}), encoding='utf-8')
            guard = subprocess.run([str(copy), '--guardian', str(journal), 'a' * 32],
                                   cwd=base, env=environment, creationflags=subprocess.CREATE_NO_WINDOW, timeout=45)
            assert guard.returncode == 0
            report['frozen_guardian_dispatch'] = True
            assert not (copy.parent / '.local').exists()
            report['state_outside_executable_directory'] = True
            api('/api/shutdown', {})
            assert process.wait(timeout=30) == 0
            report['graceful_shutdown'] = True
        finally:
            if process is not None and process.poll() is None:
                try:
                    api('/api/shutdown', {})
                    process.wait(timeout=30)
                except Exception:
                    # Only this isolated fixture is ours; report cleanup failure.
                    raise RuntimeError('Isolated executable is still running; no system settings were applied')
            origin.shutdown()
            origin.server_close()
    after = fingerprint(WinInet().read())
    assert before == after
    report['system_proxy_unchanged'] = True
    output = Path(args.report)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
