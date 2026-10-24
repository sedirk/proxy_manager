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
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from proxyworkbench import __version__
from proxyworkbench.system_proxy import WinInet, fingerprint


_PKG_MAGIC = b'MEI\014\013\012\013\016'
_PKG_COOKIE = struct.Struct('!8sIIII64s')
_PKG_ENTRY = struct.Struct('!IIIIBc')


class IncompleteExecutableError(RuntimeError):
    """The embedded PyInstaller package is absent, truncated or malformed."""


def validate_embedded_pkg(filename):
    """Read-only PKG preflight; requires no installed PyInstaller or extraction.

    Cookie/TOC layouts match PyInstaller.archive.readers.CArchiveReader and
    writers.CArchiveWriter in the pinned build dependency.  Find the last cookie
    like the bootloader, allowing Windows signing data after it; validate every
    range and compressed member before the smoke harness can execute the file.
    This checks package integrity, not publisher authenticity or all PE code.
    """
    def fail(detail):
        raise IncompleteExecutableError('Executable PKG is incomplete or invalid: ' + detail +
                                        '; wait for PyInstaller to finish before running the smoke test')

    filename = Path(filename)
    with filename.open('rb') as stream:
        initial = os.fstat(stream.fileno())
        size = initial.st_size
        if stream.read(2) != b'MZ':
            fail('Windows executable header is missing')
        end = size
        cookie_at = -1
        while end >= len(_PKG_MAGIC):
            begin = max(0, end - 65536)
            stream.seek(begin)
            block = stream.read(end - begin)
            position = block.rfind(_PKG_MAGIC)
            if position >= 0:
                cookie_at = begin + position
                break
            end = begin + len(_PKG_MAGIC) - 1
        if cookie_at < 0:
            fail('embedded archive cookie is missing')
        stream.seek(cookie_at)
        cookie = stream.read(_PKG_COOKIE.size)
        if len(cookie) != _PKG_COOKIE.size:
            fail('embedded archive cookie was truncated')
        magic, pkg_length, toc_offset, toc_length, pyvers, library = _PKG_COOKIE.unpack(cookie)
        archive_end = cookie_at + _PKG_COOKIE.size
        archive_start = archive_end - pkg_length
        if (magic != _PKG_MAGIC or pkg_length <= _PKG_COOKIE.size or archive_start < 2
                or not toc_length or toc_offset + toc_length != pkg_length - _PKG_COOKIE.size):
            fail('archive or table-of-contents boundaries are inconsistent')
        try:
            library = library.split(b'\0', 1)[0].decode('ascii')
        except UnicodeDecodeError:
            fail('Python library name is malformed')
        if not library or not pyvers:
            fail('Python runtime information is missing')
        stream.seek(archive_start + toc_offset)
        toc = stream.read(toc_length)
        if len(toc) != toc_length:
            fail('table of contents was truncated')
        entries, names, cursor = [], set(), 0
        while cursor < len(toc):
            if len(toc) - cursor < _PKG_ENTRY.size:
                fail('table entry header was truncated')
            length, offset, stored, unpacked, compressed, kind = _PKG_ENTRY.unpack_from(toc, cursor)
            if length <= _PKG_ENTRY.size or length % 16 or length > len(toc) - cursor:
                fail('table entry length is invalid')
            raw_name = toc[cursor + _PKG_ENTRY.size:cursor + length]
            if b'\0' not in raw_name:
                fail('table entry name is not terminated')
            name, padding = raw_name.split(b'\0', 1)
            if not name or padding.strip(b'\0'):
                fail('table entry name or padding is invalid')
            try:
                name = name.decode('utf-8')
                kind = kind.decode('ascii')
            except UnicodeDecodeError:
                fail('table entry text is malformed')
            if kind not in 'bdzZMmsxoln' or compressed not in (0, 1):
                fail('table entry type or compression flag is invalid')
            if offset > toc_offset or stored > toc_offset - offset:
                fail('member points outside the package data')
            if not compressed and stored != unpacked:
                fail('uncompressed member length is inconsistent')
            if kind != 'o' and name in names:
                fail('table of contents has duplicate members')
            names.add(name)
            entries.append((name, kind, offset, stored, unpacked, compressed))
            cursor += length
        if library not in names or not any(entry[1] == 's' for entry in entries) or not any(entry[1] == 'z' for entry in entries):
            fail('Python runtime, entry script or PYZ archive is missing')
        for name, kind, offset, stored, unpacked, compressed in entries:
            if not compressed:
                continue
            stream.seek(archive_start + offset)
            decoder, remaining, produced = zlib.decompressobj(), stored, 0
            try:
                while remaining:
                    block = stream.read(min(65536, remaining))
                    if not block:
                        fail('compressed member was truncated')
                    remaining -= len(block)
                    pending = block
                    while pending:
                        data = decoder.decompress(pending, min(65536, unpacked - produced + 1))
                        produced += len(data)
                        if produced > unpacked:
                            fail('compressed member exceeds its declared length')
                        pending = decoder.unconsumed_tail
                if not decoder.eof or decoder.unused_data or produced != unpacked:
                    fail('compressed member checksum, ending or length is incomplete')
            except zlib.error:
                fail('compressed member checksum is invalid')
        final, current = os.fstat(stream.fileno()), filename.stat()
        observed = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
        if observed(initial) != observed(final) or observed(initial) != observed(current):
            fail('file changed during package validation')
    return {'archive_bytes': pkg_length, 'archive_offset': archive_start,
            'cookie_offset': cookie_at, 'toc_bytes': toc_length, 'entries': len(entries),
            'python_version': pyvers, 'python_library': library}


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
    archive = validate_embedded_pkg(binary)
    before = fingerprint(WinInet().read())
    report = {'version': __version__, 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'embedded_pkg_preflight': archive}
    with tempfile.TemporaryDirectory(prefix='flowdesk-exe-') as folder:
        base = Path(folder)
        copy = base / '中文目录 with spaces' / binary.name
        copy.parent.mkdir()
        shutil.copy2(binary, copy)
        # Never launch a copy sampled while a builder is still writing it.
        copied_hash = hashlib.sha256(copy.read_bytes()).hexdigest()
        stable_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
        if copied_hash != report['sha256'] or stable_hash != report['sha256']:
            raise RuntimeError('Executable changed during test preparation; wait for the build to finish')
        if validate_embedded_pkg(copy) != archive:
            raise RuntimeError('Executable package changed during test preparation; wait for the build to finish')
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
            catalog = api('/api/catalog')
            assert catalog['schema_version'] == 1 and isinstance(catalog['apps'], list)
            assert any(app['id'] == 'flowdesk' and app['protected'] for app in catalog['apps'])
            report['application_catalog_api'] = True
            for name in ('index.html', 'app.js', 'routing-view.js', 'guide.js', 'styles.css', 'guide.css'):
                with opener.open(url + '/' + name) as response:
                    assert response.read() == (ROOT / 'web' / name).read_bytes()
            report['bundled_web_assets'] = True
            second = subprocess.run(launch, cwd=base, env=environment,
                                    creationflags=subprocess.CREATE_NO_WINDOW, timeout=45)
            assert second.returncode == 0
            assert api('/api/health')['instance_id'] == record['instance_id']
            report['repeat_launch_reuses_instance'] = True
            manual_executable = base / '中文目录 with spaces' / '手动清单验收.exe'
            shutil.copy2(copy, manual_executable)
            added = api('/api/catalog/apps', {'name': '手动清单验收', 'executable': str(manual_executable)})
            manual_app = next(app for app in added['catalog']['apps'] if app['id'] == added['app_id'])
            manual_id = manual_app['manual_id']
            assert manual_app['manual'] and manual_id
            visual_routes=api('/api/app-routes')
            assert any(route['app_id']==added['app_id'] for route in visual_routes['routes'])
            # Check the packaged policy without starting the registered app.
            profile=api('/api/catalog/launch-profile',{'app_id':added['app_id'],'mode':'http_environment','proxy_url':'http://127.0.0.1:10808'})
            assert "EnvironmentVariables['ELECTRON_GET_USE_PROXY'] = '1'" in profile['content']
            assert "EnvironmentVariables['GLOBAL_AGENT_HTTPS_PROXY'] = 'http://127.0.0.1:10808'" in profile['content']
            clear_profile=api('/api/catalog/launch-profile',{'app_id':added['app_id'],'mode':'clear_environment'})
            assert "EnvironmentVariables.Remove('ELECTRON_GET_USE_PROXY')" in clear_profile['content']
            assert "EnvironmentVariables.Remove('GLOBAL_AGENT_HTTPS_PROXY')" in clear_profile['content']
            assert "EnvironmentVariables['ELECTRON_GET_USE_PROXY'] =" not in clear_profile['content']
            report['electron_proxy_profiles']={'http_opt_in':True,'legacy_global_agent':True,'clear_removes_overrides':True,'target_application_not_launched':True}
            visual_saved=api('/api/app-routes/save',{'app_id':added['app_id'],'mode':'inherit'})
            assert any(route['app_id']==added['app_id'] and route['saved'] and route['mode']=='inherit' for route in visual_saved['routes'])
            assert not api('/api/state')['runtime']['running']
            duplicate = api('/api/catalog/apps', {'name': '手动清单验收', 'executable': str(manual_executable)})
            assert duplicate['duplicate'] is True
            assert len([app for app in duplicate['catalog']['apps'] if app.get('manual_id') == manual_id]) == 1
            assert not api('/api/state')['runtime']['running']
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
            persisted = api('/api/catalog')
            assert any(app.get('manual_id') == manual_id for app in persisted['apps'])
            visual_persisted=api('/api/app-routes')
            assert any(route['app_id']==added['app_id'] and route['saved'] for route in visual_persisted['routes'])
            report['visual_app_routes']={'save':True,'restart_persistence':True,'no_target_process_launched':True,'legacy_relay_not_started':True}
            guided = api('/api/troubleshoot')
            assert isinstance(guided['tools'], list) and isinstance(guided['catalog']['apps'], list)
            guided_check = api('/api/troubleshoot/check', {'app_id': added['app_id'],
                                'url': 'http://127.0.0.1:' + str(origin.server_port) + '/'})
            assert guided_check['recommendation']['status'] == 'target_reachable'
            assert guided_check['recommendation']['profile'] is None
            assert not api('/api/state')['runtime']['running']
            report['guided_diagnosis'] = {'api': True, 'real_loopback_target': True,
                                         'direct_success_needs_no_proxy_change': True, 'target_application_not_launched': True}
            route_options=[option for tool in api('/api/app-routes')['tools'] for option in tool['proxy_options'] if option['protocol']=='http']
            if route_options:
                selected_route=api('/api/app-routes/save',{'app_id':added['app_id'],'mode':'http_environment','proxy_url':route_options[0]['proxy_url']})
                assert any(route['app_id']==added['app_id'] and route['proxy_url']==route_options[0]['proxy_url'] for route in selected_route['routes'])
                report['visual_app_routes']['detected_http_save']=True
            api('/api/discover', {})
            observed = api('/api/state')['snapshot']
            assert observed['platform'] == 'windows'
            assert observed['layers']['wininet']['evidence_status'] == 'observed'
            assert observed['capabilities']['sections']['processes']['status'] == 'observed', observed['capabilities']['errors']
            report['read_only_discovery'] = {'windows': True, 'processes': True, 'wininet': True}
            catalog = api('/api/catalog')
            assert any(app.get('manual_id') == manual_id for app in catalog['apps'])
            removed = api('/api/catalog/apps/remove', {'manual_id': manual_id})
            assert not any(app.get('manual_id') == manual_id for app in removed['catalog']['apps'])
            assert manual_executable.exists()
            report['manual_catalog'] = {'add': True, 'deduplicate': True, 'survives_restart_and_discovery': True,
                                        'remove_keeps_program_file': True, 'selected_program_executed': False}
            protected = [app for app in catalog['apps'] if app['protected']]
            assert all(not app['launch_profile']['available'] for app in protected)
            report['application_catalog_after_discovery'] = {
                'apps': len(catalog['apps']), 'protected': len(protected),
                'launch_profiles_disabled_for_protected_apps': True,
                'network_processes_observed': 'network_processes' in observed,
            }
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
