"""Catalog uses registered paths and temp logs; never changes the host network."""
from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from proxyworkbench.catalog import Catalog


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='flowdesk-catalog-')
        self.root = Path(self.temp.name)
        self.exe = self.root / 'Steam' / 'steam.exe'
        self.exe.parent.mkdir()
        self.exe.write_bytes(b'fixture-not-an-executable')
        self.logs = self.exe.parent / 'logs'
        self.logs.mkdir()
        self.log = self.logs / 'connection_log.txt'
        self.log.write_text('connect retry\nconnection ready\n', encoding='utf-8')
        self.config = self.exe.parent / 'config' / 'config.vdf'
        self.config.parent.mkdir()
        self.config.write_text('PRIVATE_RAW_CONFIGURATION', encoding='utf-8')
        self.env = {key: str(self.root / key) for key in ('APPDATA', 'LOCALAPPDATA', 'USERPROFILE')}
        for path in self.env.values():
            Path(path).mkdir()
        self.snapshot = {
            'apps': [{'id': 'steam', 'name': 'Steam', 'category': 'application',
                      'running_processes': [{'pid': 23, 'name': 'steam.exe', 'executable': str(self.exe),
                                             'CommandLine': 'PRIVATE_COMMAND'}],
                      'installed_locations': [{'path': str(self.exe.parent), 'private_key': 'PRIVATE_INSTALLED_SECRET'}],
                      'observed_connections': {'tcp_count': 2, 'to_proxy_endpoints': []}}],
            'layers': {'wininet': {'enabled': True, 'proxy_server': 'http://user:PRIVATE_PROXY_PASS@127.0.0.1:10808'},
                       'winhttp': {'access_type': 'direct'},
                       'environment': {'user': {'values': {'HTTP_PROXY': 'http://envuser:PRIVATE_ENV_PASS@127.0.0.1:10808'}}}},
            'network_processes': [{'app_id': 'steam', 'pid': 23, 'name': 'steam.exe', 'executable': str(self.exe),
                                   'tcp_count': 2, 'connections': [
                                       {'remote_address': '127.0.0.1', 'remote_port': 10808, 'proxy_endpoint_ids': ['ep-one']},
                                       {'remote_address': None, 'remote_port': 443, 'remote_redacted': True,
                                        'remote_scope': 'non_loopback', 'proxy_endpoint_ids': []}]}],
        }

    def tearDown(self):
        self.temp.cleanup()

    def catalog(self, snapshot=None):
        return Catalog(self.snapshot if snapshot is None else snapshot, data_root=self.root, environ=self.env)

    def app(self, catalog, app_id='steam'):
        return next(app for app in catalog.describe()['apps'] if app['id'] == app_id)

    def resource(self, catalog, kind='log', app_id='steam'):
        return next(resource for resource in self.app(catalog, app_id)['resources'] if resource['kind'] == kind and resource['exists'])

    def test_catalog_connects_settings_log_locations_and_socket_evidence(self):
        catalog = self.catalog()
        app = self.app(catalog)
        self.assertEqual(app['effective_proxy'], 'unknown')
        self.assertEqual(app['connection_summary']['tcp_count'], 2)
        self.assertEqual(app['connection_summary']['status'], 'proxy_peer_observed')
        self.assertEqual(app['connection_summary']['proxy_endpoint_ids'], ['ep-one'])
        self.assertTrue(app['connection_summary']['connections'][1]['remote_redacted'])
        self.assertEqual(app['connection_summary']['connections'][1]['remote_scope'], 'non_loopback')
        self.assertEqual({item['layer'] for item in app['settings']}, {'wininet', 'winhttp', 'environment_user', 'environment_machine', 'application', 'tun'})
        text = json.dumps(catalog.describe())
        for secret in ('PRIVATE_COMMAND', 'PRIVATE_INSTALLED_SECRET', 'PRIVATE_PROXY_PASS', 'PRIVATE_ENV_PASS', 'PRIVATE_RAW_CONFIGURATION'):
            self.assertNotIn(secret, text)
        self.assertTrue(self.resource(catalog)['can_tail'])

    def test_generic_network_processes_group_by_executable(self):
        snap = deepcopy(self.snapshot)
        for pid in (40, 41):
            snap['network_processes'].append({'id': 'ignored-shared-id', 'name': 'custom.exe', 'pid': pid,
                                             'app_id': None, 'executable': str(self.root / 'custom.exe'),
                                             'tcp_count': 1, 'connections': []})
        generic = [app for app in self.catalog(snap).describe()['apps'] if app['id'].startswith('process-')]
        self.assertEqual(len(generic), 1)
        self.assertEqual(len(generic[0]['running_processes']), 2)
        self.assertEqual(generic[0]['connection_summary']['tcp_count'], 2)
        self.assertEqual(generic[0]['effective_proxy'], 'unknown')
        self.assertNotIn('direct', generic[0]['connection_summary']['status'])

    def test_known_apps_prefer_main_image_even_when_helpers_are_listed_first(self):
        for app_id, main_name, helper_name in (('steam', 'steam.exe', 'steamwebhelper.exe'),
                                               ('wgc', 'wgc.exe', 'wgc_renderer_host.exe'),
                                               ('git', 'git.exe', 'git-remote-https.exe'),
                                               ('vscode', 'Code.exe', 'crashpad_handler.exe')):
            with self.subTest(app_id=app_id):
                directory = self.root / app_id
                directory.mkdir(exist_ok=True)
                main, helper = directory / main_name, directory / helper_name
                main.write_bytes(b'fixture-main')
                helper.write_bytes(b'fixture-helper')
                snapshot = {'apps': [{'id': app_id, 'name': app_id, 'running_processes': [
                    {'pid': 1, 'executable': str(helper)}, {'pid': 2, 'executable': str(main)}]}]}
                app = self.app(self.catalog(snapshot), app_id)
                self.assertTrue(app['launch_profile']['available'])
                self.assertEqual(app['launch_profile']['executable'], str(main))
                script = self.catalog(snapshot).export_launch_profile(app_id, 'clear_environment')['content']
                self.assertIn(str(main), script)
                self.assertNotIn(str(helper), script)

    def test_helpers_alone_can_locate_resources_but_never_launch(self):
        helper_dir = self.exe.parent / 'bin' / 'cef'
        helper_dir.mkdir(parents=True)
        helper = helper_dir / 'steamwebhelper.exe'
        helper.write_bytes(b'fixture-helper')
        snapshot = {'apps': [{'id': 'steam', 'name': 'Steam', 'running_processes': [
            {'pid': 1, 'name': helper.name, 'executable': str(helper)}]}]}
        catalog = self.catalog(snapshot)
        app = self.app(catalog)
        self.assertFalse(app['launch_profile']['available'])
        self.assertIsNone(app['launch_profile']['executable'])
        self.assertIn('辅助进程', app['launch_profile']['notice'])
        self.assertTrue(any(item['path'] == str(self.logs) and item['exists'] for item in app['resources']))
        self.assertTrue(any(item['path'] == str(self.config) and item['exists'] for item in app['resources']))
        with self.assertRaises(ValueError):
            catalog.export_launch_profile('steam', 'clear_environment')

    def test_unrecognized_app_may_launch_its_exact_observed_image(self):
        custom = self.exe.parent / 'custom-helper.exe'
        custom.write_bytes(b'fixture')
        snapshot = {'apps': [{'id': 'custom', 'name': 'Custom helper', 'running_processes': [
            {'pid': 1, 'executable': str(custom)}]}]}
        app = self.app(self.catalog(snapshot), 'custom')
        self.assertTrue(app['launch_profile']['available'])
        self.assertEqual(app['launch_profile']['executable'], str(custom))

    def test_unknown_without_executable_has_no_launch_script(self):
        snap = {'network_processes': [{'name': 'private.exe', 'pid': 9, 'tcp_count': 1, 'connections': []}]}
        generic = next(app for app in self.catalog(snap).describe()['apps'] if app['id'].startswith('process-'))
        self.assertFalse(generic['launch_profile']['available'])
        self.assertEqual(generic['launch_profile']['modes'], [])

    def test_candidates_are_not_reported_as_existing(self):
        app = self.app(self.catalog())
        missing = next(item for item in app['resources'] if not item['exists'])
        self.assertEqual(missing['status'], 'candidate')
        self.assertFalse(missing['can_tail'])
        self.assertFalse(missing['can_open'])
        self.config.unlink()
        missing_config = next(item for item in self.app(self.catalog())['resources'] if item['kind'] == 'config')
        self.assertFalse(missing_config['exists'])
        self.assertIn('当前未发现', missing_config['notice'])
        self.assertNotIn('已存在', missing_config['notice'])

    def test_config_only_opens_parent_and_cannot_be_read(self):
        catalog = self.catalog()
        resource = self.resource(catalog, 'config')
        with self.assertRaises(ValueError):
            catalog.tail('steam', resource['id'])
        opened = []
        result = catalog.open_resource('steam', resource['id'], opener=opened.append)
        self.assertTrue(result['opened'])
        self.assertEqual(opened, [str(self.config.parent)])

    def test_resource_id_and_application_must_both_match(self):
        catalog = self.catalog()
        identifier = self.resource(catalog)['id']
        for resource_id in ('../../secret.log', str(self.config), 'res-unknown', None, []):
            with self.subTest(resource_id=resource_id), self.assertRaises(ValueError):
                catalog.tail('steam', resource_id)
        with self.assertRaises(ValueError):
            catalog.tail('flowdesk', identifier)
        with self.assertRaises(ValueError):
            catalog.open_resource('flowdesk', identifier, opener=lambda path: self.fail('opened wrong app'))

    def test_tail_is_bounded_and_hides_credentials_even_in_json_lines(self):
        self.log.write_text('\n'.join([
            'ordinary startup log', '{"authorization": "PRIVATE_AUTH_VALUE"}',
            'HTTP_PROXY=http://u:PRIVATE_URL_PASS@127.0.0.1:10808/private/path?auth=PRIVATE_QUERY',
            'connect https://server.example/PRIVATE_PATH?key=PRIVATE_KEY',
            'node vless://PRIVATE_NODE_LINK',
            'password=PRIVATE_PASSWORD',
            'key sk-PRIVATE_API_KEY_abcdefghijklmno', 'connection ready',
        ]), encoding='utf-8')
        catalog = self.catalog()
        result = catalog.tail('steam', self.resource(catalog)['id'], 65536)
        self.assertTrue(result['redacted'])
        self.assertIn('connection ready', result['content'])
        for secret in ('PRIVATE_AUTH_VALUE', 'PRIVATE_URL_PASS', 'PRIVATE_QUERY', 'PRIVATE_PATH', 'PRIVATE_KEY', 'PRIVATE_NODE_LINK', 'PRIVATE_PASSWORD', 'PRIVATE_API_KEY'):
            self.assertNotIn(secret, result['content'])
        self.log.write_text('x' * 100000 + '\nlast line\n', encoding='utf-8')
        result = catalog.tail('steam', self.resource(catalog)['id'], 200)
        self.assertTrue(result['truncated'])
        self.assertLessEqual(len(result['content']), 200)
        self.assertIn('last line', result['content'])
        for value in (0, -1, 65537, True, '100'):
            with self.assertRaises(ValueError):
                catalog.tail('steam', self.resource(catalog)['id'], value)

    def test_private_key_block_is_not_returned(self):
        self.log.write_text('prefix\n-----BEGIN PRIVATE KEY-----\nPRIVATE_PEM_DATA\n-----END PRIVATE KEY-----\n', encoding='utf-8')
        catalog = self.catalog()
        result = catalog.tail('steam', self.resource(catalog)['id'])
        self.assertNotIn('PRIVATE_PEM_DATA', result['content'])

    def test_tail_drops_partial_first_line_without_its_sensitive_field_name(self):
        self.log.write_text('password=' + 'PRIVATE_FRAGMENT_' * 1000, encoding='utf-8')
        catalog = self.catalog()
        result = catalog.tail('steam', self.resource(catalog)['id'], 100)
        self.assertTrue(result['truncated'])
        self.assertEqual(result['content'], '')

    def test_replaced_or_missing_log_requires_redetection(self):
        catalog = self.catalog()
        resource = self.resource(catalog)
        moved = self.log.with_suffix('.old')
        self.log.rename(moved)
        self.log.write_text('PRIVATE_REPLACEMENT', encoding='utf-8')
        with self.assertRaises(ValueError):
            catalog.tail('steam', resource['id'])
        self.log.unlink()
        with self.assertRaises(ValueError):
            catalog.tail('steam', resource['id'])

    def test_hardlinked_log_is_never_returned(self):
        link = self.logs / 'other.log'
        os.link(self.log, link)
        catalog = self.catalog()
        resources = [item for item in self.app(catalog)['resources'] if item['kind'] == 'log']
        self.assertFalse(resources)

    def test_binary_log_is_rejected(self):
        self.log.write_bytes(b'not text\0PRIVATE_BINARY')
        catalog = self.catalog()
        with self.assertRaises(ValueError):
            catalog.tail('steam', self.resource(catalog)['id'])

    def test_directory_symlink_cannot_escape_registered_locations(self):
        target = self.root / 'private'
        target.mkdir()
        (target / 'secrets.log').write_text('PRIVATE_LINK_TARGET', encoding='utf-8')
        link = self.exe.parent / 'log'
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError:
            # Some Windows hosts prohibit symlink creation.  Model the same
            # reparse flag so this boundary is still exercised without a skip.
            from proxyworkbench import catalog as module
            original = Path.lstat
            def marked(path):
                info = original(path)
                if path == self.logs:
                    class Entry:
                        st_mode = info.st_mode
                        st_file_attributes = 0x400
                    return Entry()
                return info
            with patch.object(Path, 'lstat', marked):
                catalog = self.catalog()
                resource = next(item for item in self.app(catalog)['resources'] if item['path'] == str(self.logs))
                self.assertFalse(resource['exists'])
                self.assertFalse(resource['can_open'])
            return
        catalog = self.catalog()
        resource = next(item for item in self.app(catalog)['resources'] if item['path'] == str(link))
        self.assertEqual(resource['status'], 'blocked')
        self.assertFalse(resource['can_open'])
        self.assertNotIn('PRIVATE_LINK_TARGET', json.dumps(catalog.describe()))

    def test_export_only_returns_script_and_does_not_execute_or_change_environment(self):
        catalog = self.catalog()
        before = dict(os.environ)
        with patch('subprocess.Popen', side_effect=AssertionError('no process may be launched')):
            result = catalog.export_launch_profile('steam', 'http_environment', 'http://127.0.0.1:10808')
        self.assertEqual(dict(os.environ), before)
        self.assertTrue(result['filename'].endswith('.ps1'))
        self.assertIn('param([switch]$Launch)', result['content'])
        self.assertIn('EnvironmentVariables', result['content'])
        self.assertIn("'HTTP_PROXY'", result['content'])
        for name in ('ELECTRON_GET_USE_PROXY','GLOBAL_AGENT_HTTP_PROXY','GLOBAL_AGENT_HTTPS_PROXY',
                     'GLOBAL_AGENT_NO_PROXY','GLOBAL_AGENT_ENVIRONMENT_VARIABLE_NAMESPACE'):
            self.assertIn("EnvironmentVariables['" + name + "'] =", result['content'])
        self.assertIn("EnvironmentVariables['ELECTRON_GET_USE_PROXY'] = '1'",result['content'])
        self.assertIn("EnvironmentVariables['GLOBAL_AGENT_HTTPS_PROXY'] = 'http://127.0.0.1:10808'",result['content'])
        self.assertNotIn('SetEnvironmentVariable', result['content'])
        self.assertNotIn('Stop-Process', result['content'])
        self.assertNotIn('netsh', result['content'])
        self.assertIn('Get-Process', result['content'])
        self.assertIn('不等于强制', ''.join(result['limitations']))

    def test_clear_environment_is_not_a_global_proxy_reset(self):
        result = self.catalog().export_launch_profile('steam', 'clear_environment')
        self.assertIn("EnvironmentVariables.Remove('ALL_PROXY')", result['content'])
        self.assertNotIn('WinINet', result['content'])
        self.assertNotIn("EnvironmentVariables['ALL_PROXY'] =", result['content'])
        for name in ('ELECTRON_GET_USE_PROXY','GLOBAL_AGENT_HTTP_PROXY','GLOBAL_AGENT_HTTPS_PROXY',
                     'GLOBAL_AGENT_NO_PROXY','GLOBAL_AGENT_ENVIRONMENT_VARIABLE_NAMESPACE'):
            self.assertIn("EnvironmentVariables.Remove('" + name + "')",result['content'])
            self.assertNotIn("EnvironmentVariables['" + name + "'] =",result['content'])

    def test_proxy_profile_rejects_credentials_commands_and_unsupported_protocols(self):
        catalog = self.catalog()
        for url in ('http://user:pass@127.0.0.1:10808', 'http://127.0.0.1:10808/path', 'http://127.0.0.1:10808/?token=secret',
                    'http://127.0.0.1', 'https://127.0.0.1:10808', 'http://127.0.0.1:99999', 'http://127.0.0.1:10808\nwhoami'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                catalog.export_launch_profile('steam', 'http_environment', url)
        with self.assertRaises(ValueError):
            catalog.export_launch_profile('steam', 'socks_environment', 'socks5://127.0.0.1:10808')
        with self.assertRaises(ValueError):
            catalog.export_launch_profile('steam', 'http_environment', 'http://127.0.0.1:10808', ['line\ncommand'])

    def test_curl_supports_socks_and_safe_argument_quoting(self):
        curl = self.exe.parent / "curl.exe"
        curl.write_bytes(b'fixture')
        snapshot = {'apps': [{'id': 'curl', 'name': 'curl', 'running_processes': [{'pid': 3, 'name': 'curl.exe', 'executable': str(curl)}]}]}
        result = self.catalog(snapshot).export_launch_profile('curl', 'socks_environment', 'socks5h://[::1]:10808', ["a'$(Get-Secret)", 'space argument'])
        self.assertIn("'socks5h://[::1]:10808'", result['content'])
        self.assertIn("a''$(Get-Secret)", result['content'])
        self.assertNotIn('Get-Process', result['content'])
        self.assertNotIn("EnvironmentVariables['HTTP_PROXY'] =", result['content'])
        self.assertIn("EnvironmentVariables.Remove('ELECTRON_GET_USE_PROXY')",result['content'])
        self.assertNotIn("EnvironmentVariables['ELECTRON_GET_USE_PROXY'] =",result['content'])

    def test_codex_and_proxy_cores_cannot_export_relaunch_scripts(self):
        snapshot = {'apps': []}
        for app_id, name in (('codex', 'Codex.exe'), ('xray', 'xray.exe'), ('v2rayn', 'v2rayN.exe'), ('uu', 'uu.exe')):
            exe = self.exe.parent / name
            exe.write_bytes(b'fixture')
            snapshot['apps'].append({'id': app_id, 'name': name, 'running_processes': [{'pid': 4, 'executable': str(exe)}]})
        catalog = self.catalog(snapshot)
        for app in catalog.describe()['apps']:
            self.assertTrue(app['protected'])
            self.assertFalse(app['launch_profile']['available'])
            with self.assertRaises(ValueError):
                catalog.export_launch_profile(app['id'], 'clear_environment')

    def test_describe_cannot_mutate_resource_authorization(self):
        catalog = self.catalog()
        described = catalog.describe()
        config = next(item for item in described['apps'] if item['id'] == 'steam')['resources']
        resource = next(item for item in config if item['kind'] == 'config')
        resource['can_tail'] = True
        with self.assertRaises(ValueError):
            catalog.tail('steam', resource['id'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
