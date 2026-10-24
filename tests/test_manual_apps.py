"""Manual registration is metadata only; fixtures never run target programs."""
from copy import deepcopy
import http.client
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from proxyworkbench.catalog import application_executable_path, manual_apps_document
from proxyworkbench.service import Service
from proxyworkbench.server import ControlServer


class DetachedLease:
    def status(self):
        return {'phase': 'detached'}

    def close(self):
        pass


class ManualAppsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='flowdesk-manual-app-')
        self.root = Path(self.temp.name)
        self.exe = self.root / 'Custom application.exe'
        self.exe.write_bytes(b'fixture, not executable code')
        self.service = Service(self.root, discover=False, lease=DetachedLease())
        self.registry = self.root / '.local' / 'custom-apps.json'

    def tearDown(self):
        self.service.close()
        self.temp.cleanup()

    def add(self, executable=None, name=None):
        return self.service.catalog_add_app({'executable': str(executable or self.exe), 'name': name})

    def registered(self, catalog=None):
        return [app for app in (catalog or self.service.catalog_state())['apps'] if app['manual']]

    def test_add_records_exact_path_and_never_executes_or_changes_network(self):
        before_env, before_snapshot = dict(os.environ), deepcopy(self.service.snapshot)
        with patch('subprocess.Popen', side_effect=AssertionError('registration may not launch processes')):
            added = self.add(name='我的软件')
        app = self.registered(added['catalog'])[0]
        self.assertEqual(app['id'], added['app_id'])
        self.assertEqual(app['name'], '我的软件')
        self.assertEqual(app['executable'], str(self.exe))
        self.assertTrue(app['manual'])
        self.assertRegex(app['manual_id'], r'^manual-[a-f0-9]{32}$')
        self.assertTrue(app['launch_profile']['available'])
        self.assertFalse(app['running_processes'])
        saved = json.loads(self.registry.read_text(encoding='utf-8'))
        self.assertEqual(saved['schema_version'], 1)
        self.assertEqual(saved['apps'][0]['executable'], str(self.exe))
        self.assertEqual(dict(os.environ), before_env)
        self.assertEqual(self.service.snapshot, before_snapshot)
        self.assertFalse(self.service.relay.status()['running'])
        self.assertEqual(self.service.lease.status()['phase'], 'detached')

    def test_registration_survives_restart_and_discovery_refresh(self):
        original = self.add()
        identifier = self.registered()[0]['manual_id']
        self.service.close()
        self.service = Service(self.root, discover=False, lease=DetachedLease())
        self.assertEqual(self.registered()[0]['manual_id'], identifier)
        with patch('proxyworkbench.discovery.snapshot', return_value={'captured_at': 'fixture', 'apps': [], 'endpoints': []}):
            self.service.discover()
        self.assertEqual(self.registered()[0]['manual_id'], identifier)
        self.assertEqual(self.registered()[0]['id'], original['app_id'])

    def test_duplicate_path_selects_existing_record_without_overwriting_its_name(self):
        initial = self.add(name='Original')
        before = self.registry.read_bytes()
        again = self.add(name='A different label')
        self.assertTrue(again['duplicate'])
        self.assertEqual(initial['app_id'], again['app_id'])
        self.assertEqual(len(self.registered()), 1)
        self.assertEqual(self.registered()[0]['name'], 'Original')
        self.assertEqual(self.registry.read_bytes(), before)

    def test_manual_path_merges_automatic_app_and_remove_preserves_automatic_app(self):
        self.service.snapshot = {'apps': [{'id': 'custom-auto', 'name': 'Automatically found', 'category': 'application',
                                           'running_processes': [{'pid': 10, 'name': self.exe.name, 'executable': str(self.exe)}]}]}
        original_snapshot = deepcopy(self.service.snapshot)
        added = self.add(name='User label')
        self.assertEqual(added['app_id'], 'custom-auto')
        app = self.registered()[0]
        self.assertEqual(len([item for item in added['catalog']['apps'] if item['executable'] == str(self.exe)]), 1)
        with patch('subprocess.Popen', side_effect=AssertionError('remove may not stop or start programs')):
            removed = self.service.catalog_remove_app({'manual_id': app['manual_id']})
        remaining = next(item for item in removed['catalog']['apps'] if item['id'] == 'custom-auto')
        self.assertFalse(remaining['manual'])
        self.assertIsNone(remaining['manual_id'])
        self.assertEqual(remaining['name'], 'Automatically found')
        self.assertEqual(self.service.snapshot, original_snapshot)
        self.assertTrue(self.exe.exists())

    def test_discovery_can_change_app_id_without_changing_manual_remove_id(self):
        app = self.registered(self.add()['catalog'])[0]
        self.service.snapshot = {'apps': [{'id': 'discovered-later', 'name': 'Custom',
                                           'running_processes': [{'pid': 10, 'executable': str(self.exe)}]}]}
        self.service._catalog_cache = None
        refreshed = self.registered()[0]
        self.assertEqual(refreshed['id'], 'discovered-later')
        self.assertEqual(refreshed['manual_id'], app['manual_id'])
        removed = self.service.catalog_remove_app({'manual_id': app['manual_id']})
        self.assertFalse(next(item for item in removed['catalog']['apps'] if item['id'] == 'discovered-later')['manual'])

    def test_multiple_images_of_one_automatic_app_keep_every_manual_registration(self):
        executables = []
        for directory in ('installation-one', 'installation-two'):
            folder = self.root / directory
            folder.mkdir()
            image = folder / 'python.exe'
            image.write_bytes(b'fixture')
            executables.append(image)
        self.service.snapshot = {'apps': [{'id': 'python', 'name': 'Python', 'category': 'application',
                                           'running_processes': [{'pid': 30 + index, 'name': 'python.exe', 'executable': str(image)}
                                                                 for index, image in enumerate(executables)]}],
                                 'network_processes': [{'app_id': 'python', 'pid': 30 + index, 'name': 'python.exe',
                                                        'executable': str(image), 'tcp_count': 1, 'connections': []}
                                                       for index, image in enumerate(executables)]}
        self.add(executables[0], 'Python one')
        self.add(executables[1], 'Python two')
        apps = self.registered()
        self.assertEqual(len(apps), 2)
        self.assertEqual({app['executable'] for app in apps}, {str(image) for image in executables})
        self.assertEqual(len({app['manual_id'] for app in apps}), 2)
        second = next(app for app in apps if app['executable'] == str(executables[1]))
        self.assertEqual([entry['pid'] for entry in second['running_processes']], [31])
        self.assertEqual(second['connection_summary']['tcp_count'], 1)
        for image in executables:
            self.assertTrue(self.add(image)['duplicate'])
        identifiers = [app['manual_id'] for app in apps]
        # Removing the first registration can change the second app_id back to
        # 'python'; its stable manual_id still makes the next removal exact.
        self.service.catalog_remove_app({'manual_id': identifiers[0]})
        self.assertEqual(len(self.registered()), 1)
        self.service.catalog_remove_app({'manual_id': identifiers[1]})
        self.assertFalse(self.registered())
        self.assertTrue(any(app['id'] == 'python' for app in self.service.catalog_state()['apps']))

    def test_installed_directory_merges_only_its_known_exact_main_program(self):
        directory = self.root / 'Steam installation'
        directory.mkdir()
        main, unrelated = directory / 'steam.exe', directory / 'different-tool.exe'
        main.write_bytes(b'fixture')
        unrelated.write_bytes(b'fixture')
        self.service.snapshot = {'apps': [{'id': 'steam', 'name': 'Steam', 'category': 'application',
                                           'running_processes': [], 'installed_locations': [{'path': str(directory)}]}]}
        added = self.add(main, 'Installed Steam')
        self.assertEqual(added['app_id'], 'steam')
        self.assertEqual(len([app for app in added['catalog']['apps'] if app['executable'] == str(main)]), 1)
        self.assertTrue(self.registered()[0]['launch_profile']['available'])
        other = self.add(unrelated, 'Unrelated tool')
        self.assertNotEqual(other['app_id'], 'steam')
        self.assertEqual(len(self.registered()), 2)

    def test_deleted_program_remains_registered_unlaunchable_and_removable(self):
        registered = self.registered(self.add()['catalog'])[0]
        self.exe.unlink()
        # Even the existing cached catalog must stop advertising a launchable
        # entry; a page refresh alone does not rebuild socket/log evidence.
        self.assertFalse(self.registered()[0]['launch_profile']['available'])
        with self.assertRaises(ValueError):
            self.service.catalog_launch_profile({'app_id': registered['id'], 'mode': 'clear_environment'})
        self.service.close()
        self.service = Service(self.root, discover=False, lease=DetachedLease())
        stale = self.registered()[0]
        self.assertEqual(stale['manual_id'], registered['manual_id'])
        self.assertEqual(stale['executable'], str(self.exe))
        self.assertFalse(stale['launch_profile']['available'])
        self.assertIn('失效', stale['launch_profile']['notice'])
        with self.assertRaises(ValueError):
            self.service.catalog_launch_profile({'app_id': stale['id'], 'mode': 'clear_environment'})
        self.service.catalog_remove_app({'manual_id': stale['manual_id']})
        self.assertFalse(self.registered())

    def test_custom_name_cannot_bypass_core_protection(self):
        for filename in ('Codex.exe', 'xray.exe', 'v2rayN.exe'):
            executable = self.root / filename
            executable.write_bytes(b'fixture')
            result = self.add(executable, 'Ordinary notes app')
            app = next(item for item in result['catalog']['apps'] if item['id'] == result['app_id'])
            self.assertTrue(app['protected'], filename)
            self.assertFalse(app['launch_profile']['available'])
            with self.assertRaises(ValueError):
                self.service.catalog_launch_profile({'app_id': app['id'], 'mode': 'clear_environment'})

    def test_automatic_protected_identity_survives_manual_custom_name(self):
        self.service.snapshot = {'apps': [{'id': 'codex', 'name': 'Codex', 'category': 'application',
                                           'running_processes': [{'pid': 10, 'executable': str(self.exe)}]}]}
        result = self.add(name='Not the original label')
        self.assertEqual(result['app_id'], 'codex')
        app = self.registered()[0]
        self.assertTrue(app['protected'])
        self.assertFalse(app['launch_profile']['available'])

    def test_invalid_paths_and_names_do_not_create_a_registry(self):
        wrong_file = self.root / 'text.txt'
        wrong_file.write_text('fixture', encoding='utf-8')
        paths = ('', None, 42, 'relative.exe', str(self.root), str(wrong_file),
                 str(self.exe) + ' --proxy=127.0.0.1', '"' + str(self.exe) + '"',
                 str(self.exe) + ':alternate.exe', str(self.exe) + '\n',
                 r'\\server\private-share\tool.exe', r'\\?\C:\tool.exe')
        for path in paths:
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.service.catalog_add_app({'executable': path})
        for name in (42, 'x' * 101, 'bad\nname', 'bad\u202ename'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.add(name=name)
        self.assertFalse(self.registry.exists())
        self.assertFalse(self.registered())

    def test_unc_is_rejected_before_any_filesystem_query(self):
        with patch.object(Path, 'lstat', side_effect=AssertionError('must not query network shares')):
            with self.assertRaises(ValueError):
                application_executable_path(r'\\server\private-share\tool.exe')

    def test_reparse_executable_is_rejected_without_losing_other_registrations(self):
        self.add()
        before = self.registry.read_bytes()
        link = self.root / 'link.exe'
        try:
            link.symlink_to(self.exe)
        except OSError:
            original = Path.lstat
            def marked(path):
                info = original(path)
                if path == self.exe:
                    class Reparse:
                        st_mode = info.st_mode
                        st_file_attributes = 0x400
                    return Reparse()
                return info
            with patch.object(Path, 'lstat', marked), self.assertRaises(ValueError):
                self.add()
        else:
            with self.assertRaises(ValueError):
                self.add(link)
        self.assertEqual(self.registry.read_bytes(), before)

    def test_failed_atomic_write_does_not_change_memory_or_existing_registry(self):
        self.add()
        before = self.registry.read_bytes()
        original = deepcopy(self.service.custom_apps)
        other = self.root / 'other.exe'
        other.write_bytes(b'fixture')
        with patch('proxyworkbench.system_proxy.os.replace', side_effect=OSError('fixture storage failure')):
            with self.assertRaises(OSError):
                self.add(other)
            with self.assertRaises(OSError):
                self.service.catalog_remove_app({'manual_id': original[0]['id']})
        self.assertEqual(self.service.custom_apps, original)
        self.assertEqual(self.registry.read_bytes(), before)
        self.assertFalse(list(self.registry.parent.glob('custom-apps.json.*.tmp')))

    def test_corrupt_registry_is_preserved_and_not_silently_overwritten(self):
        self.service.close()
        self.registry.write_text('{ broken private metadata', encoding='utf-8')
        before = self.registry.read_bytes()
        self.service = Service(self.root, discover=False, lease=DetachedLease())
        self.assertTrue(self.service.catalog_state()['manual_registry_error'])
        with self.assertRaises(RuntimeError):
            self.add()
        self.assertEqual(self.registry.read_bytes(), before)

    def test_only_registered_manual_id_can_be_removed(self):
        self.add()
        before = self.registry.read_bytes()
        for value in ({'app_id': 'flowdesk'}, {'manual_id': 'flowdesk'}, {'manual_id': None}, {'manual_id': '../plan.json'}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.service.catalog_remove_app(value)
        self.assertEqual(self.registry.read_bytes(), before)

    def test_stored_document_rejects_duplicate_ids_paths_and_extra_sensitive_fields(self):
        one = {'id': 'manual-' + 'a' * 32, 'name': 'One', 'executable': str(self.exe), 'private_key': 'MUST_NOT_ESCAPE'}
        parsed = manual_apps_document({'schema_version': 1, 'apps': [one]})
        self.assertNotIn('private_key', parsed['apps'][0])
        with self.assertRaises(ValueError):
            manual_apps_document({'schema_version': 1, 'apps': [one, dict(one, id='manual-' + 'b' * 32)]})


class ManualAppsApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='flowdesk-manual-api-')
        self.root = Path(self.temp.name)
        self.exe = self.root / 'Target.exe'
        self.exe.write_bytes(b'fixture')
        self.service = Service(self.root, discover=False, lease=DetachedLease())
        self.server = ControlServer(('127.0.0.1', 0), self.root, discover=False, service=self.service)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.service.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
        self.temp.cleanup()

    def request(self, path, value, *, auth=True, headers=None):
        supplied = {'Content-Type': 'application/json'}
        if auth:
            supplied['X-Session-Token'] = self.server.token
        supplied.update(headers or {})
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=8)
        connection.request('POST', path, json.dumps(value), headers=supplied)
        response = connection.getresponse()
        result = response.status, json.loads(response.read())
        connection.close()
        return result

    def test_add_remove_and_picker_require_session_and_same_origin(self):
        with patch('proxyworkbench.file_picker.choose_executable', side_effect=AssertionError('unauthorized picker')):
            for path in ('/api/catalog/apps', '/api/catalog/apps/remove', '/api/catalog/pick-executable'):
                with self.subTest(path=path):
                    self.assertEqual(self.request(path, {}, auth=False)[0], 403)
                    self.assertEqual(self.request(path, {}, headers={'Origin': 'https://untrusted.example'})[0], 403)
        self.assertFalse((self.root / '.local' / 'custom-apps.json').exists())

    def test_api_roundtrip_only_registers_metadata_and_picker_does_not_register(self):
        with patch('proxyworkbench.file_picker.choose_executable', return_value={'cancelled': False, 'executable': str(self.exe)}) as picker:
            status, picked = self.request('/api/catalog/pick-executable', {})
        self.assertEqual(status, 200)
        self.assertEqual(picked['executable'], str(self.exe))
        picker.assert_called_once_with()
        self.assertFalse((self.root / '.local' / 'custom-apps.json').exists())
        status, added = self.request('/api/catalog/apps', {'name': 'Manual', 'executable': str(self.exe)})
        self.assertEqual(status, 200)
        app = next(item for item in added['catalog']['apps'] if item['id'] == added['app_id'])
        self.assertTrue(app['manual'])
        status, removed = self.request('/api/catalog/apps/remove', {'manual_id': app['manual_id']})
        self.assertEqual(status, 200)
        self.assertFalse(any(item['manual'] for item in removed['catalog']['apps']))
        self.assertTrue(self.exe.exists())
        self.assertFalse(self.service.relay.status()['running'])
        self.assertEqual(self.service.lease.status()['phase'], 'detached')

    def test_bad_path_and_nonmanual_removal_are_client_errors(self):
        self.assertEqual(self.request('/api/catalog/apps', {'executable': 'relative.exe'})[0], 400)
        self.assertEqual(self.request('/api/catalog/apps/remove', {'manual_id': 'flowdesk'})[0], 400)


if __name__ == '__main__':
    unittest.main(verbosity=2)
