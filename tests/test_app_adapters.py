"""Cross-structure workflow fixtures; never execute a user application."""
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from proxyworkbench import app_adapters as adapters, app_connections as connections
from proxyworkbench import process_proxy
from proxyworkbench.app_routes import describe, route_key


class FixtureBackendAdapter(adapters.ManagedBackendAdapter):
    """A second backend layout, deliberately unrelated to the vendor adapter."""
    id = 'fixture_background_service'
    label = '测试桌面与服务'
    restart_scope = '重启本样例服务；窗口会重新连接。'

    def __init__(self, executable):
        super().__init__(executable)
        self.subject = {'ProcessId': 1001, 'ParentProcessId': 1, 'Started': '45',
                        'ExecutablePath': str(Path(executable).parent / 'fixture-worker.exe')}
        self.state = 'running'
        self.active_tasks = 0
        self.matches = True
        self.pending = False
        self.values = {}
        self.actions = []
        self.apply_values = True

    def backend(self, items):
        if self.state == 'stopped':
            return {'state': self.state}
        return {'state': self.state, 'active_tasks': self.active_tasks,
                'pid': self.subject['ProcessId'], '_process': self.subject}

    def context_matches(self, values):
        return self.matches

    def lifecycle_pending(self, items):
        return self.pending

    def apply_backend(self, environment, *, restart):
        self.actions.append({'restart': restart})
        self.state = 'running'
        if self.apply_values:
            self.values = dict(environment)


class GenericAdapterWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='flowdesk-adapters-')
        self.root = Path(self.directory.name)
        self.executable = self.root / 'unregistered-client.exe'
        self.executable.write_bytes(b'fixture; never execute')
        self.record = {'key': route_key(str(self.executable)), 'executable': str(self.executable),
                       'mode': 'http_environment', 'proxy_url': 'http://127.0.0.1:45678', 'updated_at': ''}
        (self.root / '.local').mkdir()
        self.save()
        self.adapter = FixtureBackendAdapter(str(self.executable))
        self.patches = [
            patch.object(adapters, 'resolve', return_value=self.adapter),
            patch.object(process_proxy, 'records', return_value=[self.adapter.subject]),
            patch.object(process_proxy, 'proxy_values', side_effect=lambda _: dict(self.adapter.values)),
            patch.object(connections.socket, 'create_connection', return_value=Mock(__enter__=Mock(), __exit__=Mock())),
            patch.dict(os.environ, {}, clear=True),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.directory.cleanup()

    def save(self):
        (self.root / '.local/app-routes.json').write_text(
            json.dumps({'schema_version': 1, 'routes': [self.record]}), encoding='utf-8')

    def test_second_backend_uses_same_ticket_apply_and_verification(self):
        report = connections.public_check(connections.inspect(self.record))
        self.assertEqual(report['environment_status'], 'missing')
        self.assertTrue(report['capabilities']['managed_backend'])
        self.assertEqual(report['adapter']['id'], self.adapter.id)
        reviews = connections.LaunchReviews(self.root)
        preview = reviews.prepare(self.record)
        self.assertTrue(preview['requires_confirmation'])
        self.assertIn(self.adapter.restart_scope, preview['steps'])
        with patch.object(connections.app_launch, 'launch', return_value={'pid': 20}) as launch:
            result = reviews.apply(self.record, preview['ticket'])
        self.assertEqual(self.adapter.actions, [{'restart': True}])
        self.assertEqual(result['pid'], self.adapter.subject['ProcessId'])
        self.assertIn('尚未验证', result['notice'])
        self.assertEqual(launch.call_args.kwargs['environment']['HTTPS_PROXY'], self.record['proxy_url'])
        with self.assertRaisesRegex(ValueError, '过期'):
            reviews.apply(self.record, preview['ticket'])

    def test_shared_guards_refuse_tasks_pending_identity_and_old_window(self):
        self.adapter.active_tasks = 1
        self.assertFalse(connections.plan(self.record)['can_launch'])
        self.adapter.active_tasks = 0
        self.adapter.pending = True
        self.assertFalse(connections.plan(self.record)['can_launch'])
        self.adapter.pending = False
        self.adapter.matches = False
        self.assertFalse(connections.plan(self.record)['can_launch'])
        self.adapter.matches = True
        desktop = {'ProcessId': 1002, 'ParentProcessId': 1, 'Started': '46',
                   'ExecutablePath': str(self.executable)}
        with patch.object(process_proxy, 'records', return_value=[self.adapter.subject, desktop]):
            self.assertIn('退出旧窗口', connections.plan(self.record)['summary'])
        self.assertEqual(self.adapter.actions, [])

    def test_incomplete_task_evidence_is_not_treated_as_idle(self):
        for active in (None, '0', -1, False):
            with self.subTest(active=active):
                self.adapter.active_tasks = active
                report = connections.inspect(self.record)
                self.assertEqual(report['backend']['state'], 'unknown')
                self.assertFalse(connections.plan(self.record)['can_launch'])
        self.assertEqual(self.adapter.actions, [])

    def test_changed_subject_and_saved_route_invalidate_review_before_action(self):
        prepared = connections.plan(self.record)
        self.adapter.subject['Started'] = '99'
        with self.assertRaisesRegex(ValueError, '状态已变化'):
            connections.execute(self.root, self.record, prepared)
        self.assertEqual(self.adapter.actions, [])
        prepared = connections.plan(self.record)
        old = deepcopy(self.record)
        self.record.update(mode='clear_environment', proxy_url='')
        self.save()
        with self.assertRaisesRegex(ValueError, '设置已变化'):
            connections.execute(self.root, old, prepared)
        self.assertEqual(self.adapter.actions, [])

    def test_post_apply_mismatch_does_not_open_desktop_or_claim_success(self):
        self.adapter.apply_values = False
        prepared = connections.plan(self.record)
        with patch.object(connections.app_launch, 'launch') as launch:
            with self.assertRaisesRegex(ValueError, '尚未确认'):
                connections.execute(self.root, self.record, prepared)
            launch.assert_not_called()
        self.assertEqual(self.adapter.actions, [{'restart': True}])

    def test_matching_backend_reused_and_stopped_backend_started_without_restart(self):
        self.adapter.values = self.adapter.environment({}, self.record)
        for state in ('running', 'stopped'):
            with self.subTest(state=state):
                self.adapter.state = state
                prepared = connections.plan(self.record)
                self.assertTrue(prepared['can_launch'])
                self.assertFalse(prepared['requires_confirmation'])
                with patch.object(connections.app_launch, 'launch', return_value={'pid': 20}):
                    connections.execute(self.root, self.record, prepared)
                self.assertEqual(self.adapter.actions[-1], {'restart': False})

    def test_unknown_application_uses_generic_environment_workflow(self):
        ordinary = adapters.ApplicationAdapter(str(self.executable))
        with patch.object(adapters, 'resolve', return_value=ordinary), patch.object(process_proxy, 'records', return_value=[]):
            report = connections.public_check(connections.inspect(self.record))
            self.assertFalse(report['capabilities']['managed_backend'])
            self.assertEqual(report['environment_status'], 'not_running')
            preview = connections.plan(self.record)
            with patch.object(connections.app_launch, 'launch', return_value={'pid': 22}) as launch:
                result = connections.execute(self.root, self.record, preview)
            self.assertEqual(result['pid'], 22)
            launch.assert_called_once_with(str(self.executable), self.record['proxy_url'], self.record['mode'])
        self.assertEqual(self.adapter.actions, [])

    def test_unreadable_ordinary_environment_is_unknown_and_live_instance_is_preserved(self):
        main = {'ProcessId': 1002, 'ParentProcessId': 1, 'Started': '46', 'ExecutablePath': str(self.executable)}
        with patch.object(adapters, 'resolve', return_value=adapters.ApplicationAdapter(str(self.executable))), \
                patch.object(process_proxy, 'records', return_value=[main]), \
                patch.object(process_proxy, 'proxy_values', side_effect=ValueError('no access')):
            report = connections.public_check(connections.inspect(self.record))
            self.assertEqual(report['environment_status'], 'unknown')
            self.assertFalse(connections.plan(self.record)['can_launch'])

    def test_generic_report_hides_adapter_private_context_and_proxy_credentials(self):
        self.adapter.values = {'HTTP_PROXY': 'http://secret:secret@127.0.0.1:123/private?secret=secret'}
        report = connections.public_check(connections.inspect(self.record))
        text = json.dumps(report)
        self.assertNotIn('secret', text)
        self.assertNotIn('_adapter', report)
        self.assertNotIn('_process', report['backend'])


class AdapterResolutionTests(unittest.TestCase):
    def test_unknown_chromium_and_unsupported_layout_capabilities(self):
        unknown = adapters.resolve('C:/fixture/unlisted.exe')
        self.assertEqual(unknown.id, 'process_environment')
        self.assertTrue(unknown.capabilities['can_apply'])
        browser = adapters.resolve('C:/fixture/chrome.exe')
        self.assertTrue(browser.capabilities['explicit_proxy_arguments'])
        self.assertTrue(any('没有读取' in c['detail'] for c in browser.checks()))
        unsupported = adapters.resolve('C:/fixture/Hermes.exe')
        self.assertFalse(unsupported.capabilities['can_apply'])
        self.assertFalse(unsupported.description['can_apply'])
        self.assertIn('主程序', unsupported.description['notice'])

    def test_route_description_uses_adapter_capabilities_for_any_backend(self):
        adapter = FixtureBackendAdapter('C:/fixture/unlisted.exe')
        app = {'id': 'fixture', 'executable': adapter.executable, 'protected': False,
               'launch_profile': {'available': True}, 'running_processes': []}
        with patch.object(adapters, 'resolve', return_value=adapter):
            result = describe(app)
        self.assertTrue(result['can_apply'])
        self.assertTrue(result['capabilities']['managed_backend'])
        self.assertEqual(result['adapter']['id'], adapter.id)


if __name__ == '__main__':
    unittest.main()
