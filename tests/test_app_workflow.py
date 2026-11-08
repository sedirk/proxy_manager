from copy import deepcopy
from pathlib import Path
import json
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from proxyworkbench.service import Service
from proxyworkbench.app_workflow import compose, verify_path


def option(port=10808):
    return {'id': 'endpoint', 'tool_id': 'fixture', 'tool_name': 'Fixture proxy',
            'protocol': 'http', 'proxy_url': f'http://127.0.0.1:{port}', 'host': '127.0.0.1', 'port': port}


def response(code=200):
    return {'layers': [{'layer': 'http', 'status': 'passed', 'http_status': code}]}


def inspection(status='matches'):
    return {'summary': 'fixture evidence', 'checks': [], 'environment_status': status,
            'capabilities': {'managed_backend': False, 'can_apply': True},
            'application': {'running': True}, 'backend': {'state': 'unsupported'}}


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='flowdesk-workflow-')
        self.root = Path(self.temp.name)
        self.exe = self.root / 'UnknownApp.exe'
        self.exe.write_bytes(b'fixture never executed')
        self.service = Service(self.root, discover=False)
        self.app_id = self.service.catalog_add_app({'executable': str(self.exe)})['app_id']
        self.service.snapshot = {'network_tools': [{'id': 'fixture', 'proxy_options': [option()]}]}
        self.service._catalog_cache = None

    def tearDown(self):
        self.service.close()
        self.temp.cleanup()

    def save(self, mode='http_environment'):
        self.service.app_route_save({'app_id': self.app_id, 'mode': mode, 'proxy_url': option()['proxy_url']})

    def check(self, stage='diagnose', url='https://example.test/public', runner=None, env='matches'):
        with patch.object(self.service, 'discover', return_value={}), \
                patch('proxyworkbench.app_connections.inspect', return_value=inspection(env)), \
                patch('proxyworkbench.service.probes.probe', side_effect=runner or (lambda *a, **k: response())):
            return self.service.app_route_workflow({'app_id': self.app_id, 'url': url}, stage)

    def test_unsaved_unknown_app_without_url_has_checks_and_no_network_or_mutation(self):
        before = deepcopy(self.service.plan)
        probe = Mock(return_value=response())
        report = self.check(url='', runner=probe, env='not_running')
        probe.assert_not_called()
        self.assertFalse(report['saved'])
        self.assertIsNone(report['comparison'])
        self.assertIsNone(report['recommendation'])
        self.assertTrue(any('先保存' in step for step in report['next_steps']))
        self.assertFalse((self.root / '.local/app-routes.json').exists())
        self.assertFalse(self.service.relay.status()['running'])
        self.assertEqual(before, self.service.plan)

    def test_diagnosis_recommends_only_observed_route_without_saving_or_launching(self):
        def runner(url, target, **kwargs):
            return {'layers': [{'layer': 'tls', 'status': 'failed'}]} if target['type'] == 'direct' else response()
        with patch('proxyworkbench.app_launch.launch') as launch:
            report = self.check(runner=runner)
            launch.assert_not_called()
        self.assertEqual(report['recommendation'], {'mode': 'http_environment', 'proxy_url': option()['proxy_url']})
        self.assertFalse((self.root / '.local/app-routes.json').exists())
        self.assertEqual(report['application_result']['status'], 'unverified')

    def test_same_symptom_with_http_denial_has_no_proxy_fix_recommendation(self):
        report = self.check(runner=lambda *a, **k: response(403))
        self.assertIsNone(report['recommendation'])
        self.assertEqual(report['comparison']['recommendation']['status'], 'http_response')
        self.assertEqual(report['application_result']['status'], 'unverified')

    def test_verify_probes_saved_route_only_ignoring_caller_override(self):
        self.save()
        probe = Mock(return_value=response())
        with patch.object(self.service, 'discover', return_value={}), \
                patch('proxyworkbench.app_connections.inspect', return_value=inspection()), \
                patch('proxyworkbench.service.probes.probe', probe):
            report = self.service.app_route_workflow({'app_id': self.app_id, 'url': 'https://example.test/',
                'proxy_url': 'http://untrusted.test:123', 'mode': 'inherit'}, 'verify')
        self.assertEqual(probe.call_count, 1)
        self.assertEqual(probe.call_args.args[1]['host'], '127.0.0.1')
        self.assertEqual(probe.call_args.args[1]['port'], 10808)
        self.assertEqual(report['application_result'], {'status': 'unverified', 'source': 'none'})
        result = self.service.app_route_feedback({'app_id': self.app_id, 'check_id': report['check_id'], 'outcome': 'failed'})
        self.assertEqual(result['application_result'], {'status': 'failed', 'source': 'user_report'})
        self.assertIn('没有将探测成功', result['message'])

    def test_inherit_does_not_masquerade_as_direct_and_missing_entrance_does_not_probe(self):
        for mode in ('inherit', 'http_environment'):
            with self.subTest(mode=mode):
                self.service.snapshot['network_tools'] = [{'proxy_options': [option()]}]
                self.save(mode)
                self.service.snapshot['network_tools'] = []
                probe = Mock(return_value=response())
                report = self.check('verify', runner=probe)
                probe.assert_not_called()
                self.assertEqual(report['application_result']['status'], 'unverified')
                if mode == 'inherit': self.assertEqual(report['comparison']['results'], [])
                else: self.assertFalse(report['comparison']['results'][0]['ok'])

    def test_no_saved_route_cannot_be_verified_and_bad_url_rejected_before_discovery(self):
        with self.assertRaisesRegex(ValueError, '先保存'): self.check('verify')
        for url in ('https://user:secret@example.test/', 'https://example.test/?token=secret', 'file:///secret', None):
            with patch.object(self.service, 'discover') as scan, self.assertRaises(ValueError):
                self.service.app_route_workflow({'app_id': self.app_id, 'url': url}, 'diagnose')
            scan.assert_not_called()

    def test_feedback_requires_verification_same_app_current_record_and_expiry(self):
        self.save()
        diagnosis = self.check()
        with self.assertRaisesRegex(ValueError, '验证'):
            self.service.app_route_feedback({'app_id': self.app_id, 'check_id': diagnosis['check_id'], 'outcome': 'resolved'})
        report = self.check('verify')
        value = {'app_id': self.app_id, 'check_id': report['check_id'], 'outcome': 'resolved'}
        with self.assertRaises(ValueError): self.service.app_route_feedback({**value, 'app_id': 'another-app'})
        with self.assertRaises(ValueError): self.service.app_route_feedback({**value, 'outcome': 'guessed'})
        self.service.workflow_checks[report['check_id']]['at'] -= 601
        with self.assertRaises(ValueError): self.service.app_route_feedback(value)
        report = self.check('verify')
        self.save('clear_environment')
        with self.assertRaises(ValueError): self.service.app_route_feedback({**value, 'check_id': report['check_id']})

    def test_new_diagnosis_invalidates_old_verification_and_removed_app_refuses_feedback(self):
        self.save()
        report = self.check('verify')
        self.check()
        with self.assertRaises(ValueError):
            self.service.app_route_feedback({'app_id': self.app_id, 'check_id': report['check_id'], 'outcome': 'resolved'})
        report = self.check('verify')
        self.service.catalog_remove_app({'manual_id': self.app_id})
        with self.assertRaises(ValueError):
            self.service.app_route_feedback({'app_id': self.app_id, 'check_id': report['check_id'], 'outcome': 'resolved'})

    def test_process_status_is_not_business_success_and_urls_are_not_persisted(self):
        self.save('clear_environment')
        probe = Mock(return_value=response())
        report = self.check('verify', url='https://example.test/private-case-path', runner=probe, env='different')
        self.assertTrue(any('不一致' in step for step in report['next_steps']))
        self.assertEqual(report['application_result']['status'], 'unverified')
        self.assertEqual(probe.call_args.args[1]['type'], 'direct')
        for path in (self.root / '.local').glob('*.json'):
            self.assertNotIn('private-case-path', path.read_text(encoding='utf-8'))
        self.assertNotIn('private-case-path', json.dumps(self.service.workflow_checks))

    def test_changes_during_check_cannot_be_published_as_current(self):
        self.save()
        def runner(*args, **kwargs):
            self.service.route_sessions['fixture-unrelated'] = {'pid': 1}
            self.save('inherit')
            return response()
        with self.assertRaisesRegex(ValueError, '检查期间'): self.check('verify', runner=runner)
        self.assertFalse(self.service.workflow_checks)

    def test_failed_apply_during_verification_invalidates_evidence(self):
        self.save('inherit')
        def inspect_while_applying(record):
            with patch.object(self.service.launch_reviews, 'apply', side_effect=ValueError('partly changed backend')):
                with self.assertRaises(ValueError):
                    self.service.app_route_launch({'app_id': self.app_id, 'ticket': 'fixture'})
            return inspection()
        with patch.object(self.service, 'discover', return_value={}), \
                patch('proxyworkbench.app_connections.inspect', side_effect=inspect_while_applying):
            with self.assertRaisesRegex(ValueError, '检查期间'):
                self.service.app_route_workflow({'app_id': self.app_id}, 'verify')
        self.assertFalse(self.service.workflow_checks)
        self.assertFalse(self.service.applying_routes)

    def test_verification_and_feedback_refuse_inflight_apply(self):
        self.save('inherit')
        report = self.check('verify')
        entered, finish = threading.Event(), threading.Event()
        def blocked(*args):
            entered.set()
            if not finish.wait(5): raise RuntimeError('fixture timed out')
            return {'pid': 99}
        errors = []
        def run():
            try: self.service.app_route_launch({'app_id': self.app_id, 'ticket': 'fixture'})
            except Exception as exc: errors.append(exc)
        with patch.object(self.service.launch_reviews, 'apply', side_effect=blocked):
            worker = threading.Thread(target=run)
            worker.start()
            try:
                self.assertTrue(entered.wait(2))
                with self.assertRaisesRegex(ValueError, '正在应用'): self.check('verify')
                with self.assertRaises(ValueError):
                    self.service.app_route_feedback({'app_id': self.app_id, 'check_id': report['check_id'], 'outcome': 'resolved'})
            finally:
                finish.set(); worker.join(5)
        self.assertFalse(errors)
        self.assertFalse(self.service.applying_routes)

    def test_merged_protocol_confirmation_is_shared_with_legacy_diagnosis(self):
        self.service.snapshot['network_tools'] = []
        with patch.object(self.service, '_network_tools', return_value=[{'proxy_options': [option()]}]):
            report = self.check()
            self.assertEqual(len(report['comparison']['results']), 2)
            with patch.object(self.service, 'discover', return_value={}), patch('proxyworkbench.service.probes.probe', return_value=response()):
                old = self.service.guide_check({'app_id': self.app_id, 'url': 'https://example.test/'})
            self.assertEqual(len(old['results']), 2)

    def test_discovery_failure_busy_and_protection_do_not_launch_or_probe(self):
        with patch.object(self.service, 'discover', return_value={'error': 'fixture'}):
            with self.assertRaisesRegex(ValueError, '旧快照'):
                self.service.app_route_workflow({'app_id': self.app_id}, 'diagnose')
        self.service.guide_slots.acquire()
        try:
            with self.assertRaises(RuntimeError): self.service.app_route_workflow({'app_id': self.app_id}, 'diagnose')
        finally: self.service.guide_slots.release()
        exe = self.root / 'codex.exe'; exe.write_bytes(b'fixture')
        protected = self.service.catalog_add_app({'executable': str(exe)})['app_id']
        with patch.object(self.service, 'discover') as scan, self.assertRaises(ValueError):
            self.service.app_route_workflow({'app_id': protected}, 'diagnose')
        scan.assert_not_called()


if __name__ == '__main__': unittest.main()
