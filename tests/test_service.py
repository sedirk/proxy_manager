import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from proxyworkbench.service import Service, design_plan, preserves_default
from proxyworkbench.store import default_plan


class FakeLease:
    def __init__(self):
        self.phase = 'detached'

    def status(self):
        return {'phase': self.phase}

    def restore(self):
        if self.phase != 'conflict':
            self.phase = 'restored'
        return self.status()

    def close(self):
        pass


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.lease = FakeLease()
        self.service = Service(self.temp.name, discover=False, lease=self.lease)

    def tearDown(self):
        self.lease.phase = 'detached'
        self.service.close()
        self.temp.cleanup()

    def test_startup_is_detached_and_metadata_roundtrip(self):
        self.assertFalse(self.service.state()['runtime']['running'])
        plan = self.service.plan
        plan['name'] = '我的接线'
        plan['layout'] = {'nodes': {'channel:steam': {'x': 1, 'y': 2}}, 'viewport': {'zoom': .8}}
        result = self.service.save_plan(plan)['plan']
        self.assertEqual(result['layout'], plan['layout'])
        self.assertEqual(result['channels'][1]['app_id'], 'steam')
        self.assertEqual(json.loads((Path(self.temp.name) / '.local/plan.json').read_text(encoding='utf-8'))['name'], '我的接线')

    def test_running_configuration_not_changed_by_saving_design(self):
        self.service.start(self.service.plan)
        before = self.service.relay.status()
        plan = copy.deepcopy(self.service.plan)
        plan['channels'][0]['default_target'] = 'direct'
        self.service.save_plan(plan)
        self.assertEqual(self.service.relay.status()['channels'], before['channels'])
        self.assertNotEqual(self.service.running_plan['channels'][0]['default_target'], 'direct')
        with self.assertRaises(RuntimeError):
            self.service.start(plan)

    def test_conflict_keeps_listener_alive(self):
        self.service.start(self.service.plan)
        self.lease.phase = 'conflict'
        with self.assertRaises(RuntimeError):
            self.service.stop()
        self.assertTrue(self.service.relay.status()['running'])

    def test_preview_is_not_connection_evidence(self):
        result = self.service.preview(self.service.plan)
        self.assertFalse(result['impact']['active_apps_verified'])
        self.assertFalse(self.service.relay.status()['running'])
        route = next(r for r in result['routes'] if r['channel_id'] == 'steam' and r['host'] == 'cdn.steamcontent.com')
        self.assertEqual(route['target_id'], 'direct')

    def test_existing_default_compared_per_protocol(self):
        target = {'type': 'http', 'host': '127.0.0.1', 'port': 10808}
        self.assertTrue(preserves_default({'flags': 3, 'server': 'http=127.0.0.1:10808;https=127.0.0.1:10808'}, target))
        self.assertFalse(preserves_default({'flags': 3, 'server': 'http=127.0.0.1:10808;https=localhost:10808'}, target))
        self.assertFalse(preserves_default({'flags': 3, 'server': '[::1]:10808'}, target))
        self.assertFalse(preserves_default({'flags': 3, 'server': 'http=127.0.0.1:10808;https=localhost:8080'}, target))
        self.assertFalse(preserves_default({'flags': 3, 'server': '127.0.0.1:10808'}, {'type': 'direct'}))
        self.assertTrue(preserves_default({'flags': 1, 'server': ''}, {'type': 'direct'}))
        self.assertFalse(preserves_default({'flags': 1, 'server': ''}, {'type': 'direct', 'interface_index': 2}))

    def test_no_validated_proxy_defaults_to_block(self):
        plan = default_plan({'endpoints': [{'address': '127.0.0.1', 'port': 10808, 'declared_protocol': None}]})
        self.assertEqual(plan['channels'][0]['default_target'], 'block')

    def test_detection_does_not_overwrite_user_plan(self):
        self.service.save_plan(self.service.plan)
        self.service.plan['name'] = 'edited'
        with patch('proxyworkbench.discovery.snapshot', return_value={'captured_at': 'test', 'endpoints': []}):
            self.service.discover()
        self.assertEqual(self.service.plan['name'], 'edited')

    def test_probe_requires_live_channel(self):
        with self.assertRaises(ValueError):
            self.service.probe({'url': 'http://localhost', 'channel_id': 'steam'})

    def test_closed_service_cannot_reopen_listeners_or_apply(self):
        self.service.close()
        with self.assertRaises(RuntimeError):
            self.service.start(self.service.plan)
        with self.assertRaises(RuntimeError):
            self.service.system_apply('stale-preview')
        self.assertFalse(self.service.relay.status()['running'])

    def test_failed_plan_storage_rolls_back_new_listeners(self):
        with patch.object(self.service.store, 'write', side_effect=OSError('fixture disk full')):
            with self.assertRaises(RuntimeError):
                self.service.start(self.service.plan)
        self.assertFalse(self.service.relay.status()['running'])
        self.assertIsNone(self.service.running_plan)

    def test_audit_failure_does_not_misreport_network_state(self):
        with patch.object(self.service.store, 'audit', side_effect=OSError('fixture read only')):
            result = self.service.start(self.service.plan)
        self.assertTrue(result['runtime']['running'])
        self.assertIn('OSError', self.service.state()['audit_error'])

    def test_probe_uses_explicit_draft_target_and_live_channel_scope(self):
        plan = copy.deepcopy(self.service.plan)
        plan['targets'].append({'id': 'draft', 'type': 'http', 'host': '127.0.0.1', 'port': 12345})
        with patch('proxyworkbench.probes.probe', return_value={'status': 'fixture'}) as probe:
            result = self.service.probe({'url': 'http://example.test', 'target_id': 'draft', 'plan': plan})
        self.assertEqual(probe.call_args.args[1]['port'], 12345)
        self.assertIn('草稿', result['scope'])
        self.assertNotIn('draft', [t['id'] for t in self.service.plan['targets']])


if __name__ == '__main__':
    unittest.main()
