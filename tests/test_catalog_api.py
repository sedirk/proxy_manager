import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest

from proxyworkbench.server import ControlServer


class CatalogApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='catalog-api-')
        root = Path(cls.temp.name)
        executable = root / 'curl.exe'
        executable.write_bytes(b'not-an-executable-fixture')
        cls.server = ControlServer(('127.0.0.1', 0), root, discover=False)
        cls.server.service.snapshot = {
            'captured_at': '2026-10-24T00:00:00+00:00', 'layers': {}, 'endpoints': [],
            'apps': [{'id': 'curl', 'name': 'curl', 'category': 'application',
                      'running_processes': [{'pid': 10, 'name': 'curl.exe', 'executable': str(executable)}]},
                     {'id': 'codex', 'name': 'Codex', 'category': 'application', 'running_processes': []}],
        }
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.service.close()
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(3)
        cls.temp.cleanup()

    def request(self, path, method='GET', value=None, auth=True):
        headers = {'X-Session-Token': self.server.token} if auth else {}
        body = None
        if value is not None:
            body = json.dumps(value)
            headers['Content-Type'] = 'application/json'
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=8)
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        status, result = response.status, json.loads(response.read())
        connection.close()
        return status, result

    def test_catalog_requires_authenticated_local_session_and_is_observational(self):
        self.assertEqual(self.request('/api/catalog', auth=False)[0], 403)
        status, value = self.request('/api/catalog')
        self.assertEqual(status, 200)
        self.assertIn('apps', value)
        self.assertFalse(self.server.service.relay.status()['running'])
        self.assertEqual(self.server.service.lease.status().get('phase'), 'detached')

    def test_arbitrary_path_read_and_unknown_action_refused(self):
        for body in ({'app_id': 'curl', 'resource_id': '../../.local/plan.json', 'action': 'tail'},
                     {'app_id': 'curl', 'resource_id': 'anything', 'action': 'execute'}):
            self.assertEqual(self.request('/api/catalog/resource', 'POST', body)[0], 400)

    def test_protected_app_cannot_generate_reconfiguration_profile(self):
        status, _ = self.request('/api/catalog/launch-profile', 'POST',
                                 {'app_id': 'codex', 'mode': 'clear_environment'})
        self.assertEqual(status, 400)
        self.assertFalse(self.server.service.relay.status()['running'])

    def test_guidance_and_launch_endpoints_require_session_before_any_operation(self):
        self.assertEqual(self.request('/api/troubleshoot', auth=False)[0], 403)
        for action in ('check', 'profile', 'launch', 'feedback'):
            self.assertEqual(self.request('/api/troubleshoot/' + action, 'POST', {}, auth=False)[0], 403)
        status, value = self.request('/api/troubleshoot')
        self.assertEqual(status, 200)
        self.assertIn('catalog', value)
        self.assertIn('tools', value)
        self.assertEqual(self.request('/api/app-routes', auth=False)[0], 403)
        for action in ('save','launch','inspect','prepare-launch','shortcut'):
            self.assertEqual(self.request('/api/app-routes/'+action,'POST',{},auth=False)[0],403)
        self.assertEqual(self.request('/api/network-tools/check','POST',{},auth=False)[0],403)


if __name__ == '__main__':
    unittest.main()
