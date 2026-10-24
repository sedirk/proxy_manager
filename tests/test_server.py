import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest

from proxyworkbench.server import ControlServer


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        (root / 'web').mkdir()
        (root / 'web/index.html').write_text('fixture', encoding='utf-8')
        cls.server = ControlServer(('127.0.0.1', 0), root, discover=False)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.service.close()
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(2)
        cls.temp.cleanup()

    def request(self, path, method='GET', value=None, headers=None, auth=True):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        supplied = {'X-Session-Token': self.server.token} if auth else {}
        if value is not None:
            value = json.dumps(value)
            supplied['Content-Type'] = 'application/json'
        supplied.update(headers or {})
        conn.request(method, path, body=value, headers=supplied)
        response = conn.getresponse()
        result = (response.status, response.read(), dict(response.getheaders()))
        conn.close()
        return result

    def test_session_bootstrap_and_protected_reads(self):
        self.assertEqual(self.request('/api/session', auth=False)[0], 200)
        self.assertEqual(self.request('/api/state', auth=False)[0], 403)
        self.assertEqual(self.request('/api/state')[0], 200)

    def test_host_and_origin_and_fetch_site_rejected(self):
        for headers in ({'Host': 'attacker.example'}, {'Origin': 'https://attacker.example'}, {'Sec-Fetch-Site': 'cross-site'}):
            with self.subTest(headers=headers):
                self.assertEqual(self.request('/api/session', headers=headers, auth=False)[0], 403)

    def test_no_arbitrary_files(self):
        for path in ('/../.local/plan.json', '/%2e%2e/.local/plan.json', '/.local/server.json'):
            self.assertEqual(self.request(path)[0], 404)

    def test_wrong_media_type_and_unknown_plan(self):
        self.assertEqual(self.request('/api/runtime/start', 'POST', {}, {'Content-Type': 'text/plain'})[0], 400)
        self.assertEqual(self.request('/api/plan', 'PUT', {'plan': {}})[0], 400)
        self.assertFalse(self.server.service.relay.status()['running'])

    def test_preview_and_export_do_not_start_proxy(self):
        status, body, _ = self.request('/api/preview', 'POST', {})
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)['valid'])
        status, body, _ = self.request('/api/export', 'POST', {'kind': 'diagnostics'})
        self.assertEqual(status, 200)
        self.assertNotIn(self.server.token, body.decode())
        self.assertFalse(self.server.service.relay.status()['running'])

    def test_security_headers_and_no_cors(self):
        status, _, headers = self.request('/', auth=False)
        self.assertEqual(status, 200)
        self.assertEqual(headers['X-Frame-Options'], 'DENY')
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        self.assertNotIn('Access-Control-Allow-Origin', headers)


if __name__ == '__main__':
    unittest.main()
