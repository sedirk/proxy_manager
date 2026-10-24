import json
import unittest
from proxyworkbench.discovery import _network_processes, _PROXY_APPS


class NetworkProcessTests(unittest.TestCase):
    def test_unknown_network_app_has_bounded_socket_evidence_not_direct_claim(self):
        processes = {71: {'Name': 'downloader.exe', 'ExecutablePath': r'C:\Apps\downloader.exe',
                          'CommandLine': 'PRIVATE_ARGUMENT', 'ParentProcessId': 1}}
        rows = [{'OwningProcess': 71, 'RemoteAddress': '198.51.100.4', 'RemotePort': 443}] * 40
        found = _network_processes({'connections': rows}, [], processes)
        self.assertEqual(found[0]['tcp_count'], 40)
        self.assertEqual(len(found[0]['connections']), 32)
        self.assertTrue(found[0]['connections_truncated'])
        self.assertEqual(found[0]['effective_proxy'], 'unknown')
        self.assertNotIn('PRIVATE_ARGUMENT', json.dumps(found))

    def test_upstream_proxy_details_hidden_and_cli_not_proxy_core(self):
        processes = {1: {'Name': 'xray.exe'}, 2: {'Name': 'curl.exe'}}
        rows = [{'OwningProcess': 1, 'RemoteAddress': '198.51.100.42', 'RemotePort': 4567},
                {'OwningProcess': 2, 'RemoteAddress': '198.51.100.8', 'RemotePort': 443}]
        found = _network_processes({'connections': rows}, [], processes)
        self.assertNotIn('198.51.100.42', json.dumps(found))
        self.assertNotIn('curl', _PROXY_APPS)
        self.assertNotIn('198.51.100.8', json.dumps(found))
        self.assertEqual(next(p for p in found if p['app_id'] == 'curl')['connections'][0]['remote_port'], 443)

    def test_local_candidate_correlation_respects_address_family_and_role(self):
        processes = {1: {'Name': 'unknown.exe'}}
        rows = [{'OwningProcess': 1, 'RemoteAddress': '127.0.0.1', 'RemotePort': 10808}]
        def endpoint(id_, address, role='proxy_candidate'):
            return {'id': id_, 'address': address, 'port': 10808, 'role': role, 'transport': 'tcp'}
        endpoints = [endpoint('v4', '127.0.0.1'), endpoint('v6', '::'), endpoint('uu', '127.0.0.1', 'accelerator_listener')]
        found = _network_processes({'connections': rows}, endpoints, processes)
        self.assertEqual(found[0]['connections'][0]['proxy_endpoint_ids'], ['v4'])
        self.assertEqual(found[0]['effective_proxy'], 'unknown')

    def test_same_executable_pids_share_stable_id(self):
        processes = {1: {'Name': 'app.exe', 'ExecutablePath': r'C:\Apps\app.exe'},
                     2: {'Name': 'APP.exe', 'ExecutablePath': r'c:\apps\APP.exe'}}
        rows = [{'OwningProcess': pid, 'RemoteAddress': '127.0.0.1', 'RemotePort': 80} for pid in processes]
        found = _network_processes({'connections': rows}, [], processes)
        self.assertEqual(found[0]['id'], found[1]['id'])


if __name__ == '__main__':
    unittest.main()
