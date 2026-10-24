"""Credential redaction is independent of system/network state."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from proxyworkbench.privacy import redact


class PrivacyTests(unittest.TestCase):
    def test_nested_sensitive_keys_and_command_lines_are_hidden(self):
        source = {'normal': {'password': 'PASSWORD', 'userName': 'USERNAME', 'api_key': 'APIKEY', 'raw_config': 'WHOLECONFIG', 'command_line': 'PROCESSARGS'},
                  'list': [{'subscription': 'SUBLINK'}, {'authorization': 'AUTH'}], 'port': 10808, 'ok': True}
        output = json.dumps(redact(source))
        for secret in ('PASSWORD', 'USERNAME', 'APIKEY', 'WHOLECONFIG', 'PROCESSARGS', 'SUBLINK', 'AUTH'):
            self.assertNotIn(secret, output)
        self.assertEqual(redact(source)['port'], 10808)
        self.assertIs(redact(source)['ok'], True)

    def test_url_credentials_query_fragment_and_private_path_are_hidden(self):
        text = redact('https://USER:PASS@pac.example/PRIVATEPATH?token=QUERYSECRET#FRAGMENTSECRET')
        for secret in ('USER', 'PASS', 'PRIVATEPATH', 'QUERYSECRET', 'FRAGMENTSECRET'):
            self.assertNotIn(secret, text)
        self.assertIn('pac.example', text)

    def test_public_dns_path_preserves_topology_without_query_secret(self):
        value = redact('https://dns.example/dns-query?key=QUERYSECRET')
        self.assertIn('/dns-query', value)
        self.assertNotIn('QUERYSECRET', value)

    def test_node_links_and_bare_uuid_are_not_exported(self):
        identifier = '12345678-1234-1234-1234-123456789abc'
        for protocol in ('vless', 'vmess', 'trojan', 'ss', 'ssr', 'hysteria2', 'hy2', 'tuic', 'wireguard'):
            with self.subTest(protocol=protocol):
                value = redact(protocol + '://' + identifier + '@NODESECRET:443?token=QUERYSECRET')
                self.assertNotIn(identifier, value)
                self.assertNotIn('NODESECRET', value)
        self.assertNotIn(identifier, redact('label ' + identifier))

    def test_uuid_in_url_path_does_not_break_full_url_redaction(self):
        value = redact('https://subscription.example/12345678-1234-1234-1234-123456789abc/PRIVATEPATH?key=SECRET')
        self.assertNotIn('PRIVATEPATH', value)
        self.assertNotIn('SECRET', value)

    def test_schemeless_proxy_credentials_are_hidden(self):
        value = redact('http=user:SECRET@127.0.0.1:10808;https=127.0.0.1:10808')
        self.assertNotIn('SECRET', value)
        self.assertIn('127.0.0.1:10808', value)

    def test_log_credentials_jwt_and_private_key_are_hidden(self):
        value = redact('Authorization: Bearer ABCDEFGHIJKLMNOP token=TOKENVALUE password="PASSWORD VALUE"')
        for secret in ('ABCDEFGHIJKLMNOP', 'TOKENVALUE', 'PASSWORD VALUE'):
            self.assertNotIn(secret, value)
        jwt = 'eyJABCDEFGHIJKLMN.ABCDEFGHIJKLMNOP.QRSTUVWXYZabcdef'
        self.assertNotIn(jwt, redact(jwt))
        self.assertNotIn('PRIVATEKEYBYTES', redact('-----BEGIN PRIVATE KEY-----\nPRIVATEKEYBYTES\n-----END PRIVATE KEY-----'))

    def test_structural_values_and_tuple_are_json_compatible(self):
        value = redact({'status': 'observed', 'values': (None, False, 10808), 'target': '127.0.0.1:10808'})
        self.assertEqual(value['values'], [None, False, 10808])
        self.assertEqual(value['status'], 'observed')
        self.assertEqual(value['target'], '127.0.0.1:10808')
        json.dumps(value)


if __name__ == '__main__':
    unittest.main(verbosity=2)
