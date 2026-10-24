import unittest

from proxyworkbench.policy import Policy, domain_matches, normalize_host, validate_plan


def plan():
    return {"id": "fixture", "targets": [{"id": "direct", "type": "direct"}, {"id": "deny", "type": "block"},
            {"id": "upstream", "type": "http", "host": "127.0.0.1", "port": 9999}],
            "channels": [{"id": "browser", "name": "Browser", "default_target": "direct", "rules": [
                {"id": "specific", "domains": ["api.example.com"], "target": "deny"},
                {"id": "suffix", "domains": ["*.example.com"], "target": "upstream"}]}]}


class PolicyTests(unittest.TestCase):
    def test_order_and_channel_default(self):
        policy = Policy(plan())
        self.assertEqual(policy.route("browser", "API.Example.com.", 443)["target_id"], "deny")
        self.assertEqual(policy.route("browser", "cdn.example.com", 443)["target_id"], "upstream")
        self.assertEqual(policy.route("browser", "example.com", 443)["target_id"], "direct")
        self.assertEqual(policy.route("browser", "badexample.com", 443)["target_id"], "direct")

    def test_idna_ips_and_wildcard_boundary(self):
        self.assertEqual(normalize_host("BÜCHER.example"), "xn--bcher-kva.example")
        self.assertEqual(normalize_host("[::1]"), "::1")
        self.assertTrue(domain_matches("a.b.example.com", "*.example.com"))
        self.assertFalse(domain_matches("example.com", "*.example.com"))
        self.assertTrue(domain_matches("127.0.0.1", "*"))

    def test_no_dns_or_mutations_during_validation(self):
        original = plan()
        canonical = validate_plan(original)
        self.assertNotIn("limits", original)
        self.assertEqual(canonical["channels"][0]["listen_port"], 0)
        self.assertEqual(canonical["limits"]["max_connections"], 128)

    def test_invalid_or_ambiguous_configuration_rejected(self):
        mutations = [lambda p: p["targets"].append(dict(p["targets"][0])),
                     lambda p: p["channels"][0].update(default_target="unknown"),
                     lambda p: p["channels"][0].update(listen_host="0.0.0.0"),
                     lambda p: p["channels"][0].update(listen_port=True),
                     lambda p: p["targets"][2].update(password="secret"),
                     lambda p: p["targets"][2].update(interface_index=5),
                     lambda p: p["channels"][0]["rules"][0].update(domains=["https://example.com/path"]),
                     lambda p: p["channels"][0]["rules"][0].update(domains=["*example.com"]),
                     lambda p: p.update(limits={"connect_timeout": float("nan")})]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                candidate = plan()
                mutation(candidate)
                with self.assertRaises(ValueError):
                    validate_plan(candidate)

    def test_duplicate_nonzero_ports_and_rule_ids_rejected(self):
        candidate = plan()
        candidate["channels"][0]["listen_port"] = 9998
        candidate["channels"].append({"id": "other", "listen_port": 9998, "default_target": "direct"})
        with self.assertRaises(ValueError):
            validate_plan(candidate)

    def test_exact_dns_overrides_keep_policy_host_and_change_dial_host(self):
        candidate = plan()
        candidate["dns_overrides"] = {"API.Example.com": "127.0.0.1", "ipv6.example.com": "::1"}
        policy = Policy(candidate)
        route = policy.route("browser", "api.example.com", 443)
        self.assertEqual(route["target_id"], "deny")
        self.assertEqual(route["host"], "api.example.com")
        self.assertEqual(route["dial_host"], "127.0.0.1")
        self.assertEqual(route["dns_source"], "plan_override")
        self.assertEqual(policy.route("browser", "elsewhere.example.com", 80)["dial_host"], "elsewhere.example.com")
        for overrides in ({"*.example.com": "127.0.0.1"}, {"example.com": "http://127.0.0.1"},
                          {"127.0.0.1": "127.0.0.2"}, {"example.com": "::1%3"}):
            candidate["dns_overrides"] = overrides
            with self.assertRaises(ValueError):
                validate_plan(candidate)
        candidate = plan()
        candidate["channels"][0]["rules"][1]["id"] = "specific"
        with self.assertRaises(ValueError):
            validate_plan(candidate)


if __name__ == "__main__":
    unittest.main()
