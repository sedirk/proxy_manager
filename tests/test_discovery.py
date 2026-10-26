"""Mocked collectors and private temp configurations; no system writes/probes."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from proxyworkbench import discovery

UUID = "12345678-1234-1234-1234-123456789abc"


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="proxy-discovery-fixture-")
        self.root = Path(self.temp.name)
        self.config = self.root / "generated.json"
        self.config.write_text(json.dumps({
            "inbounds": [{"protocol": "mixed", "listen": "127.0.0.1", "port": 10808, "tag": UUID,
                          "settings": {"accounts": [{"user": "PRIVATE_INBOUND_USER", "pass": "PRIVATE_INBOUND_PASSWORD"}]}}],
            "outbounds": [{"protocol": "vless", "tag": "PRIVATE_NODE_LABEL", "settings": {"vnext": [{"address": "PRIVATE_NODE_ADDRESS", "users": [{"id": UUID}]}]}}],
            "subscription": "https://subscription.example/PRIVATE_SUBSCRIPTION_PATH?token=PRIVATE_SUBSCRIPTION_TOKEN",
            "dns": {"servers": ["https://dns.example/dns-query?token=PRIVATE_DNS_TOKEN"], "hosts": {"PRIVATE_HOSTNAME": "192.0.2.1"}},
            "routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "domain": ["PRIVATE_RULE_DOMAIN"], "outboundTag": "PRIVATE_NODE_LABEL"},
                                                                       {"process_name": ["steam.exe"], "outboundTag": "direct"}]},
        }), encoding="utf-8")
        self.raw = {
            "supported": True, "errors": {},
            "wininet": {"enabled": 1, "proxy_server": "http=envuser:PRIVATE_PROXY_PASSWORD@127.0.0.1:10808;https=127.0.0.1:10808", "bypass": "<local>",
                         "auto_config_url": "https://pacuser:PRIVATE_PAC_PASSWORD@pac.example/PRIVATE_PAC_PATH?token=PRIVATE_PAC_TOKEN", "auto_detect": False, "scope": "user"},
            "winhttp": {"access_type": "direct", "proxy": None, "bypass": None},
            "process_environment": {"http_proxy": "http://envuser:PRIVATE_ENV_PASSWORD@127.0.0.1:10808", "NO_PROXY": "localhost,127.0.0.1", "UNRELATED_SECRET": "PRIVATE_UNRELATED_ENV"},
            "environment": {"user": {"HTTP_PROXY": "http://127.0.0.1:10809"}, "machine": {}},
            "processes": [{"Name": "xray.exe", "ProcessId": 10, "ParentProcessId": 20, "ExecutablePath": str(self.root / "xray.exe")},
                          {"Name": "Codex.exe", "ProcessId": 11, "ParentProcessId": 1, "ExecutablePath": str(self.root / "Codex.exe"), "CommandLine": "PRIVATE_CODEX_COMMAND_LINE"},
                          {"Name": "steam.exe", "ProcessId": 12, "ParentProcessId": 1, "ExecutablePath": str(self.root / "steam.exe")},
                          {"Name": "rustdesk.exe", "ProcessId": 13, "ParentProcessId": 1, "ExecutablePath": str(self.root / "rustdesk.exe")},
                          {"Name": "v2rayN.exe", "ProcessId": 20, "ParentProcessId": 1, "ExecutablePath": str(self.root / "v2rayN.exe")},
                          {"Name": "unrelated.exe", "ProcessId": 99, "CommandLine": "PRIVATE_UNRELATED_COMMAND_LINE", "ExecutablePath": str(self.root / "unrelated.exe")}],
            "core_commands": [{"Name": "xray.exe", "ProcessId": 10, "ExecutablePath": str(self.root / "xray.exe"),
                               "CommandLine": f'"{self.root / "xray.exe"}" run -c "{self.config}" --secret=PRIVATE_CLI_SECRET'}],
            "tcp_listeners": [{"LocalAddress": "::", "LocalPort": 10808, "OwningProcess": 10}, {"LocalAddress": "127.0.0.1", "LocalPort": 7890, "OwningProcess": 99}],
            "udp_listeners": [{"LocalAddress": "0.0.0.0", "LocalPort": 10809, "OwningProcess": 10}],
            "connections": [{"OwningProcess": 11, "RemoteAddress": "127.0.0.1", "RemotePort": 10808},
                            {"OwningProcess": 12, "RemoteAddress": "198.51.100.99", "RemotePort": 443},
                            {"OwningProcess": 10, "RemoteAddress": "198.51.100.42", "RemotePort": 443}],
            "adapters": [{"Name": "Ethernet", "InterfaceDescription": "Physical Ethernet", "ifIndex": 1, "Status": "Up"},
                         {"Name": "xray_tun", "InterfaceDescription": "Wintun", "ifIndex": 9, "Status": "Up"}],
            "ip_interfaces": [{"InterfaceIndex": 1, "InterfaceAlias": "Ethernet", "AddressFamily": 2, "InterfaceMetric": 10},
                              {"InterfaceIndex": 9, "InterfaceAlias": "xray_tun", "AddressFamily": 2, "InterfaceMetric": 0}],
            "addresses": [{"InterfaceIndex": 1, "IPAddress": "192.0.2.10", "PrefixLength": 24, "AddressFamily": 2},
                          {"InterfaceIndex": 9, "IPAddress": "172.18.0.1", "PrefixLength": 30, "AddressFamily": 2}],
            "dns": [{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["192.0.2.1"]}],
            "routes": [{"InterfaceIndex": 1, "InterfaceAlias": "Ethernet", "DestinationPrefix": "0.0.0.0/0", "NextHop": "192.0.2.1", "RouteMetric": 0},
                       {"InterfaceIndex": 9, "InterfaceAlias": "xray_tun", "DestinationPrefix": "0.0.0.0/0", "NextHop": "0.0.0.0", "RouteMetric": 100}],
            "installed": [{"name": "RustDesk", "InstallLocation": str(self.root / "RustDesk"), "DisplayVersion": "1.5.0"}],
        }
        self.hosts = discovery._section(source="fixture hosts", custom_mapping_count=1, active_mapping_count=1, content_exported=False)

    def tearDown(self):
        self.temp.cleanup()

    def snapshot(self, raw=None):
        with patch.object(discovery, "_collect_raw", return_value=deepcopy(self.raw if raw is None else raw)), patch.object(discovery, "_hosts_state", return_value=self.hosts):
            return discovery.snapshot()

    def test_stable_top_level_schema_is_json_serializable(self):
        result = self.snapshot()
        self.assertEqual(result["schema_version"], 1)
        self.assertTrue({"layers", "endpoints", "apps", "interfaces", "findings", "capabilities"} <= result.keys())
        self.assertTrue(result["capabilities"]["read_only"])
        self.assertFalse(result["capabilities"]["active_probes"])
        self.assertFalse(result["capabilities"]["protocol_verification"])
        json.dumps(result)

    def test_uu_private_listeners_are_not_generic_proxy_candidates(self):
        self.raw['processes'].extend([{'Name': 'uu.exe', 'ProcessId': 100}, {'Name': 'uu_neths_helper.exe', 'ProcessId': 101}])
        self.raw['tcp_listeners'].append({'LocalAddress': '127.1.163.1', 'LocalPort': 60443, 'OwningProcess': 101})
        self.hosts['loopback_redirect_counts'] = {'127.1.163.1': 5}
        result = self.snapshot()
        app = next(app for app in result['apps'] if app['id'] == 'uu')
        self.assertEqual(app['category'], 'accelerator')
        listener = next(e for e in result['endpoints'] if e['port'] == 60443)
        self.assertEqual(listener['role'], 'accelerator_listener')
        self.assertIsNone(listener['declared_protocol'])
        layer = result['layers']['accelerators']
        self.assertEqual(layer['hosts_redirect_count'], 5)
        self.assertEqual(layer['proxy_disable_setting'], 'unknown')
        self.assertFalse(layer['game_session_verified'])
        self.assertIn('accelerator_hosts_listener', [f['id'] for f in result['findings']])

    def test_no_credentials_nodes_subscription_or_command_lines_escape(self):
        text = json.dumps(self.snapshot())
        for secret in (UUID, "PRIVATE_INBOUND_USER", "PRIVATE_INBOUND_PASSWORD", "PRIVATE_NODE_LABEL", "PRIVATE_NODE_ADDRESS", "PRIVATE_SUBSCRIPTION_PATH", "PRIVATE_SUBSCRIPTION_TOKEN",
                       "PRIVATE_DNS_TOKEN", "PRIVATE_HOSTNAME", "PRIVATE_RULE_DOMAIN", "PRIVATE_PROXY_PASSWORD", "PRIVATE_PAC_PASSWORD", "PRIVATE_PAC_PATH", "PRIVATE_PAC_TOKEN",
                       "PRIVATE_ENV_PASSWORD", "PRIVATE_UNRELATED_ENV", "PRIVATE_CODEX_COMMAND_LINE", "PRIVATE_UNRELATED_COMMAND_LINE", "PRIVATE_CLI_SECRET", "198.51.100.42"):
            self.assertNotIn(secret, text, secret)
        self.assertIn("credentials redacted", text)

    def test_protocol_requires_configuration_not_common_port_number(self):
        result = self.snapshot()
        unknown = next(item for item in result["endpoints"] if item["port"] == 7890)
        self.assertIsNone(unknown["declared_protocol"])
        self.assertEqual(unknown["protocol_evidence"], "unknown")
        mixed = next(item for item in result["endpoints"] if item["port"] == 10808)
        self.assertEqual(mixed["declared_protocol"], "mixed")
        self.assertFalse(mixed["protocol_verified"])
        self.assertFalse(result["layers"]["core_configs"][0]["loaded_config_verified"])

    def test_configuration_port_requires_matching_owner_pid(self):
        raw = deepcopy(self.raw)
        raw["tcp_listeners"][0]["OwningProcess"] = 99
        result = self.snapshot(raw)
        self.assertIsNone(next(item for item in result["endpoints"] if item["port"] == 10808)["declared_protocol"])

    def test_application_connection_observation_is_not_all_traffic_verification(self):
        result = self.snapshot()
        codex = next(item for item in result["apps"] if item["id"] == "codex")
        self.assertEqual(codex["effective_proxy"], "unknown")
        self.assertEqual(len(codex["observed_connections"]["to_proxy_endpoints"]), 1)
        self.assertFalse(result["capabilities"]["other_process_environment_read"])
        self.assertNotIn("198.51.100.99", json.dumps(result))

    def test_environment_is_scoped_and_case_normalized(self):
        env = self.snapshot()["layers"]["environment"]
        self.assertIn("HTTP_PROXY", env["process"]["values"])
        self.assertNotIn("UNRELATED_SECRET", env["process"]["values"])
        self.assertNotEqual(env["process"]["values"], env["user"]["values"])
        self.assertIn("Process", env["limitations"])

    def test_relative_generated_config_uses_bounded_parent_layout_candidate(self):
        raw = deepcopy(self.raw)
        generated = self.root / "binConfigs" / "relative.json"
        generated.parent.mkdir()
        generated.write_bytes(self.config.read_bytes())
        raw["core_commands"][0]["CommandLine"] = f'"{self.root / "xray.exe"}" run -c relative.json'
        result = self.snapshot(raw)
        config = result["layers"]["core_configs"][0]
        self.assertEqual(config["evidence_status"], "observed")
        self.assertEqual(config["reference"], "command_line_relative_cwd_unknown")
        self.assertFalse(config["loaded_config_verified"])

    def test_relative_v2rayn_generated_config_supports_external_data_bin_layout(self):
        data_root = self.root / "external-data" / "v2rayN"
        for name, folder, filename in (("xray.exe", "xray", "config.json"),
                                       ("sing-box.exe", "sing_box", "configPre.json"),
                                       ("xray.exe", "xray", "configTest-123456789.json"),
                                       ("v2ray.exe", "v2fly_v5", "config.json")):
            with self.subTest(name=name, filename=filename):
                raw = deepcopy(self.raw)
                executable = data_root / "bin" / folder / name
                generated = data_root / "binConfigs" / filename
                generated.parent.mkdir(parents=True, exist_ok=True)
                generated.write_bytes(self.config.read_bytes())
                raw["wininet"]["enabled"] = 0
                raw["processes"][0].update(Name=name, ExecutablePath=str(executable))
                raw["core_commands"][0].update(Name=name, ExecutablePath=str(executable),
                    CommandLine=f'"{executable}" run -c {filename}')
                result = self.snapshot(raw)
                config = next(item for item in result["layers"]["core_configs"]
                              if item.get("path") == str(generated))
                self.assertEqual(config["evidence_status"], "observed")
                self.assertEqual(config["reference"], "command_line_relative_cwd_unknown")
                self.assertFalse(config["loaded_config_verified"])
                manager = next(tool for tool in result["network_tools"] if tool["id"] == "v2rayn")
                self.assertEqual(manager["proxy_options"][0]["protocol"], "http")
                self.assertNotIn("PRIVATE_NODE_ADDRESS", json.dumps(result))

    def test_external_data_candidates_require_observed_parent_layout_and_generated_basename(self):
        data_root = self.root / "external-data" / "v2rayN"
        executable = data_root / "bin" / "xray" / "xray.exe"
        parent = {"Name": "v2rayN.exe", "ExecutablePath": str(self.root / "v2rayN.exe")}
        for label, core_path, filename, observed_parent in (
                ("unknown parent", executable, "config.json", {"Name": "other.exe"}),
                ("missing parent", executable, "config.json", {}),
                ("wrong bin layout", data_root / "custom" / "xray" / "xray.exe", "config.json", parent),
                ("wrong core folder", data_root / "bin" / "other" / "xray.exe", "config.json", parent),
                ("gui config", executable, "guiNConfig.json", parent),
                ("subscription", executable, "subscriptions.json", parent),
                ("nested relative path", executable, "nested/config.json", parent)):
            with self.subTest(label=label):
                process = {"Name": "xray.exe", "ProcessId": 10, "ExecutablePath": str(core_path),
                           "CommandLine": f'"{core_path}" run -c {filename}'}
                candidates = discovery._config_candidates(process, {10: observed_parent})
                self.assertNotIn(data_root / "binConfigs" / filename, [path for path, _ in candidates])

    def test_non_local_config_reference_is_not_fetched(self):
        raw = deepcopy(self.raw)
        raw["core_commands"][0]["CommandLine"] = 'xray.exe -c https://subscription.example/PRIVATE_TOKEN'
        result = self.snapshot(raw)
        self.assertEqual(result["layers"]["core_configs"][0]["evidence_status"], "unknown")
        self.assertNotIn("PRIVATE_TOKEN", json.dumps(result))

    def test_malformed_config_never_echoes_file_content(self):
        self.config.write_text('{"PRIVATE_BROKEN_CONFIG_SECRET":', encoding="utf-8")
        result = self.snapshot()
        self.assertEqual(result["layers"]["core_configs"][0]["evidence_status"], "unknown")
        self.assertNotIn("PRIVATE_BROKEN_CONFIG_SECRET", json.dumps(result))

    def test_reparse_config_is_rejected(self):
        link = self.root / "linked.json"
        try:
            link.symlink_to(self.config)
        except OSError as exc:
            self.skipTest(str(exc))
        raw = deepcopy(self.raw)
        raw["core_commands"][0]["CommandLine"] = f'xray.exe -c "{link}"'
        self.assertEqual(self.snapshot(raw)["layers"]["core_configs"][0]["evidence_status"], "unknown")

    def test_yaml_whitelist_does_not_export_proxy_nodes_or_passwords(self):
        summary = discovery._yaml_config('''mixed-port: 7897\nbind-address: 127.0.0.1\nproxies:\n  - name: PRIVATE_NODE_LABEL\n    password: PRIVATE_NODE_PASSWORD\ndns:\n  nameserver:\n    - https://dns.example/dns-query?token=PRIVATE_DNS_TOKEN\nrules:\n  - PROCESS-NAME,steam.exe,DIRECT\n  - MATCH,PRIVATE_NODE_LABEL\ntun:\n  enable: true\n''')
        text = json.dumps(summary)
        self.assertNotIn("PRIVATE_", text)
        self.assertEqual(summary["inbounds"][0]["protocol"], "mixed")
        self.assertEqual(summary["routing"]["process_rules"][0]["action"], "direct")
        self.assertIn("白名单", summary["parse_limitations"])

    def test_virtual_interface_name_does_not_prove_tun_conflict(self):
        result = self.snapshot()
        self.assertTrue(next(item for item in result["interfaces"] if item["index"] == 9)["virtual_hint"])
        self.assertNotIn("remote_control_virtual_route", [item["id"] for item in result["findings"]])
        self.raw["routes"][1]["RouteMetric"] = 0
        result = self.snapshot()
        finding = next(item for item in result["findings"] if item["id"] == "remote_control_virtual_route")
        self.assertIn("尚未证明", finding["detail"])
        self.assertEqual(finding["evidence_status"], "observed")

    def test_unsupported_platform_is_explicit_and_does_not_run_windows_collectors(self):
        with patch.object(discovery, "_is_windows", return_value=False), patch.object(discovery, "_powershell_state", side_effect=AssertionError("must not run")), patch.object(discovery, "_hosts_state", side_effect=AssertionError("must not read Windows hosts")):
            result = discovery.snapshot()
        self.assertEqual(result["layers"]["wininet"]["evidence_status"], "unsupported")
        self.assertEqual(result["layers"]["winhttp"]["evidence_status"], "unsupported")
        self.assertEqual(result["endpoints"], [])
        self.assertEqual(result["layers"]["environment"]["process"]["evidence_status"], "observed")

    def test_collector_timeout_keeps_successful_sections_and_marks_unknown(self):
        with patch.object(discovery, "_is_windows", return_value=True), patch.object(discovery, "_registry_state", return_value=(self.raw["wininet"], self.raw["environment"], [])), patch.object(discovery, "_winhttp_state", return_value=self.raw["winhttp"]), patch.object(discovery, "_powershell_state", side_effect=subprocess.TimeoutExpired("powershell.exe", 0.01)), patch.object(discovery, "_hosts_state", return_value=self.hosts):
            result = discovery.snapshot(timeout=0.01)
        self.assertEqual(result["layers"]["wininet"]["evidence_status"], "observed")
        self.assertEqual(result["capabilities"]["sections"]["tcp_listeners"]["status"], "unknown")
        self.assertIn("powershell", result["capabilities"]["errors"])

    def test_powershell_collection_uses_read_only_commands_and_core_filter(self):
        completed = SimpleNamespace(returncode=0, stdout="{}", stderr="")
        with patch.object(discovery.subprocess, "run", return_value=completed) as run:
            discovery._powershell_state(1)
        arguments = run.call_args.args[0]
        script = arguments[-1]
        for forbidden in ("Set-Net", "Remove-Net", "New-Net", "Restart-", "Stop-Process", "Start-Process", "Win32_Product", "SetEnvironmentVariable"):
            self.assertNotIn(forbidden, script)
        self.assertIn("-Filter", script)
        self.assertIn("Name='xray.exe'", script)
        self.assertEqual(run.call_args.kwargs["timeout"], 1)

    def test_hosts_overview_does_not_export_full_private_mappings(self):
        system_root = self.root / "fake-windows"
        hosts = system_root / "System32" / "drivers" / "etc" / "hosts"
        hosts.parent.mkdir(parents=True)
        hosts.write_text("127.0.0.1 localhost\n192.0.2.2 PRIVATE_LOCAL_HOST\n192.0.2.3 steamcommunity.com\n", encoding="utf-8")
        with patch.dict(os.environ, {"SystemRoot": str(system_root)}):
            result = discovery._hosts_state()
        self.assertEqual(result["custom_mapping_count"], 2)
        self.assertEqual(result["interesting_hostnames"], ["steamcommunity.com"])
        self.assertNotIn("PRIVATE_LOCAL_HOST", json.dumps(result))
        self.assertFalse(result["content_exported"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
