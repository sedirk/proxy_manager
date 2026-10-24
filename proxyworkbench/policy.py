"""Validated, deterministic routing policy. No sockets or system changes."""
from __future__ import annotations

import copy
import ipaddress
import re

ID = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
DEFAULT_LIMITS = {"connect_timeout": 10.0, "header_timeout": 10.0,
                  "idle_timeout": 120.0, "max_header_bytes": 32768,
                  "max_connections": 128, "stop_timeout": 3.0}


def normalize_host(value):
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError("Host must contain 1–253 characters")
    value = value.rstrip(".")
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if any(character.isspace() or ord(character) < 33 for character in value) or any(
            character in value for character in ("/", "\\", "@", "%", "?", "#")):
        raise ValueError("Host contains unsupported characters")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if ":" in value:
            raise ValueError("Invalid IP address") from None
    value = value.encode("idna").decode("ascii").lower()
    if len(value) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                  for label in value.split(".")):
        raise ValueError("Invalid DNS host")
    return value


def _identifier(value, field):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ValueError(f"{field} must use 1–64 letters, numbers, _, - or .")
    return value


def _integer(value, lower, upper, field):
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise ValueError(f"{field} must be an integer from {lower} to {upper}")
    return value


def _objects(value, field, maximum):
    if not isinstance(value, list) or not 1 <= len(value) <= maximum or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"{field} must contain 1–{maximum} objects")
    return value


def _pattern(value):
    if value == "*":
        return value
    if not isinstance(value, str):
        raise ValueError("Domain rule must be a DNS host, IP, *.suffix or *")
    if value.startswith("*."):
        suffix = normalize_host(value[2:])
        try:
            ipaddress.ip_address(suffix)
        except ValueError:
            return "*." + suffix
        raise ValueError("Wildcard IP rules are unsupported")
    if "*" in value:
        raise ValueError("Only a leading *. wildcard is supported")
    return normalize_host(value)


def validate_plan(value):
    """Return canonical JSON data, rejecting unknown target/authentication fields."""
    if not isinstance(value, dict):
        raise ValueError("Plan must be an object")
    result = {"id": _identifier(value.get("id", "plan"), "Plan id"), "targets": [], "channels": [], "dns_overrides": {}}
    overrides = value.get("dns_overrides", {})
    if not isinstance(overrides, dict) or len(overrides) > 512:
        raise ValueError("dns_overrides must map at most 512 exact DNS names to literal IPs")
    for name, address in overrides.items():
        host = normalize_host(name)
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError("DNS override keys must be DNS names, not IP addresses")
        if host in result["dns_overrides"]:
            raise ValueError("Duplicate normalized DNS override")
        try:
            if not isinstance(address, str) or "%" in address:
                raise ValueError()
            result["dns_overrides"][host] = str(ipaddress.ip_address(address))
        except ValueError:
            raise ValueError("DNS override values must be literal IPv4 or IPv6 addresses") from None
    targets = {}
    for target in _objects(value.get("targets"), "targets", 128):
        if set(target) - {"id", "name", "type", "host", "port", "interface_index"}:
            raise ValueError("Unsupported target fields; upstream authentication is not supported")
        name = _identifier(target.get("id"), "Target id")
        if name in targets:
            raise ValueError("Duplicate target id")
        kind = target.get("type")
        if kind not in ("direct", "http", "socks5", "block"):
            raise ValueError("Target type must be direct, http, socks5 or block")
        item = {"id": name, "type": kind}
        if "name" in target:
            if not isinstance(target["name"], str) or not 1 <= len(target["name"]) <= 100:
                raise ValueError("Target name must contain 1–100 characters")
            item["name"] = target["name"]
        if kind in ("http", "socks5"):
            item.update(host=normalize_host(target.get("host")), port=_integer(target.get("port"), 1, 65535, "Upstream port"))
        elif target.get("host") is not None or target.get("port") is not None:
            raise ValueError("Only upstream targets can specify host/port")
        if target.get("interface_index") is not None:
            if kind != "direct":
                raise ValueError("Interface binding is supported only for direct targets")
            item["interface_index"] = _integer(target["interface_index"], 1, 0xFFFFFF, "Interface index")
        targets[name] = item
        result["targets"].append(item)
    requested_ports = set()
    channel_ids = set()
    for channel in _objects(value.get("channels"), "channels", 32):
        name = _identifier(channel.get("id"), "Channel id")
        if name in channel_ids:
            raise ValueError("Duplicate channel id")
        channel_ids.add(name)
        label = channel.get("name", name)
        if not isinstance(label, str) or not 1 <= len(label) <= 100:
            raise ValueError("Channel name must contain 1–100 characters")
        if channel.get("listen_host", "127.0.0.1") != "127.0.0.1":
            raise ValueError("Channels listen only on 127.0.0.1")
        port = _integer(channel.get("listen_port", 0), 0, 65535, "Listen port")
        if port and port in requested_ports:
            raise ValueError("Two channels cannot request the same port")
        if port:
            requested_ports.add(port)
        default = channel.get("default_target")
        if default not in targets:
            raise ValueError("Unknown default target")
        rules = channel.get("rules", [])
        if not isinstance(rules, list) or len(rules) > 512:
            raise ValueError("At most 512 ordered rules are supported per channel")
        normalized, identifiers = [], set()
        for rule in rules:
            if not isinstance(rule, dict):
                raise ValueError("Rule must be an object")
            rule_id = _identifier(rule.get("id"), "Rule id")
            if rule_id in identifiers:
                raise ValueError("Duplicate rule id")
            identifiers.add(rule_id)
            if rule.get("target") not in targets:
                raise ValueError("Unknown rule target")
            domains = rule.get("domains")
            if not isinstance(domains, list) or not 1 <= len(domains) <= 128:
                raise ValueError("Each rule needs 1–128 domain patterns")
            normalized.append({"id": rule_id, "domains": [_pattern(domain) for domain in domains], "target": rule["target"]})
        result["channels"].append({"id": name, "name": label, "listen_port": port,
                                    "default_target": default, "rules": normalized})
    limits = dict(DEFAULT_LIMITS)
    given = value.get("limits", {})
    if not isinstance(given, dict) or set(given) - set(limits):
        raise ValueError("Unknown relay limits")
    for key, number in given.items():
        if key in ("max_header_bytes", "max_connections"):
            lower, upper = (1024, 131072) if key == "max_header_bytes" else (1, 1024)
            limits[key] = _integer(number, lower, upper, key)
        else:
            if isinstance(number, bool) or not isinstance(number, (int, float)) or not 0.05 <= number <= 3600:
                raise ValueError(f"{key} must be between 0.05 and 3600 seconds")
            limits[key] = float(number)
    result["limits"] = limits
    return result


def domain_matches(host, pattern):
    host = normalize_host(host)
    pattern = _pattern(pattern)
    return pattern == "*" or host == pattern or (pattern.startswith("*.") and host.endswith(pattern[1:]) and host != pattern[2:])


class Policy:
    def __init__(self, plan):
        self.plan = validate_plan(plan)
        self.channels = {channel["id"]: channel for channel in self.plan["channels"]}
        self.targets = {target["id"]: target for target in self.plan["targets"]}

    def route(self, channel_id, host, port):
        if channel_id not in self.channels:
            raise ValueError("Unknown channel")
        host = normalize_host(host)
        _integer(port, 1, 65535, "Destination port")
        channel = self.channels[channel_id]
        target, rule_id = channel["default_target"], None
        for rule in channel["rules"]:
            if any(domain_matches(host, pattern) for pattern in rule["domains"]):
                target, rule_id = rule["target"], rule["id"]
                break
        dial_host = self.plan["dns_overrides"].get(host, host)
        dns_source = ("plan_override" if host in self.plan["dns_overrides"] else
                      "system_resolver" if self.targets[target]["type"] == "direct" else
                      "not_used" if self.targets[target]["type"] == "block" else "upstream_resolver")
        return {"channel_id": channel_id, "host": host, "dial_host": dial_host, "dns_source": dns_source, "port": port,
                "rule_id": rule_id, "target_id": target, "target": copy.deepcopy(self.targets[target])}
