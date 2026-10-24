"""Read-only Windows proxy and routing discovery with deliberately limited output.

The snapshot records observations, not successful traffic routing. It never
changes settings, starts/stops a process, sends a probe, or guesses a protocol
from a port number. Raw core command lines/configuration stay inside collectors;
only an explicit inbound/routing/DNS whitelist reaches the returned JSON.
"""
from __future__ import annotations

import ctypes
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
from urllib.parse import urlsplit, urlunsplit

SCHEMA_VERSION = 1
_CONFIG_LIMIT = 4 * 1024 * 1024
_PROXY_ENV = {"http_proxy", "https_proxy", "all_proxy", "no_proxy", "ftp_proxy", "grpc_proxy"}
_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
_APP_SPECS = {
    "v2rayn": ("v2rayN", {"v2rayn.exe"}, ("v2rayn",)),
    "xray": ("Xray", {"xray.exe"}, ("xray",)),
    "v2ray": ("V2Ray", {"v2ray.exe"}, ("v2ray",)),
    "sing_box": ("sing-box", {"sing-box.exe", "singbox.exe"}, ("sing-box", "singbox")),
    "clash": ("Clash", {"clash.exe", "clash-meta.exe", "clash-win64.exe", "clash-windows-amd64.exe"}, ("clash for windows",)),
    "mihomo": ("Mihomo", {"mihomo.exe", "verge-mihomo.exe"}, ("mihomo",)),
    "clash_verge": ("Clash Verge", {"clash-verge.exe", "clashverge.exe", "clash-verge-service.exe"}, ("clash verge", "clashverge")),
    "mihomo_party": ("Mihomo Party", {"mihomo-party.exe"}, ("mihomo party", "mihomo-party")),
    "ssr": ("Shadowsocks / SSR", {"shadowsocks.exe", "shadowsocksr.exe", "shadowsocksr-dotnet4.0.exe", "shadowsocksr-dotnet2.0.exe", "ssr.exe", "sslocal.exe"}, ("shadowsocks", "shadowsocksr")),
    "surge": ("Surge", {"surge.exe"}, ("surge",)),
    "nekobox": ("NekoBox / Nekoray", {"nekobox.exe", "nekoray.exe"}, ("nekobox", "nekoray")),
    "hiddify": ("Hiddify", {"hiddify.exe"}, ("hiddify",)),
    "proxifier": ("Proxifier", {"proxifier.exe"}, ("proxifier",)),
    "uu": ("网易 UU 加速器", {"uu.exe", "uu_ball.exe", "uu_neths_helper.exe", "uuhelper.exe", "uubooster.exe"}, ("网易uu", "网易 uu", "netease uu", "uu加速器", "uu 加速器")),
    "codex": ("Codex", {"codex.exe", "codex-app-server.exe", "app-server.exe"}, ("openai codex", "codex")),
    "steam": ("Steam", {"steam.exe", "steamwebhelper.exe", "steamservice.exe"}, ("steam",)),
    "wgc": ("Wargaming Game Center", {"wgc.exe", "wgc_renderer_host.exe"}, ("wargaming.net game center", "wargaming game center")),
    "rustdesk": ("RustDesk", {"rustdesk.exe"}, ("rustdesk",)),
    "chrome": ("Chrome", {"chrome.exe"}, ("google chrome",)),
    "edge": ("Microsoft Edge", {"msedge.exe"}, ("microsoft edge",)),
    "firefox": ("Firefox", {"firefox.exe"}, ("mozilla firefox",)),
    "git": ("Git", {"git.exe", "git-remote-http.exe", "git-remote-https.exe"}, ("git version", "git for windows")),
    "curl": ("curl", {"curl.exe"}, ()),
    "python": ("Python", {"python.exe", "pythonw.exe"}, ("python 3.",)),
    "node": ("Node.js", {"node.exe"}, ("node.js",)),
    "vscode": ("Visual Studio Code", {"code.exe"}, ("visual studio code",)),
}
_ACCELERATOR_APPS = {"uu"}
_PROXY_APPS = {"v2rayn", "xray", "v2ray", "sing_box", "clash", "mihomo", "clash_verge", "mihomo_party", "ssr", "surge", "nekobox", "hiddify", "proxifier"}
_CORE_NAMES = {"xray.exe", "v2ray.exe", "sing-box.exe", "singbox.exe", "clash.exe", "clash-meta.exe", "clash-win64.exe", "clash-windows-amd64.exe", "mihomo.exe", "verge-mihomo.exe", "sslocal.exe"}


def _is_windows():
    return os.name == "nt"


def _now():
    return datetime.now(timezone.utc).isoformat()


def _safe_text(value, limit=240):
    """For labels/errors only; never pass complete configuration text here."""
    text = str(value or "").replace("\x00", "")
    text = re.sub(r"(?i)(?:ss|ssr|vmess|vless|trojan)://[^\s]+", "[node link redacted]", text)
    text = _UUID.sub("[UUID redacted]", text)
    text = re.sub(r"(?i)(https?://)[^/\s@]+@", r"\1[credentials redacted]@", text)
    text = re.sub(r"(?i)([?&](?:token|key|auth|access_token|subscription)=)[^&\s]+", r"\1[redacted]", text)
    return text[:limit]


def _safe_url(value, *, hide_path=False):
    value = str(value or "").strip()
    if not value:
        return ""
    try:
        parsed = urlsplit(value)
        if parsed.scheme and parsed.netloc:
            host = parsed.hostname or ""
            if ":" in host:
                host = "[" + host + "]"
            authority = host + (":" + str(parsed.port) if parsed.port else "")
            if parsed.username is not None or parsed.password is not None:
                authority = "[credentials redacted]@" + authority
            path = "/[path redacted]" if hide_path and parsed.path not in ("", "/") else parsed.path
            query = "[redacted]" if parsed.query else ""
            fragment = "[redacted]" if parsed.fragment else ""
            return _safe_text(urlunsplit((parsed.scheme, authority, path, query, fragment)), 500)
    except ValueError:
        return "[invalid URL redacted]"
    # ProxyServer also permits scheme-less credentials and per-scheme entries.
    value = re.sub(r"[^\s;=/@]+(?::[^\s;/@]*)?@", "[credentials redacted]@", value)
    return _safe_text(value, 500)


def _section(status="observed", source=None, **data):
    return {"evidence_status": status, "source": source, **data}


def _rows(value):
    return [] if value is None else ([value] if isinstance(value, dict) else list(value))


def _integer(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _family(value):
    return "IPv6" if value in (23, "IPv6", "InterNetworkV6") else ("IPv4" if value in (2, "IPv4", "InterNetwork") else str(value))


def _registry_value(hive, key, name):
    import winreg
    try:
        with winreg.OpenKey(hive, key) as opened:
            return winreg.QueryValueEx(opened, name)[0]
    except FileNotFoundError:
        return None


def _registry_state():
    import winreg
    internet = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    policy = _registry_value(winreg.HKEY_LOCAL_MACHINE, r"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxySettingsPerUser")
    hive = winreg.HKEY_LOCAL_MACHINE if policy == 0 else winreg.HKEY_CURRENT_USER
    wininet = {"scope": "machine" if policy == 0 else "user"}
    for field, value in (("enabled", "ProxyEnable"), ("proxy_server", "ProxyServer"), ("bypass", "ProxyOverride"), ("auto_config_url", "AutoConfigURL")):
        wininet[field] = _registry_value(hive, internet, value)
    connection = _registry_value(hive, internet + r"\Connections", "DefaultConnectionSettings")
    wininet["auto_detect"] = bool(connection[8] & 8) if isinstance(connection, bytes) and len(connection) > 8 else None
    environment = {}
    for scope, env_hive, env_key in (("user", winreg.HKEY_CURRENT_USER, r"Environment"),
                                   ("machine", winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")):
        values = {}
        for name in sorted(_PROXY_ENV):
            value = _registry_value(env_hive, env_key, name.upper())
            if value is not None:
                values[name.upper()] = str(value)
        environment[scope] = values
    installed = []
    # Registry enumeration avoids Win32_Product, which may trigger MSI repairs.
    uninstall = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
    for reg_hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
            try:
                with winreg.OpenKey(reg_hive, uninstall, 0, winreg.KEY_READ | view) as parent:
                    count = min(winreg.QueryInfoKey(parent)[0], 4096)
                    for index in range(count):
                        try:
                            child = winreg.EnumKey(parent, index)
                            with winreg.OpenKey(parent, child) as item:
                                name = winreg.QueryValueEx(item, "DisplayName")[0]
                                if not _installed_app_id(name):
                                    continue
                                record = {"name": name}
                                for field in ("InstallLocation", "DisplayIcon", "DisplayVersion"):
                                    try:
                                        record[field] = winreg.QueryValueEx(item, field)[0]
                                    except FileNotFoundError:
                                        pass
                                installed.append(record)
                        except (OSError, ValueError):
                            continue
            except OSError:
                continue
    return wininet, environment, installed


def _winhttp_state():
    from ctypes import wintypes
    class ProxyInfo(ctypes.Structure):
        _fields_ = [("access", wintypes.DWORD), ("proxy", ctypes.c_void_p), ("bypass", ctypes.c_void_p)]
    winhttp = ctypes.WinDLL("winhttp", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    winhttp.WinHttpGetDefaultProxyConfiguration.argtypes = [ctypes.POINTER(ProxyInfo)]
    winhttp.WinHttpGetDefaultProxyConfiguration.restype = wintypes.BOOL
    kernel.GlobalFree.argtypes = [ctypes.c_void_p]
    kernel.GlobalFree.restype = ctypes.c_void_p
    info = ProxyInfo()
    if not winhttp.WinHttpGetDefaultProxyConfiguration(ctypes.byref(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return {"access_type": {0: "default", 1: "direct", 3: "named_proxy", 4: "automatic"}.get(info.access, "unknown"),
                "proxy": ctypes.wstring_at(info.proxy) if info.proxy else None,
                "bypass": ctypes.wstring_at(info.bypass) if info.bypass else None}
    finally:
        if info.proxy:
            kernel.GlobalFree(info.proxy)
        if info.bypass:
            kernel.GlobalFree(info.bypass)


def _powershell_state(timeout):
    core_filter = " OR ".join("Name='" + name + "'" for name in sorted(_CORE_NAMES))
    script = r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$taskResult = @{ errors = @{} }
try { $taskResult.processes = @(Get-CimInstance Win32_Process -Property Name,ProcessId,ParentProcessId,ExecutablePath | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath) } catch { $taskResult.errors.processes = $_.Exception.Message }
try { $taskResult.core_commands = @(Get-CimInstance Win32_Process -Filter "CORE_FILTER" -Property Name,ProcessId,ExecutablePath,CommandLine | Select-Object Name,ProcessId,ExecutablePath,CommandLine) } catch { $taskResult.errors.core_commands = $_.Exception.Message }
try { $taskResult.tcp_listeners = @(Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess) } catch { $taskResult.errors.tcp_listeners = $_.Exception.Message }
try { $taskResult.udp_listeners = @(Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess) } catch { $taskResult.errors.udp_listeners = $_.Exception.Message }
try { $taskResult.connections = @(Get-NetTCPConnection -State Established | Select-Object OwningProcess,LocalAddress,LocalPort,RemoteAddress,RemotePort) } catch { $taskResult.errors.connections = $_.Exception.Message }
try { $taskResult.adapters = @(Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceDescription,ifIndex,Status) } catch { $taskResult.errors.adapters = $_.Exception.Message }
try { $taskResult.ip_interfaces = @(Get-NetIPInterface | Select-Object InterfaceIndex,InterfaceAlias,AddressFamily,ConnectionState,InterfaceMetric,NlMtu) } catch { $taskResult.errors.ip_interfaces = $_.Exception.Message }
try { $taskResult.addresses = @(Get-NetIPAddress | Select-Object InterfaceIndex,IPAddress,PrefixLength,AddressFamily,AddressState) } catch { $taskResult.errors.addresses = $_.Exception.Message }
try { $taskResult.dns = @(Get-DnsClientServerAddress | Select-Object InterfaceIndex,AddressFamily,ServerAddresses) } catch { $taskResult.errors.dns = $_.Exception.Message }
try { $taskResult.routes = @(Get-NetRoute -DestinationPrefix @('0.0.0.0/0','::/0') | Select-Object InterfaceIndex,InterfaceAlias,DestinationPrefix,NextHop,RouteMetric,State) } catch { $taskResult.errors.routes = $_.Exception.Message }
$taskResult | ConvertTo-Json -Depth 7 -Compress
'''.replace("CORE_FILTER", core_filter)
    result = subprocess.run(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, encoding="utf-8-sig", errors="replace", timeout=timeout,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode:
        raise OSError("只读 PowerShell 采集失败：" + _safe_text(result.stderr, 180))
    return json.loads(result.stdout)


def _collect_raw(timeout):
    raw = {"supported": _is_windows(), "errors": {}, "process_environment": dict(os.environ)}
    if not raw["supported"]:
        return raw
    try:
        raw["wininet"], raw["environment"], raw["installed"] = _registry_state()
    except (OSError, ValueError) as exc:
        raw["errors"]["registry"] = _safe_text(exc)
    try:
        raw["winhttp"] = _winhttp_state()
    except (OSError, ValueError) as exc:
        raw["errors"]["winhttp"] = _safe_text(exc)
    try:
        observed = _powershell_state(timeout)
        raw.update({key: value for key, value in observed.items() if key != "errors"})
        raw["errors"].update(observed.get("errors", {}))
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        raw["errors"]["powershell"] = _safe_text(type(exc).__name__ + ": " + str(exc))
    return raw


def _app_id(name, path=""):
    name = str(name or "").lower()
    for key, (_, names, _) in _APP_SPECS.items():
        if name in names:
            return "wgc_cn360" if key == "wgc" and "360" in str(path).lower() else key
    return None


def _installed_app_id(name):
    name = str(name or "").lower()
    for key, (_, _, patterns) in _APP_SPECS.items():
        if any(pattern in name for pattern in patterns):
            return "wgc_cn360" if key == "wgc" and "360" in name else key
    return None


def _argv(command):
    if _is_windows():
        from ctypes import wintypes
        shell = ctypes.WinDLL("shell32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        shell.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
        shell.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        count = ctypes.c_int()
        pointer = shell.CommandLineToArgvW(str(command), ctypes.byref(count))
        if not pointer:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return [pointer[index] for index in range(count.value)]
        finally:
            kernel.LocalFree(pointer)
    return [value.strip('"') for value in shlex.split(str(command), posix=False)]


def _config_candidates(process, parents):
    arguments = _argv(process.get("CommandLine", ""))
    name = str(process.get("Name", "")).lower()
    executable = Path(process.get("ExecutablePath") or "")
    paths, directories = [], []
    file_flags = {"-c", "-config", "--config", "-f", "--config-file"}
    directory_flags = {"-confdir", "--confdir", "-C"}
    if name in {"clash.exe", "clash-meta.exe", "clash-win64.exe", "clash-windows-amd64.exe", "mihomo.exe", "verge-mihomo.exe"}:
        directory_flags.add("-d")
    index = 1
    while index < len(arguments):
        argument = arguments[index]
        flag, separator, value = argument.partition("=")
        if flag in file_flags | directory_flags:
            if not separator:
                index += 1
                value = arguments[index] if index < len(arguments) else ""
            if value and not re.match(r"^[a-z][a-z0-9+.-]*://", value, re.I):
                (paths if flag in file_flags else directories).append(value)
        index += 1
    candidates = []
    for value, directory in [(value, False) for value in paths] + [(value, True) for value in directories]:
        path = Path(value)
        bases = [None] if path.is_absolute() else [executable.parent]
        parent = parents.get(_integer(process.get("ProcessId")), {})
        if not path.is_absolute() and parent.get("ExecutablePath"):
            bases.append(Path(parent["ExecutablePath"]).parent)
            if _app_id(parent.get("Name"), parent.get("ExecutablePath")) in _PROXY_APPS:
                # v2rayN commonly starts a relative generated config from
                # binConfigs. These are bounded layout candidates, not a claim
                # that CIM supplied the running process current directory.
                bases.extend(Path(parent["ExecutablePath"]).parent / folder
                             for folder in ("binConfigs", "guiConfigs", "configs"))
        for base in bases:
            candidate = path if base is None else base / path
            reference = "command_line_absolute" if base is None else "command_line_relative_cwd_unknown"
            if directory:
                # Only bounded direct children of the explicitly referenced dir.
                if candidate.is_dir():
                    for child in sorted(candidate.iterdir())[:128]:
                        if child.suffix.lower() in (".json", ".jsonc", ".yaml", ".yml"):
                            candidates.append((child, reference))
            else:
                candidates.append((candidate, reference))
    unique = {}
    for path, reference in candidates:
        unique.setdefault(os.path.normcase(os.path.abspath(path)), (path, reference))
    values = list(unique.values())
    existing = [(path, reference) for path, reference in values if path.is_file()]
    return (existing or values)[:8]


def _safe_config_path(path):
    absolute = Path(os.path.abspath(path))
    for part in reversed((absolute, *absolute.parents)):
        info = part.lstat()
        if part.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("拒绝读取重解析点配置")
    if not absolute.is_file() or absolute.stat().st_size > _CONFIG_LIMIT:
        raise ValueError("配置不是小型普通文件")
    return absolute


def _dns_summary(data):
    if not isinstance(data, dict):
        return {"present": False}
    servers = data.get("servers", [])
    servers = servers if isinstance(servers, list) else []
    safe_servers = []
    for item in servers[:12]:
        value = item if isinstance(item, str) else item.get("address") if isinstance(item, dict) else None
        if value:
            safe_servers.append(_safe_url(value, hide_path=str(value).find("dns-query") < 0))
    return {"present": True, "server_count": len(servers), "servers": safe_servers,
            "strategy": _safe_text(data.get("strategy") or data.get("queryStrategy"), 80),
            "static_hosts_count": len(data.get("hosts", {})) if isinstance(data.get("hosts"), dict) else 0,
            "fake_ip_enabled": bool(data.get("fakeip", {}).get("enabled")) if isinstance(data.get("fakeip"), dict) else bool(data.get("fake-ip", False))}


def _route_summary(data):
    if not isinstance(data, dict):
        return {"present": False}
    rules = data.get("rules", [])
    rules = rules if isinstance(rules, list) else []
    kinds, actions, process_rules = {}, {}, []
    for rule in rules[:4096]:
        if not isinstance(rule, dict):
            continue
        for field, kind in (("domain", "domain"), ("domain_suffix", "domain"), ("ip", "ip"), ("ip_cidr", "ip"),
                            ("process_name", "process"), ("process_path", "process"), ("inboundTag", "inbound"), ("inbound", "inbound"), ("port", "port")):
            if field in rule:
                kinds[kind] = kinds.get(kind, 0) + 1
        raw_action = str(rule.get("outboundTag") or rule.get("outbound") or rule.get("action") or "").lower()
        action = raw_action if raw_action in {"direct", "proxy", "block", "reject", "dns"} else "other"
        actions[action] = actions.get(action, 0) + 1
        names = rule.get("process_name", [])
        names = [names] if isinstance(names, str) else names if isinstance(names, list) else []
        known_names = [_safe_text(name, 80) for name in names if _app_id(name)]
        if known_names:
            process_rules.append({"process_names": known_names[:12], "action": action})
    return {"present": True, "rule_count": len(rules), "rule_kinds": kinds, "action_counts": actions,
            "process_rules": process_rules[:40], "domain_strategy": _safe_text(data.get("domainStrategy"), 80),
            "effective_routing_verified": False}


def _json_config(data):
    if not isinstance(data, dict):
        raise ValueError("配置根必须是对象")
    inbounds = []
    for inbound in data.get("inbounds", [])[:128]:
        if not isinstance(inbound, dict):
            continue
        protocol = str(inbound.get("protocol") or inbound.get("type") or "").lower()
        allowed = {"http", "socks", "mixed", "tun", "shadowsocks", "dokodemo-door", "redirect", "tproxy", "naive", "hysteria2", "tuic"}
        protocol = protocol if protocol in allowed else "unknown"
        listen = inbound.get("listen")
        listen = _safe_text(listen, 120) if isinstance(listen, str) else None
        port = _integer(inbound.get("port", inbound.get("listen_port")))
        if port is not None and not 1 <= port <= 65535:
            port = None
        inbounds.append({"protocol": protocol, "listen": listen, "port": port,
                         "interface_name": _safe_text(inbound.get("interface_name"), 80) if protocol == "tun" else None})
    return {"inbounds": inbounds, "routing": _route_summary(data.get("routing", data.get("route"))), "dns": _dns_summary(data.get("dns"))}


def _yaml_config(text):
    """Restricted Clash/Mihomo whitelist; does not parse or export node sections."""
    inbounds, rules, dns_servers = [], [], []
    section, subfield, bind, tun_enabled = None, None, None, False
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        top = re.match(r"^([\w-]+)\s*:\s*(.*?)\s*(?:#.*)?$", line)
        if top:
            section, value = top.groups()
            subfield = None
            if section == "bind-address":
                bind = value.strip("'\"")
            protocols = {"port": "http", "socks-port": "socks", "mixed-port": "mixed", "redir-port": "redirect", "tproxy-port": "tproxy"}
            if section in protocols:
                port = _integer(value.strip("'\""))
                if port and 1 <= port <= 65535:
                    inbounds.append({"protocol": protocols[section], "listen": None, "port": port, "interface_name": None})
            continue
        if section == "dns":
            field = re.match(r"^\s+([\w-]+)\s*:\s*(.*?)\s*$", line)
            if field:
                subfield, value = field.groups()
                if subfield in {"nameserver", "fallback", "default-nameserver"} and value:
                    for server in value.strip("[]").split(","):
                        if server.strip():
                            dns_servers.append(_safe_url(server.strip().strip("'\""), hide_path=True))
            elif subfield in {"nameserver", "fallback", "default-nameserver"}:
                item = re.match(r"^\s+-\s+(.+?)\s*$", line)
                if item:
                    dns_servers.append(_safe_url(item[1].strip("'\""), hide_path=True))
        elif section == "rules" and re.match(r"^\s+-\s+", line):
            rules.append(line.strip()[1:].strip().strip("'\""))
        elif section == "tun" and re.match(r"^\s+enable\s*:\s*true\b", line, re.I):
            tun_enabled = True
    for inbound in inbounds:
        inbound["listen"] = _safe_text(bind, 120) if bind else None
    if tun_enabled:
        inbounds.append({"protocol": "tun", "listen": None, "port": None, "interface_name": None})
    process_rules, kinds = [], {}
    for rule in rules:
        pieces = rule.split(",")
        kind = pieces[0].upper()
        kinds[kind] = kinds.get(kind, 0) + 1
        if kind == "PROCESS-NAME" and len(pieces) >= 3 and _app_id(pieces[1]):
            action = pieces[-1].lower()
            process_rules.append({"process_names": [_safe_text(pieces[1], 80)], "action": action if action in {"direct", "proxy", "reject"} else "other"})
    return {"inbounds": inbounds, "routing": {"present": bool(rules), "rule_count": len(rules), "rule_kinds": kinds,
            "process_rules": process_rules[:40], "effective_routing_verified": False},
            "dns": {"present": bool(dns_servers), "server_count": len(dns_servers), "servers": dns_servers[:12]},
            "parse_limitations": "YAML 仅识别白名单字段；锚点、引用、合并及复杂语法未求值。"}


def _core_configs(raw):
    parents = {int(row["ProcessId"]): row for row in _rows(raw.get("processes")) if row.get("ProcessId") is not None}
    # Resolve a core's relative argument against its parent GUI directory only as
    # a candidate: Windows CIM does not expose the process current directory.
    parent_executables = {pid: parents.get(_integer(row.get("ParentProcessId")), {}) for pid, row in parents.items()}
    result = []
    for process in _rows(raw.get("core_commands")):
        if str(process.get("Name", "")).lower() not in _CORE_NAMES:
            continue
        pid, name = _integer(process.get("ProcessId")), _safe_text(process.get("Name"), 80)
        try:
            candidates = _config_candidates(process, parent_executables)
        except (OSError, ValueError) as exc:
            candidates = []
            result.append(_section("unknown", "running_core_command_line", pid=pid, name=name, error=_safe_text(exc), loaded_config_verified=False))
        if not candidates:
            result.append(_section("unknown", "running_core_command_line", pid=pid, name=name, error="未发现可安全读取的本机配置路径", loaded_config_verified=False))
        for candidate, reference in candidates:
            try:
                path = _safe_config_path(candidate)
                info = path.stat()
                data = path.read_bytes()
                if len(data) > _CONFIG_LIMIT or path.stat().st_mtime_ns != info.st_mtime_ns or path.stat().st_size != info.st_size:
                    raise ValueError("配置在读取期间改变")
                text = data.decode("utf-8-sig")
                summary = _json_config(json.loads(text)) if path.suffix.lower() in (".json", ".jsonc") else _yaml_config(text)
                result.append(_section("observed", "running_core_command_line", pid=pid, name=name, path=_safe_text(path, 500),
                                       reference=reference, loaded_config_verified=False, **summary))
            except (OSError, ValueError, UnicodeError, TypeError) as exc:
                # Do not echo JSON decoder content or the raw command line.
                result.append(_section("unknown", "running_core_command_line", pid=pid, name=name,
                                       path=_safe_text(candidate, 500), reference=reference,
                                       error="配置读取/白名单解析失败：" + type(exc).__name__, loaded_config_verified=False))
    return result


def _hosts_state():
    path = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
    try:
        info = path.stat()
        if info.st_size > 1024 * 1024:
            raise ValueError("hosts 超过只读摘要上限")
        raw_bytes = path.read_bytes()
        text = raw_bytes.decode("utf-8-sig", errors="replace")
        entries, custom, hostnames, loopback_redirects = 0, 0, [], {}
        for line in text.splitlines():
            fields = line.split("#", 1)[0].split()
            if len(fields) < 2:
                continue
            try:
                address = ipaddress.ip_address(fields[0])
            except ValueError:
                continue
            entries += len(fields) - 1
            if address.is_loopback and fields[0] not in ('127.0.0.1', '::1'):
                loopback_redirects[str(address)] = loopback_redirects.get(str(address), 0) + len(fields) - 1
            for hostname in fields[1:]:
                hostname = hostname.lower()
                hostnames.append(hostname)
                if hostname not in {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}:
                    custom += 1
        interesting = sorted({name for name in hostnames if any(domain in name for domain in ("steamcommunity.com", "steampowered.com", "chatgpt.com", "openai.com", "wargaming.net"))})
        return _section(source="Windows hosts file", path=str(path), size_bytes=info.st_size,
                        modified_at=datetime.fromtimestamp(info.st_mtime, timezone.utc).isoformat(), active_mapping_count=entries,
                        custom_mapping_count=custom, duplicate_hostname_count=len(hostnames) - len(set(hostnames)),
                        interesting_hostnames=interesting[:20], sha256=hashlib.sha256(raw_bytes).hexdigest(),
                        loopback_redirect_counts=loopback_redirects, content_exported=False)
    except (OSError, ValueError) as exc:
        return _section("unknown", "Windows hosts file", path=str(path), error=_safe_text(exc), content_exported=False)


def _interfaces(raw):
    interfaces = {}
    for item in _rows(raw.get("adapters")):
        index = _integer(item.get("ifIndex"))
        if index is not None:
            interfaces[index] = {"index": index, "name": _safe_text(item.get("Name"), 100), "description": _safe_text(item.get("InterfaceDescription"), 160),
                                 "status": _safe_text(item.get("Status"), 40), "addresses": [], "dns": [], "metrics": {}, "evidence_status": "observed"}
    def obtain(item):
        index = _integer(item.get("InterfaceIndex"))
        return interfaces.setdefault(index, {"index": index, "name": _safe_text(item.get("InterfaceAlias"), 100), "description": "",
                                            "status": "unknown", "addresses": [], "dns": [], "metrics": {}, "evidence_status": "observed"})
    for item in _rows(raw.get("ip_interfaces")):
        entry = obtain(item)
        entry["metrics"][_family(item.get("AddressFamily"))] = _integer(item.get("InterfaceMetric"))
        if not entry["name"]:
            entry["name"] = _safe_text(item.get("InterfaceAlias"), 100)
    for item in _rows(raw.get("addresses")):
        obtain(item)["addresses"].append({"address": _safe_text(item.get("IPAddress"), 100), "prefix_length": _integer(item.get("PrefixLength")), "family": _family(item.get("AddressFamily"))})
    for item in _rows(raw.get("dns")):
        values = item.get("ServerAddresses") or []
        values = [values] if isinstance(values, str) else values
        obtain(item)["dns"].extend({"address": _safe_text(value, 140), "family": _family(item.get("AddressFamily"))} for value in values)
    for item in interfaces.values():
        item["virtual_hint"] = bool(re.search(r"tun|tap|wintun|xray|sing.box|clash|mihomo|zerotier|tailscale|vpn", item["name"] + " " + item["description"], re.I))
        item["virtual_hint_basis"] = "interface_name_or_description_only"
        item["addresses"].sort(key=lambda value: (value["family"], value["address"]))
        item["dns"].sort(key=lambda value: (value["family"], value["address"]))
    return sorted(interfaces.values(), key=lambda item: item["index"] if item["index"] is not None else -1)


def _routes(raw, interfaces):
    by_index = {item["index"]: item for item in interfaces}
    routes = []
    for value in _rows(raw.get("routes")):
        family = "IPv6" if ":" in str(value.get("DestinationPrefix", "")) else "IPv4"
        index = _integer(value.get("InterfaceIndex"))
        metric, interface_metric = _integer(value.get("RouteMetric")), by_index.get(index, {}).get("metrics", {}).get(family)
        routes.append({"interface_index": index, "interface_name": _safe_text(value.get("InterfaceAlias"), 100), "family": family,
                       "destination": value.get("DestinationPrefix"), "next_hop": _safe_text(value.get("NextHop"), 100), "route_metric": metric,
                       "interface_metric": interface_metric, "effective_metric": metric + interface_metric if metric is not None and interface_metric is not None else None})
    routes.sort(key=lambda value: (value["family"], value["effective_metric"] if value["effective_metric"] is not None else 2 ** 32, value["interface_index"] or -1))
    selected = {}
    for family in ("IPv4", "IPv6"):
        candidates = [item for item in routes if item["family"] == family and item["effective_metric"] is not None]
        selected[family] = [item["interface_index"] for item in candidates if item["effective_metric"] == candidates[0]["effective_metric"]] if candidates else []
    return _section("unknown" if "routes" not in raw else "observed", "Get-NetRoute + Get-NetIPInterface", routes=routes, selected_by_family=selected,
                    limitations="仅为默认路由与接口 metric 快照；未验证应用绑定、按目的地路由或真实流量出口。")


def _environment(raw):
    scopes = {"process": raw.get("process_environment", {}), **raw.get("environment", {})}
    result = {"evidence_status": "observed", "limitations": "Process 仅指本工作台进程；未读取其他已运行应用的环境块。Windows 环境变量名不区分大小写。"}
    for scope in ("process", "user", "machine"):
        present = scope in scopes
        values = {str(name).upper(): _safe_url(value, hide_path=True) for name, value in scopes.get(scope, {}).items() if str(name).lower() in _PROXY_ENV and value is not None}
        result[scope] = _section("observed" if present else ("unsupported" if not raw.get("supported") else "unknown"), "os.environ" if scope == "process" else "Windows environment registry", values=dict(sorted(values.items())))
    return result


def _endpoints(raw, configs, process_by_pid):
    result = []
    for transport, key in (("tcp", "tcp_listeners"), ("udp", "udp_listeners")):
        for item in _rows(raw.get(key))[:4096]:
            port, pid = _integer(item.get("LocalPort")), _integer(item.get("OwningProcess"))
            address = _safe_text(item.get("LocalAddress"), 100)
            owner = process_by_pid.get(pid, {})
            app = _app_id(owner.get("Name"), owner.get("ExecutablePath"))
            declarations = []
            for config in configs:
                if config.get("pid") != pid:
                    continue
                for inbound in config.get("inbounds", []):
                    if inbound.get("port") == port:
                        declarations.append({"protocol": inbound["protocol"], "configured_listen": inbound.get("listen"), "config_path": config.get("path"), "evidence_status": "observed"})
            protocols = sorted({item["protocol"] for item in declarations if item["protocol"] != "unknown"})
            identity = json.dumps([transport, address, port, pid], separators=(",", ":"))
            result.append({"id": "ep-" + hashlib.sha256(identity.encode()).hexdigest()[:16], "transport": transport,
                           "address": address, "port": port, "pid": pid, "owner": _safe_text(owner.get("Name"), 100) or None,
                           "app_id": app, "role": "accelerator_listener" if app in _ACCELERATOR_APPS else "proxy_candidate" if app in _PROXY_APPS or declarations else ("application_listener" if app else "unclassified_listener"),
                           "evidence_status": "observed", "observed_listener": True,
                           "declared_protocol": protocols[0] if len(protocols) == 1 else None,
                           "protocol_declarations": declarations, "protocol_evidence": "configuration_reference" if declarations else "unknown",
                           "protocol_verified": False})
    return sorted(result, key=lambda item: (item["transport"], item["port"] or 0, item["address"], item["pid"] or 0))


def _apps(raw, endpoints, process_by_pid):
    found, process_app = {}, {}
    def obtain(key):
        title = "360 Wargaming Game Center" if key == "wgc_cn360" else _APP_SPECS[key][0]
        return found.setdefault(key, {"id": key, "name": title, "category": "accelerator" if key in _ACCELERATOR_APPS else "proxy" if key in _PROXY_APPS else "application",
                                      "running_processes": [], "installed_locations": [], "observed_connections": {"tcp_count": 0, "to_proxy_endpoints": []},
                                      "effective_proxy": "unknown", "evidence_status": "observed"})
    for pid, process in process_by_pid.items():
        key = _app_id(process.get("Name"), process.get("ExecutablePath"))
        if key:
            process_app[pid] = key
            obtain(key)["running_processes"].append({"pid": pid, "name": _safe_text(process.get("Name"), 100),
                                                   "executable": _safe_text(process.get("ExecutablePath"), 500) or None, "parent_pid": _integer(process.get("ParentProcessId"))})
    for item in _rows(raw.get("installed")):
        key = _installed_app_id(item.get("name"))
        if key:
            location = _safe_text(item.get("InstallLocation") or item.get("DisplayIcon"), 500)
            evidence = {"display_name": _safe_text(item.get("name"), 140), "path": location or None,
                        "version": _safe_text(item.get("DisplayVersion"), 80) or None, "source": "uninstall_registry", "execution_verified": False}
            if evidence not in obtain(key)["installed_locations"]:
                obtain(key)["installed_locations"].append(evidence)
    proxy_endpoints = [item for item in endpoints if item["role"] == "proxy_candidate"]
    for item in _rows(raw.get("connections")):
        key = process_app.get(_integer(item.get("OwningProcess")))
        if not key:
            continue
        app = obtain(key)
        app["observed_connections"]["tcp_count"] += 1
        address, port = item.get("RemoteAddress"), _integer(item.get("RemotePort"))
        try:
            loopback = ipaddress.ip_address(str(address).split("%", 1)[0]).is_loopback
        except ValueError:
            loopback = False
        if loopback:
            for endpoint in proxy_endpoints:
                if endpoint["transport"] == "tcp" and endpoint["port"] == port and endpoint["address"] in {address, "0.0.0.0", "::", "127.0.0.1", "::1"}:
                    if endpoint["id"] not in app["observed_connections"]["to_proxy_endpoints"]:
                        app["observed_connections"]["to_proxy_endpoints"].append(endpoint["id"])
    for app in found.values():
        app["running_processes"].sort(key=lambda item: item["pid"])
        app["observed_connections"]["to_proxy_endpoints"].sort()
        app["limitations"] = "现有 TCP 连接只证明当时的连接端点，不能证明该应用所有流量、下载或 WebSocket 的实际路由。"
    return sorted(found.values(), key=lambda item: item["id"])


def _network_processes(raw, endpoints, process_by_pid):
    """Bounded PID/socket evidence for software without a named adapter.

    A public peer is not proof of direct routing. Core upstream peers remain
    hidden, consistent with the existing discovery privacy contract.
    """
    found = {}
    candidates = [entry for entry in endpoints if entry['transport'] == 'tcp'
                  and entry['role'] == 'proxy_candidate']
    for row in _rows(raw.get('connections')):
        pid = _integer(row.get('OwningProcess'))
        process = process_by_pid.get(pid)
        if not process:
            continue
        if pid not in found and len(found) >= 512:
            continue
        name = _safe_text(process.get('Name'), 100)
        executable = _safe_text(process.get('ExecutablePath'), 500) or None
        app_id = _app_id(name, executable or '')
        identity = (executable or name).replace('\\', '/').casefold()
        item = found.setdefault(pid, {
            'id': 'process-' + hashlib.sha256(identity.encode('utf-8')).hexdigest()[:16],
            'name': name, 'executable': executable, 'pid': pid,
            'parent_pid': _integer(process.get('ParentProcessId')), 'app_id': app_id,
            'tcp_count': 0, 'connections': [], 'connections_truncated': False,
            'evidence_status': 'observed', 'effective_proxy': 'unknown',
        })
        item['tcp_count'] += 1
        if len(item['connections']) >= 32:
            item['connections_truncated'] = True
            continue
        try:
            remote = ipaddress.ip_address(str(row.get('RemoteAddress', '')).split('%', 1)[0])
        except ValueError:
            continue
        port = _integer(row.get('RemotePort'))
        matches = []
        if remote.is_loopback:
            for endpoint in candidates:
                if endpoint['port'] != port:
                    continue
                try:
                    bound = ipaddress.ip_address(endpoint['address'].split('%', 1)[0])
                except ValueError:
                    continue
                # Dual-stack behavior cannot be inferred from an IPv6 listener.
                if bound.version == remote.version and (bound == remote or bound.is_unspecified):
                    matches.append(endpoint['id'])
        # Persist only loopback peers. Public destination lists can reveal
        # browsing activity; an upstream core's address/port can reveal nodes.
        hidden = not remote.is_loopback
        core_peer = app_id in _PROXY_APPS and hidden
        item['connections'].append({
            'remote_address': None if hidden else str(remote),
            'remote_port': None if core_peer else port,
            'local_address': _safe_text(row.get('LocalAddress'), 100) or None,
            'local_port': _integer(row.get('LocalPort')),
            'proxy_endpoint_ids': matches, 'remote_redacted': hidden,
            'remote_scope': 'loopback' if remote.is_loopback else 'non_loopback',
            'meaning': '代理上游细节已隐藏' if core_peer else '已观察 TCP 对端，非回环地址已摘要；最终出口与 UDP 路径未确认',
        })
    return sorted(found.values(), key=lambda item: (item['name'].casefold(), item['pid']))


def _findings(layers, interfaces, apps, endpoints, errors):
    result = []
    def add(identifier, title, detail, severity="info", affected=None):
        result.append({"id": identifier, "severity": severity, "title": title, "detail": detail,
                       "evidence_status": "observed", "affected_apps": affected or []})
    wininet, winhttp = layers["wininet"], layers["winhttp"]
    if wininet.get("enabled") and winhttp.get("access_type") == "direct":
        add("proxy_layers_differ", "系统代理与 WinHTTP 设置不同", "当前 WinINET 启用代理，WinHTTP 默认配置为直连；不同应用可能读取不同层，尚未验证应用实际行为。")
    environment = layers["environment"]
    if environment["process"]["values"] != environment["user"]["values"] and environment["user"]["evidence_status"] == "observed":
        add("environment_scope_difference", "工作台进程与用户代理变量不同", "已运行进程可能保留旧环境；此处未读取 Codex 等其他进程的环境，不能断定它们是否继承。")
    if any(item.get("protocol_evidence") == "unknown" and item["role"] == "proxy_candidate" for item in endpoints):
        add("proxy_protocol_unknown", "部分代理候选监听的协议未知", "监听端口与 PID 已观察到；未发现可关联入站配置或尚未主动验证，不能按端口号判定 HTTP/SOCKS。")
    hosts = layers["hosts"]
    if hosts.get("custom_mapping_count", 0):
        add("hosts_resolution_scope", "检测到自定义 hosts 映射", "HTTP/SOCKS 远端解析、代理核心 DNS 或应用自有 DNS 可能采用不同解析路径；本快照未验证它们是否读取 hosts。")
    candidates = [item["index"] for item in interfaces if item["virtual_hint"]]
    defaults = {index for indices in layers["default_routes"]["selected_by_family"].values() for index in indices}
    app_ids = {item["id"] for item in apps if item["running_processes"]}
    if app_ids.intersection(_ACCELERATOR_APPS):
        add("accelerator_coexistence", "加速器与代理需要分层共存", "已观察到网易 UU 进程。其私有监听不等于可用 HTTP/SOCKS 出口；游戏加速、下载流量、hosts 重写及驱动重定向需要分别验证。不会自动停止 UU 或代理核心。", "notice", ["uu", "steam", "wgc", "codex"])
        if wininet.get("enabled"):
            add("accelerator_proxy_control", "UU 运行时系统代理仍启用", "本次仍观察到启用的系统代理；请在 UU 中核对‘加速时禁用网络代理’。本工具未读取该开关，也不会据进程存在推断其设置。", affected=["uu", "codex"])
        matching = layers["accelerators"].get("hosts_redirect_count", 0)
        if matching:
            add("accelerator_hosts_listener", "hosts 与加速器本地监听存在对应", f"{matching} 项 hosts 映射指向当前 UU 监听的环回地址。它们与代理侧 DNS 可能采用不同路径；匹配不证明写入者或所有游戏流量已加速。", "notice", ["uu"])
    if "rustdesk" in app_ids and defaults.intersection(candidates):
        add("remote_control_virtual_route", "远程控制应用与虚拟默认路由同时存在", "名称疑似虚拟接口的网卡具有默认路由；这只是兼容排查线索，尚未证明 TUN 冲突、打洞失败或绕行生效。", "notice", ["rustdesk"])
    if "steam" in app_ids and (wininet.get("enabled") or wininet.get("auto_config_url")):
        add("steam_split_unknown", "Steam 下载与社区分流尚未验证", "系统代理/PAC 设置本身不能证明 Steam 内容下载是否直连；需另行观察实际连接或做受控验证。", affected=["steam"])
    if errors:
        add("partial_discovery", "部分系统信息暂不可读取", "快照保留了采集失败或权限不足的分区，缺失项按未知处理，不代表未配置。", "notice")
    return result


def snapshot(*, timeout=15.0) -> dict:
    """Return a JSON-serializable current observation; all actions are read-only."""
    raw = _collect_raw(timeout)
    supported = bool(raw.get("supported"))
    errors = {str(key): _safe_text(value) for key, value in raw.get("errors", {}).items()}
    unavailable = "unknown" if supported else "unsupported"
    current = raw.get("wininet")
    wininet = _section("observed" if current is not None else unavailable, "Windows Internet Settings registry",
                       scope=(current or {}).get("scope"), enabled=bool(current.get("enabled")) if current is not None and current.get("enabled") is not None else None,
                       proxy_server=_safe_url((current or {}).get("proxy_server")), bypass=_safe_text((current or {}).get("bypass"), 1000),
                       auto_config_url=_safe_url((current or {}).get("auto_config_url"), hide_path=True), auto_detect=(current or {}).get("auto_detect"),
                       limitations="配置观察不代表每个应用遵循 WinINET，也未执行 PAC/WPAD 或判定某个 URL 的代理结果。")
    current = raw.get("winhttp")
    winhttp = _section("observed" if current is not None else unavailable, "WinHttpGetDefaultProxyConfiguration",
                       access_type=(current or {}).get("access_type", "unknown"), proxy=_safe_url((current or {}).get("proxy")),
                       bypass=_safe_text((current or {}).get("bypass"), 1000), limitations="默认配置不能代表应用自建 WinHTTP 会话或高级自动代理的实际结果。")
    configs = _core_configs(raw) if supported else []
    interfaces = _interfaces(raw) if supported else []
    routes = _routes(raw, interfaces)
    if not supported:
        routes["evidence_status"] = "unsupported"
    process_by_pid = {_integer(item.get("ProcessId")): item for item in _rows(raw.get("processes")) if _integer(item.get("ProcessId")) is not None}
    endpoints = _endpoints(raw, configs, process_by_pid)
    apps = _apps(raw, endpoints, process_by_pid)
    layers = {"wininet": wininet, "winhttp": winhttp, "environment": _environment(raw), "core_configs": configs,
              "hosts": _hosts_state() if supported else _section("unsupported", "Windows hosts file", content_exported=False), "default_routes": routes}
    accelerator_apps = [app for app in apps if app["id"] in _ACCELERATOR_APPS]
    accelerator_endpoints = [e for e in endpoints if e["role"] == "accelerator_listener"]
    redirect_counts = layers["hosts"].get("loopback_redirect_counts", {})
    matched_addresses = {e['address'] for e in accelerator_endpoints if e['address'] in redirect_counts}
    layers["accelerators"] = _section("observed" if "processes" in raw else unavailable, "processes / listeners / hosts summary",
        apps=[{"id": app["id"], "name": app["name"], "running": bool(app["running_processes"]),
               "process_count": len(app["running_processes"])} for app in accelerator_apps],
        listener_count=len(accelerator_endpoints), hosts_redirect_count=sum(redirect_counts[a] for a in matched_addresses),
        proxy_disable_setting="unknown", hosts_conflict_setting="unknown", driver_redirection="unknown", game_session_verified=False,
        limitations="只读观察；没有读取或改动 UU 开关、驱动/WFP 规则、加速节点与游戏会话，不把私有端口当通用代理。")
    sections = {}
    for key in ("processes", "core_commands", "tcp_listeners", "udp_listeners", "connections", "adapters", "ip_interfaces", "addresses", "dns", "routes"):
        sections[key] = {"status": "observed" if key in raw else unavailable,
                         "error": errors.get(key) or errors.get("powershell") if key not in raw else None}
    return {"schema_version": SCHEMA_VERSION, "captured_at": _now(), "platform": "windows" if supported else sys.platform,
            "evidence_status": "observed", "layers": layers, "endpoints": endpoints, "apps": apps, "interfaces": interfaces,
            "network_processes": _network_processes(raw, endpoints, process_by_pid),
            "findings": _findings(layers, interfaces, apps, endpoints, errors),
            "capabilities": {"read_only": True, "active_probes": False, "protocol_verification": False,
                             "other_process_environment_read": False, "remote_node_details_exported": False,
                             "sections": sections, "errors": errors,
                             "limitations": ["没有修改网络、代理、DNS、hosts、环境变量或客户端配置，也没有启动/重启进程。",
                                             "没有递归扫描磁盘；未运行的便携客户端可能无法发现。",
                                             "配置引用、监听与连接属于观察；未验证 DNS、HTTP、TLS、WebSocket 或实际游戏/远程控制会话。"]}}
