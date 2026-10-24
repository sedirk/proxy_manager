"""Describe observed network software and eligible local proxy entrances."""
import ipaddress
import re
from urllib.parse import urlsplit

PROFILES = {
    'uu': ('加速器', '主要通过加速规则、驱动或专用通道工作；其私有端口不能直接填作 HTTP 代理。', r'netease.*uu|网易.*uu|\buu\b'),
    'atrust': ('企业网络 / 零信任', '可能影响企业内网、隧道和访问策略；需要在 aTrust 中核对授权与连接状态。', r'atrust|sangfor.*vnic'),
    'zerotier': ('虚拟组网', '提供虚拟网卡和组网路由；本机管理端口不是应用代理入口。', r'zerotier'),
}
MANAGERS = {'v2rayn', 'clash_verge', 'mihomo_party', 'nekobox', 'hiddify'}
PROXIES = {'v2rayn', 'xray', 'v2ray', 'sing_box', 'clash', 'mihomo', 'clash_verge',
           'mihomo_party', 'ssr', 'surge', 'nekobox', 'hiddify', 'proxifier'}


def _local(address):
    try:
        bound = ipaddress.ip_address(address.split('%', 1)[0])
        return ('::1' if bound.version == 6 else '127.0.0.1') if bound.is_unspecified else str(bound) if bound.is_loopback else None
    except (ValueError, AttributeError):
        return None


def _system_http(wininet):
    if wininet.get('evidence_status') != 'observed' or not wininet.get('enabled'):
        return set()
    result = set()
    for segment in str(wininet.get('proxy_server') or '').split(';'):
        if '=' in segment:
            scheme, segment = segment.split('=', 1)
            if scheme.strip().lower() not in {'http', 'https'}:
                continue
        try:
            parsed = urlsplit(segment if '://' in segment else 'http://' + segment)
            host = parsed.hostname
            if parsed.scheme == 'http' and host and _local(host) and parsed.port and not parsed.username and not parsed.password:
                result.add((_local(host), parsed.port))
        except ValueError:
            pass
    return result


def inventory(apps, endpoints, interfaces, wininet, services=()):
    by_id = {app['id']: app for app in apps}
    processes = {process['pid']: (app['id'], process) for app in apps for process in app.get('running_processes', [])}
    # Only observed parent chains associate a core with its manager.
    owners = {}
    for pid, (app_id, process) in processes.items():
        selected, parent, visited = app_id, process.get('parent_pid'), {pid}
        for _ in range(6):
            if parent not in processes or parent in visited:
                break
            visited.add(parent)
            parent_id, item = processes[parent]
            if parent_id in MANAGERS:
                selected = parent_id
                break
            parent = item.get('parent_pid')
        owners[pid] = selected
    tool_ids = set(PROFILES) | PROXIES
    result = {}
    def obtain(tool_id):
        app = by_id.get(tool_id, {})
        kind, notice, _ = PROFILES.get(tool_id, ('应用代理', '可用入口需结合所属进程、协议来源与目标地址的实际检测确认。', ''))
        return result.setdefault(tool_id, {'id': tool_id, 'name': app.get('name') or {'atrust': '深信服 aTrust', 'zerotier': 'ZeroTier', 'uu': '网易 UU 加速器'}.get(tool_id, tool_id),
            'kind': kind, 'notice': notice, 'running': False, 'installed': bool(app.get('installed_locations')),
            'processes': [], 'services': [], 'interfaces': [], 'endpoints': [], 'proxy_options': []})
    for app in apps:
        if app['id'] not in tool_ids:
            continue
        grouped = {owners.get(p['pid'], app['id']) for p in app.get('running_processes', [])} or {app['id']}
        for selected in grouped:
            tool = obtain(selected)
            for process in app.get('running_processes', []):
                if owners.get(process['pid'], app['id']) == selected:
                    tool['processes'].append({'pid': process['pid'], 'name': process.get('name')})
                    tool['running'] = True
    for service in services[:128]:
        text = str(service.get('Name', '')) + ' ' + str(service.get('DisplayName', ''))
        selected = next((key for key in tool_ids if key.replace('_', '') in text.lower().replace('-', '')), None)
        if selected:
            tool = obtain(selected)
            tool['services'].append({'name': str(service.get('Name', ''))[:100], 'state': str(service.get('State', 'unknown'))[:30]})
            tool['running'] |= service.get('State') == 'Running'
    for interface in interfaces:
        text = interface.get('name', '') + ' ' + interface.get('description', '')
        selected = next((key for key, (_, _, pattern) in PROFILES.items() if re.search(pattern, text, re.I)), None)
        if selected:
            obtain(selected)['interfaces'].append({'name': re.sub(r'\[[^]]+\]', '[组网标识已省略]', interface.get('name', '')),
                'description': interface.get('description'), 'status': interface.get('status'), 'index': interface.get('index')})
    system = _system_http(wininet)
    for endpoint in endpoints:
        selected = owners.get(endpoint.get('pid'), endpoint.get('app_id'))
        if selected not in tool_ids:
            # An explicitly configured system HTTP endpoint can belong to an
            # otherwise unknown local process, but never to a tunnel/accelerator.
            if endpoint.get('transport') != 'tcp' or (_local(endpoint.get('address')), endpoint.get('port')) not in system:
                continue
            selected = 'system-proxy'
        tool = obtain(selected)
        tool['running'] = True  # A live listener is itself a running-process observation.
        if endpoint.get('pid') and not any(item['pid'] == endpoint['pid'] for item in tool['processes']):
            tool['processes'].append({'pid': endpoint['pid'], 'name': endpoint.get('owner')})
        entry = {key: endpoint.get(key) for key in ('id', 'address', 'port', 'transport', 'owner', 'pid')}
        protocol = endpoint.get('declared_protocol')
        host = _local(endpoint.get('address'))
        configured_system = (host, endpoint.get('port')) in system
        eligible = selected not in PROFILES and endpoint.get('transport') == 'tcp' and host
        protocol = 'http' if protocol in {'http', 'mixed'} else 'socks5' if protocol in {'socks', 'socks5'} else 'http' if configured_system and not protocol else None
        entry.update(protocol=protocol, usable_proxy=bool(eligible and protocol),
                     source='配置引用与监听归属' if endpoint.get('declared_protocol') else '当前系统 HTTP 代理与监听匹配' if configured_system else '进程监听；协议尚未确认')
        tool['endpoints'].append(entry)
        if entry['usable_proxy']:
            address = '[' + host + ']' if ':' in host else host
            proxy_url = protocol + '://' + address + ':' + str(entry['port'])
            if not any(option['proxy_url'] == proxy_url for item in result.values() for option in item['proxy_options']):
                tool['proxy_options'].append({'id': entry['id'], 'tool_id': selected, 'tool_name': tool['name'], 'protocol': protocol,
                    'host': host, 'port': entry['port'], 'proxy_url': proxy_url, 'source': entry['source'], 'verified': False})
    for tool in result.values():
        if tool['id'] == 'system-proxy':
            tool['name'] = '当前系统代理'
        tool['listener_count'] = len(tool['endpoints'])
        tool['endpoints'] = tool['endpoints'][:24]
        tool['process_count'] = len(tool['processes'])
        tool['state_label'] = '运行中' if tool['running'] else '有网卡线索' if tool['interfaces'] else '有记录，未发现运行进程'
        tool['action_label'] = f"{len(tool['proxy_options'])} 个可检测的代理入口" if tool['proxy_options'] else '通过网卡或专用规则工作' if tool['id'] in PROFILES else '尚未发现协议明确的本地入口'
    return sorted(result.values(), key=lambda tool: (not bool(tool['proxy_options']), not tool['running'], tool['name']))
