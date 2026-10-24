"""Compare observed sections without asserting which application wrote them."""
from .system_proxy import fingerprint


def compare(previous, current):
    result = {'before': previous.get('captured_at'), 'after': current.get('captured_at'), 'items': []}
    if not previous or previous.get('schema_version') != current.get('schema_version'):
        return result
    left, right = previous.get('layers', {}), current.get('layers', {})
    fields = {
        'wininet': ('系统代理 / PAC', ['enabled', 'proxy_server', 'bypass', 'auto_config_url', 'auto_detect']),
        'winhttp': ('WinHTTP', ['access_type', 'proxy', 'bypass']),
        'hosts': ('hosts 文件', ['size_bytes', 'modified_at', 'active_mapping_count']),
        'default_routes': ('默认路由', ['routes', 'selected_by_family']),
        'environment': ('代理环境变量', ['process', 'user', 'machine']),
    }
    for section, (name, keys) in fields.items():
        a, b = left.get(section, {}), right.get(section, {})
        if a.get('evidence_status') != 'observed' or b.get('evidence_status') != 'observed':
            continue
        before, after = {k: a.get(k) for k in keys}, {k: b.get(k) for k in keys}
        if fingerprint(before) != fingerprint(after) or (section == 'hosts' and a.get('sha256') and b.get('sha256') and a['sha256'] != b['sha256']):
            result['items'].append({'section': section, 'name': name, 'before': before, 'after': after,
                                    'writer': 'unknown', 'notice': '两次快照存在变化；不能仅凭时间先后认定由某个应用造成。'})
    return result
