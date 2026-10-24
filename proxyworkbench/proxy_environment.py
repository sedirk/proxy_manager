"""Shared, child-only proxy policy for native launches and exported scripts."""

PROXY_NAMES = ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
               'FTP_PROXY', 'GRPC_PROXY', 'CGI_HTTP_PROXY',
               'ELECTRON_GET_USE_PROXY', 'GLOBAL_AGENT_HTTP_PROXY',
               'GLOBAL_AGENT_HTTPS_PROXY', 'GLOBAL_AGENT_NO_PROXY',
               'GLOBAL_AGENT_ENVIRONMENT_VARIABLE_NAMESPACE')
_LOCAL_BYPASS = 'localhost,127.0.0.1,::1'


def assignments(mode, endpoint=''):
    """Return only settings owned by the selected launch mode."""
    if mode in {'inherit', 'clear_environment'}:
        return {}
    if mode == 'socks_environment':
        return {'ALL_PROXY': endpoint, 'NO_PROXY': _LOCAL_BYPASS}
    if mode != 'http_environment':
        raise ValueError('不支持此应用连接方式')
    return {
        'HTTP_PROXY': endpoint, 'HTTPS_PROXY': endpoint, 'ALL_PROXY': endpoint,
        'NO_PROXY': _LOCAL_BYPASS,
        # @electron/get requires this opt-in even when HTTP(S)_PROXY is set.
        'ELECTRON_GET_USE_PROXY': '1',
        # Older @electron/get uses global-agent rather than Undici. Replace
        # inherited overrides so it cannot silently keep a different entrance.
        'GLOBAL_AGENT_HTTP_PROXY': endpoint, 'GLOBAL_AGENT_HTTPS_PROXY': endpoint,
        'GLOBAL_AGENT_NO_PROXY': _LOCAL_BYPASS + ',[::1]',
        'GLOBAL_AGENT_ENVIRONMENT_VARIABLE_NAMESPACE': 'GLOBAL_AGENT_',
    }


def child_environment(inherited, mode, endpoint=''):
    if mode == 'inherit':
        return dict(inherited)
    updates = assignments(mode, endpoint)
    environment = {key: value for key, value in inherited.items()
                   if key.upper() not in PROXY_NAMES}
    environment.update(updates)
    return environment
