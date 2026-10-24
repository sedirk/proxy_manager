"""Persistent per-application launch settings for the visual connection canvas."""
import hashlib
from pathlib import Path
from urllib.parse import urlsplit
import ipaddress

from .catalog import application_executable_path, _key

MODES = {'inherit', 'clear_environment', 'http_environment'}


def route_key(executable):
    return hashlib.sha256(_key(executable).encode()).hexdigest()[:24]


def proxy_url(value):
    if not isinstance(value, str) or len(value)>500 or any(ord(c)<33 for c in value):
        raise ValueError('代理入口无效')
    parsed=urlsplit(value)
    try:
        if (parsed.scheme!='http' or not parsed.hostname or not ipaddress.ip_address(parsed.hostname).is_loopback
                or not parsed.port or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment):
            raise ValueError
    except ValueError as exc:
        raise ValueError('请选择本机 HTTP 代理入口') from exc
    return value


def parse(value):
    if not isinstance(value,dict) or value.get('schema_version')!=1 or not isinstance(value.get('routes'),list) or len(value['routes'])>256:
        raise ValueError('应用连接设置格式无效，原文件保留')
    routes=[];seen=set()
    for item in value['routes']:
        if not isinstance(item,dict) or item.get('mode') not in MODES:raise ValueError('应用连接设置无效')
        executable=application_executable_path(item.get('executable'),require_exists=False)
        key=route_key(executable)
        if key in seen:raise ValueError('应用连接设置重复')
        seen.add(key)
        routes.append({'key':key,'executable':executable,'mode':item['mode'],
                       'proxy_url':proxy_url(item.get('proxy_url')) if item['mode']=='http_environment' else '',
                       'updated_at':str(item.get('updated_at',''))[:80]})
    return {'schema_version':1,'routes':routes}


def describe(app, record=None):
    executable=app.get('executable') or app.get('launch_profile',{}).get('executable')
    browser=bool(executable and Path(executable).name.casefold() in {'chrome.exe','msedge.exe'})
    mode=record['mode'] if record else 'inherit'
    notice='使用浏览器代理参数；仍需核对组织策略和实际请求。' if browser else '软件需要支持代理环境变量；清除变量不保证绕过软件私有代理、系统代理或 TUN。'
    if mode=='http_environment':notice+=' 已包含 Electron 下载器代理兼容设置，请在原软件验证实际下载。'
    return {'app_id':app['id'],'saved':record is not None,'key':route_key(executable) if executable else None,
            'executable':executable,'mode':mode,
            'proxy_url':record['proxy_url'] if record else '',
            'can_apply':bool(executable and app.get('launch_profile',{}).get('available') and not app.get('protected')),
            'method':'浏览器显式参数 + 新进程环境' if browser else '新进程代理环境',
            'notice':notice,
            'running':bool(app.get('running_processes'))}
