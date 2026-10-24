"""A bounded, user-triggered comparison with actionable, scoped conclusions."""
from concurrent.futures import ThreadPoolExecutor
import re
from urllib.parse import urlsplit

from . import probes


def problem_url(value):
    url = value.get('url', '')
    if not isinstance(url, str) or len(url) > 4096:
        raise ValueError('请填写失败的 http(s) 地址')
    if not url.strip():
        text = value.get('error_text', '')
        if not isinstance(text, str) or len(text) > 16000:
            raise ValueError('错误信息过长，请只保留失败地址附近的几行')
        match = re.search(r'https?://[^\s<>"\x27]+', text)
        url = match.group().rstrip(').,:;，。；：）') if match else ''
    url = url.strip()
    parsed = urlsplit(url)
    if (parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or '?' in url or '#' in url
            or len(url) > 2048 or any(ord(char) < 33 for char in url)):
        raise ValueError('需要不含密码、令牌、查询参数或片段的 http(s) 地址；请手动填写可公开的失败地址')
    try:
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError
    except ValueError as exc:
        raise ValueError('目标端口无效') from exc
    return url


def _summary(result):
    layers = result.get('layers', [])
    failed = next((layer for layer in layers if layer.get('status') == 'failed'), None)
    code = next((layer.get('http_status') for layer in layers if layer.get('http_status')), None)
    if failed:
        label = {'tcp': '建立连接', 'tls': 'TLS 握手', 'http': 'HTTP 响应'}.get(failed.get('layer'), '连接检测')
        return {'ok': False, 'http_status': code, 'label': label + '未通过'}
    if isinstance(code, int):
        return {'ok': 200 <= code < 400, 'http_status': code, 'label': 'HTTP ' + str(code)}
    return {'ok': False, 'http_status': None, 'label': '没有收到明确的 HTTP 响应'}


def diagnose(snapshot, app, value, runner=None):
    url = problem_url(value)
    runner = runner or probes.probe
    # Only entrances derived from this fresh host snapshot are used. A caller
    # cannot supply an arbitrary proxy URL or a VPN's private management port.
    options = [option for tool in snapshot.get('network_tools', []) for option in tool.get('proxy_options', [])][:3]
    choices = [{'id': 'direct', 'name': '普通连接（遵循系统路由）', 'target': {'id': 'direct', 'type': 'direct'}, 'option': None}]
    choices += [{'id': option['id'], 'name': option['tool_name'] + ' · ' + option['proxy_url'],
                 'target': {'id': option['id'], 'type': 'http' if option['protocol'] == 'http' else 'socks5',
                            'host': option['host'], 'port': option['port']}, 'option': option} for option in options]
    def run(choice):
        try:
            result = runner(url, choice['target'], timeout=6)
        except (OSError, ValueError, RuntimeError) as exc:
            result = {'layers': [{'layer': 'tcp', 'status': 'failed', 'error_type': type(exc).__name__}]}
        return {**{key: choice[key] for key in ('id', 'name', 'option')}, **_summary(result),
                'layers': result.get('layers', []), 'elapsed_ms': result.get('elapsed_ms')}
    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(run, choices))
    direct = results[0]
    working = [item for item in results[1:] if item['ok']]
    http = next((item for item in working if item['option']['protocol'] == 'http'), None)
    recommended = http if not direct['ok'] else None
    profile = None
    if recommended:
        title = '建议给 ' + app['name'] + ' 单独指定这个代理入口'
        reason = '普通连接' + direct['label'] + '；通过 ' + recommended['option']['tool_name'] + ' 返回 ' + recommended['label'] + '。'
        if app.get('protected'):
            action = '这个软件属于网络基础组件或当前工作连接，请在其自身设置中核对，工作台保留现有进程。'
        elif app.get('launch_profile', {}).get('available'):
            profile = {'mode': 'http_environment', 'proxy_url': recommended['option']['proxy_url']}
            action = '准备该软件专用的代理环境，关闭该软件后点击“按方案启动”，再重试原来的操作。软件需要支持代理环境变量。'
        else:
            action = '先在本机软件中补充该软件的准确主程序路径，再生成启动文件；也可在软件自己的设置里填写这个代理入口。'
        status = 'proxy_recommended'
    elif direct['ok']:
        status, title = 'target_reachable', '目标地址当前可达，先在原软件中重试'
        reason = '普通连接返回 ' + direct['label'] + '。这次检测没有复现目标地址不可达。'
        action = '若原软件仍失败，核对软件自己的代理设置与新日志；若失败地址变化，把新地址填入后重新检测。'
    elif any(item['http_status'] in {401, 403, 404, 405, 429} for item in results):
        status, title = 'http_response', '已收到服务端响应，需要核对地址或访问权限'
        reason = '部分路径收到 HTTP 错误响应；这与没有建立连接不同，HEAD 检测也可能被目标拒绝。'
        action = '先核对下载地址、登录或访问权限，再结合原软件的 GET 请求日志判断；不要把此结果直接当作代理失效。'
    elif working:
        status, title = 'socks_only', '发现可达的 SOCKS 入口，需要确认应用是否支持'
        reason = 'SOCKS 路径收到成功响应，但当前应用没有经过验证的 SOCKS 接入方式。'
        action = '可在代理客户端启用 HTTP 或混合入站后重新检测，或使用目标软件自身支持的 SOCKS 设置。'
    else:
        status, title = 'no_working_route', '暂时没有找到可达的连接方式'
        reason = '当前已检测的普通连接和明确代理入口均未收到成功响应。' if options else '没有发现协议明确、正在监听的本地代理入口，普通连接也未通过。'
        action = '先在代理客户端确认节点可用并启用本地 HTTP 或混合入口，再点“重新识别”；企业内网地址则核对 aTrust 或组网连接权限。'
    return {'app_id': app['id'], 'app_name': app['name'], 'url': url,
            'snapshot_captured_at': snapshot.get('captured_at'), 'results': results,
            'recommendation': {'status': status, 'title': title, 'reason': reason, 'action': action, 'profile': profile},
            'scope': '只测试此工作台对该地址的 HEAD 请求；尚未验证原软件的安装、登录或完整会话。',
            'network_notice': '普通连接仍遵循当前路由，可能经过 VPN、组网或加速器。'}
