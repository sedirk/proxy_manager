"""Compose existing inspection/probe evidence without applying settings.

Reports are point-in-time observations. User feedback is a separate source;
neither a proxy environment nor our HEAD request proves application success.
"""
from urllib.parse import urlsplit
from . import troubleshoot


def optional_url(value):
    raw = value.get('url', '')
    if not isinstance(raw, str):
        raise ValueError('目标地址需要是文本；可留空仅检查软件。')
    return troubleshoot.problem_url({'url': raw}) if raw.strip() else ''


def verify_path(record, url, snapshot, runner):
    scope = '仅此工作台发起的 HEAD 请求；不是原软件的登录、下载或完整会话。'
    if record['mode'] == 'inherit':
        return {'results': [], 'scope': scope, 'recommendation': {
            'title': '沿用默认设置由原软件决定', 'reason': '工作台无法模拟软件的系统/PAC/私有代理选择。',
            'action': '请在原软件重试，并在下面记录实际结果。'}}
    target = {'id': 'saved-route', 'type': 'direct'}
    label = '未显式使用代理（仍遵循系统路由）'
    if record['mode'] == 'http_environment':
        available = [option.get('proxy_url') for tool in snapshot.get('network_tools', [])
                     for option in tool.get('proxy_options', []) if option.get('protocol') == 'http']
        if record['proxy_url'] not in available:
            return {'results': [{'id': 'saved-route', 'name': '已保存入口', 'ok': False,
                                 'label': '入口已变化或未被识别，未发送请求', 'layers': []}],
                    'scope': scope, 'recommendation': {'title': '重新核对代理入口',
                    'reason': '当前观察中没有这个保存的 HTTP 入口。',
                    'action': '重新检测网络工具、选择有效入口，再保存并应用。'}}
        parsed = urlsplit(record['proxy_url'])
        target.update(type='http', host=parsed.hostname, port=parsed.port)
        label = '已保存 HTTP 入口 · ' + record['proxy_url']
    try:
        result = runner(url, target, timeout=6)
    except (OSError, ValueError, RuntimeError) as exc:
        result = {'layers': [{'layer': 'tcp', 'status': 'failed', 'error_type': type(exc).__name__}]}
    row = {'id': 'saved-route', 'name': label, **troubleshoot._summary(result),
           'layers': result.get('layers', []), 'elapsed_ms': result.get('elapsed_ms')}
    return {'results': [row], 'scope': scope, 'recommendation': {
        'title': '已保存路径收到响应，原软件仍需复测' if row['ok'] else '已保存路径仍有未通过项',
        'reason': row['label'],
        'action': '在原软件重试并记录结果；若仍失败，查看新日志或填写新的失败地址。' if row['ok'] else
                  '查看失败层级；HTTP 拒绝响应需核对地址或权限，不能直接判定代理失效。'}}


def compose(stage, app, record, saved, inspection, snapshot, url, runner):
    comparison = recommendation = None
    if url:
        if stage == 'diagnose':
            comparison = troubleshoot.diagnose(snapshot, app, {'url': url}, runner)
            recommendation = comparison['recommendation'].get('profile')
        else:
            comparison = verify_path(record, url, snapshot, runner)
    env = inspection.get('environment_status', 'unknown')
    steps = []
    if not saved:
        steps.append('当前尚未保存连接方式；检查以沿用默认设置为基准。选择连接方式后先保存。')
    if env in {'missing', 'different'}:
        steps.append('当前进程环境与设置不一致。先预览应用范围；旧实例可能需要正常退出，不能原地更改环境。')
    elif env == 'not_running':
        steps.append('尚无可核对的目标进程；保存后预览并应用，再重新验证。')
    elif env == 'unknown':
        steps.append('当前进程采用情况尚不明确；检查权限、程序路径及应用自己的设置，不要据此断言直连。')
    elif env == 'matches':
        steps.append('代理环境与设置一致；这仍不能证明原软件的请求成功或采用显式代理参数。')
    if comparison:
        steps.append(comparison.get('recommendation', {}).get('action', '请在原软件复测。'))
    else:
        steps.append('可填写不含凭据或查询参数的 HTTP(S) 地址，继续检查目标路径；留空不发起目标请求。')
    steps.append('请在原软件完成原来的操作，再选择“原软件已正常”或“仍然失败”；结果标为用户反馈。' if stage == 'verify' else
                 '建议只供选择，不会自动改线、保存或启动软件。应用前可查看具体影响。')
    return {'app_id': app['id'], 'stage': stage, 'saved': saved, 'inspection': inspection,
            'comparison': comparison, 'recommendation': recommendation,
            'summary': '验证已完成，原软件结果待确认。' if stage == 'verify' else '诊断已完成，请核对证据和下一步。',
            'next_steps': steps, 'application_result': {'status': 'unverified', 'source': 'none'}}
