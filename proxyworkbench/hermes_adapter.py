"""Narrow adapter for the native Hermes checkout installation on Windows.

Uses Hermes' own task-aware lifecycle CLI. No taskkill, config/secret reads,
scheduled-task edits, profile changes, or direct writes to Hermes state.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
from datetime import datetime, timezone

from .catalog import application_executable_path, _checked
from . import process_proxy
from .proxy_environment import child_environment

LAN_BYPASS = 'localhost,127.0.0.1,::1,127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,fc00::/7,fe80::/10'


def installation(executable):
    path = Path(executable)
    if path.name.casefold() != 'hermes.exe':
        return None
    # GUI and bin/hermes.exe have the same name. Require the actual GUI layout.
    suffix = ['win-unpacked', 'release', 'desktop', 'apps', 'hermes-agent']
    if [p.name.casefold() for p in list(path.parents)[:5]] != suffix:
        return None
    home = path.parents[5]
    try:
        cli = application_executable_path(str(home / 'bin' / 'hermes.exe'))
        application_executable_path(str(path))
        if not _checked(path.parent / 'resources' / 'app.asar').is_file():
            return None
        if not _checked(home / 'hermes-agent' / 'hermes_cli' / 'main.py').is_file():
            return None
    except (ValueError, OSError):
        return None
    return {'home': str(home), 'cli': cli, 'desktop': str(path)}


def describe(executable):
    if installation(executable):
        return {'id': 'hermes', 'label': 'Hermes 窗口与后台',
                'notice': '模型请求由独立后台发送。首次应用可能需退出旧窗口；后台重启先预览，有进行中任务则拒绝。本机与私网 IP 绕过代理。'}
    if Path(executable).name.casefold().startswith('hermes-setup'):
        return {'id': 'installer', 'label': 'Hermes 安装器',
                'notice': '这里只影响安装器。使用模型请在软件清单选择已安装的 Hermes，或添加其主程序。'}
    if Path(executable).name.casefold() == 'hermes.exe':
        return {'id': 'hermes_unsupported', 'label': 'Hermes 路径待确认',
                'notice': '这个路径不是已验证的 Hermes 桌面安装。bin/hermes.exe 是命令行入口；请选已安装的桌面主程序。自定义安装暂不自动重配后台。'}
    return None


def default_desktop(environ=None):
    env = os.environ if environ is None else environ
    if not env.get('LOCALAPPDATA'):
        return None
    candidate = Path(env['LOCALAPPDATA']) / 'hermes/hermes-agent/apps/desktop/release/win-unpacked/Hermes.exe'
    return str(candidate) if installation(str(candidate)) else None


def environment(inherited, mode, endpoint, install):
    result = child_environment(inherited, mode, endpoint)
    if mode == 'http_environment':
        result['NO_PROXY'] = LAN_BYPASS
        result['GLOBAL_AGENT_NO_PROXY'] = LAN_BYPASS + ',[::1]'
    # Always select the root host, not Hermes' sticky active_profile.
    for key in list(result):
        if key.upper() in {'HERMES_HOME', 'HERMES_PROFILE', 'HERMES_ACTIVE_PROFILE', 'PYTHONHOME', 'PYTHONPATH'}:
            result.pop(key)
    result.update(HERMES_HOME=install['home'], PYTHONUTF8='1', PYTHONIOENCODING='utf-8',
                  PYINSTALLER_RESET_ENVIRONMENT='1')
    return result


def backend(install, items):
    state_path = Path(install['home']) / 'gateway_state.json'
    try:
        checked = _checked(state_path)
        if checked.stat().st_size > 256 * 1024:
            raise ValueError()
        state = json.loads(checked.read_text(encoding='utf-8-sig'))
        if not isinstance(state, dict):
            raise ValueError()
        pid = int(state.get('pid') or 0)
    except FileNotFoundError:
        return {'state': 'stopped'}
    except (OSError, ValueError, TypeError):
        return {'state': 'unknown', 'detail': '后台状态文件不可核对'}
    item = next((p for p in items if p.get('ProcessId') == pid), None)
    if not item:
        return {'state': 'stopped'}
    try:
        executable = Path(item.get('ExecutablePath') or '')
        relative = executable.relative_to(Path(install['home']))
        if relative.parts[0].casefold() not in {'tools', 'installs'} or executable.name.casefold() not in {'python.exe', 'pythonw.exe'}:
            raise ValueError()
        args = process_proxy.argv(item.get('CommandLine') or process_proxy.commandline(item))
        rest = args[3:] if len(args) >= 5 and args[1:3] == ['-m', 'hermes_cli.main'] else []
        if rest[:1] in (['--profile'], ['-p']):
            if rest[1:2] != ['default']:
                raise ValueError()
            rest = rest[2:]
        if (relative.parts[0].casefold() not in {'tools', 'installs'} or
                executable.name.casefold() not in {'python.exe', 'pythonw.exe'} or rest[:2] != ['gateway', 'run']):
            raise ValueError()
        # A stale state file must not attach to a recycled Python PID.
        centiseconds = round((int(item['Started']) / 10000000 - 11644473600) * 100)
        if state.get('start_time') is None or abs(centiseconds - int(state['start_time'])) > 1:
            raise ValueError()
        if not state.get('hermes_home') or os.path.normcase(os.path.abspath(state['hermes_home'])) != os.path.normcase(os.path.abspath(install['home'])):
            raise ValueError()
        if rest[2:] not in ([], ['--quiet']):
            raise ValueError()
        updated = datetime.fromisoformat(state['updated_at'])
        if not updated.tzinfo or not -10 <= (datetime.now(timezone.utc) - updated).total_seconds() <= 180:
            raise ValueError()
        active = int(state['active_agents'])
        if active < 0:
            raise ValueError()
    except (ValueError, TypeError, KeyError, IndexError):
        return {'state': 'unknown', 'detail': '后台进程身份与安装目录不一致；拒绝重启'}
    return {'state': 'running', 'pid': pid, 'active_agents': active, '_process': item,
            'started': str(item['Started'])}


def desktop_home(values):
    """Match the installed desktop's documented home selection without secrets."""
    value = values.get('HERMES_HOME')
    if not value and values.get('HERMES_DESKTOP_USER_DATA_DIR'):
        return str(Path(values['HERMES_DESKTOP_USER_DATA_DIR']) / 'hermes-home')
    if not value and 'HERMES_HOME' not in values and os.name == 'nt':
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Environment') as key:
                value, _ = winreg.QueryValueEx(key, 'HERMES_HOME')
                value = winreg.ExpandEnvironmentStrings(value)
        except FileNotFoundError:
            pass
    if value:
        path = Path(value)
        return str(path.parent.parent if path.parent.name.casefold() == 'profiles' else path)
    if not values.get('LOCALAPPDATA'):
        raise ValueError('无法确认 Hermes 窗口使用的数据目录')
    return str(Path(values['LOCALAPPDATA']) / ('hermes' + values.get('HERMES_DATA_DIR_SUFFIX', '')))


def lifecycle_pending(install, items):
    for item in process_proxy.matching(items, install['cli']):
        args = process_proxy.argv(item.get('CommandLine') or process_proxy.commandline(item))
        if args[1:5] in (['-p', 'default', 'gateway', 'restart'], ['--profile', 'default', 'gateway', 'restart']):
            return True
    return False


def command(install, arguments, env, timeout=120):
    from .app_launch import _external_libraries
    # A temporary handle avoids inherited pipes keeping communicate() stuck after
    # a launcher timeout. Only bounded ensure JSON is read; raw CLI logs are discarded.
    with tempfile.TemporaryFile() as output:
        with _external_libraries():
            process = subprocess.Popen([install['cli'], '-p', 'default', 'gateway', *arguments],
                                       cwd=install['home'], env=env, stdin=subprocess.DEVNULL,
                                       stdout=output, stderr=subprocess.DEVNULL,
                                       creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            # Do not kill the official lifecycle client midway through a drain.
            # Future plans detect the exact still-running restart command.
            raise ValueError('Hermes 后台操作仍未结束。请稍后点“检查此软件”；本工具不会强杀后台或连续重启。') from None
        if process.returncode:
            raise ValueError('Hermes 拒绝或未完成后台操作；可能仍有任务、后台委派或安装异常。请先在 Hermes 结束任务，再检查并重试。')
        if output.tell() > 65536:
            raise ValueError('后台返回超出预期，请检查 Hermes 日志。')
        output.seek(0)
        return output.read(65536).decode('utf-8-sig', errors='replace')


def apply(install, env, restart):
    if restart:
        # No --yes/--interrupt/--force/--all: preserve Hermes' live-work guard.
        command(install, ['restart', '--detach'], env)
    output = command(install, ['ensure', '--json', '--timeout', '35'], env, timeout=45)
    verdict = None
    for line in reversed(output.splitlines()):
        try:
            candidate = json.loads(line)
            if isinstance(candidate, dict) and 'state' in candidate:
                verdict = candidate
                break
        except ValueError:
            continue
    if not verdict or verdict.get('state') != 'ready':
        raise ValueError('Hermes 后台尚未就绪，请稍后检查；未验证模型连接成功。')
