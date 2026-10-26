"""Windows shortcuts re-use saved application settings and the same review path."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from . import runtime
from .app_routes import parse


def launcher(root, key):
    if not re.fullmatch('[0-9a-f]{24}', key):
        raise ValueError('应用快捷方式标识无效')
    options = ['--data-root', str(Path(root).resolve()), '--launch-app', key]
    if runtime.frozen():
        return sys.executable, options
    interpreter = Path(sys.executable)
    windowless = interpreter.with_name('pythonw.exe')
    return str(windowless if windowless.is_file() else interpreter), [str(runtime.asset_root() / 'run.py'), *options]


def create(root, record, name, *, directory=None):
    if os.name != 'nt':
        raise ValueError('桌面快捷方式仅支持 Windows')
    from .app_launch import _external_libraries
    target, arguments = launcher(root, record['key'])
    safe_name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name).strip(' .')[:70] or '应用'
    payload = {'target': target, 'arguments': subprocess.list2cmdline(arguments),
               'directory': str(directory) if directory else '',
               'name': safe_name + '（FlowDesk）', 'key': record['key'], 'icon': record['executable'],
               'working': str(Path(target).parent)}
    # Payload is data on stdin; no user-controlled interpolation into PowerShell.
    script = """$ErrorActionPreference='Stop'
[Console]::InputEncoding=[System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$data=[Console]::In.ReadToEnd() | ConvertFrom-Json
$folder=if($data.directory){$data.directory}else{[Environment]::GetFolderPath('Desktop')}
if(-not (Test-Path -LiteralPath $folder -PathType Container)){throw 'Desktop unavailable'}
$shell=New-Object -ComObject WScript.Shell
$path=Join-Path $folder ($data.name+'.lnk')
if(Test-Path -LiteralPath $path){
  $old=$shell.CreateShortcut($path)
  if($old.TargetPath -ne $data.target -or $old.Arguments -ne $data.arguments){
    $path=Join-Path $folder ($data.name+'-'+$data.key.Substring(0,8)+'.lnk')
    if(Test-Path -LiteralPath $path){
      $existing=$shell.CreateShortcut($path)
      if($existing.TargetPath -ne $data.target -or $existing.Arguments -ne $data.arguments){throw 'A different shortcut already exists'}
    }
  }
}
$link=$shell.CreateShortcut($path)
$link.TargetPath=$data.target
$link.Arguments=$data.arguments
$link.WorkingDirectory=$data.working
$link.IconLocation=$data.icon+',0'
$link.Description='FlowDesk: use saved application connection settings'
$link.Save()
@{path=$path} | ConvertTo-Json -Compress
"""
    shell = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    with _external_libraries():
        result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-Command', script],
                                input=json.dumps(payload, ensure_ascii=False), text=True, encoding='utf-8',
                                capture_output=True, timeout=12,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode:
        raise ValueError('未能创建桌面快捷方式。请检查桌面权限或同名快捷方式；未启动应用。')
    saved = json.loads(result.stdout)
    return {'path': saved['path'], 'notice': '桌面快捷方式已创建。以后双击使用该软件最新保存的设置，无需输入命令。请保留 FlowDesk 所在位置；本次未启动软件。'}


def launch_saved(root, key, *, confirm=None):
    """No control-server instance, system lease, or arbitrary launch command."""
    from .app_connections import execute, plan
    launcher(root, key)  # Validate key before reading records.
    document = parse(json.loads((Path(root) / '.local/app-routes.json').read_text(encoding='utf-8')))
    record = next((r for r in document['routes'] if r['key'] == key), None)
    if record is None:
        raise ValueError('此应用的连接设置不存在，请在 FlowDesk 中重新保存并创建快捷方式。')
    prepared = plan(record)
    if not prepared['can_launch']:
        raise ValueError(prepared['summary'])
    if prepared['requires_confirmation']:
        if confirm is None:
            import ctypes
            confirm = lambda message: ctypes.windll.user32.MessageBoxW(None, message, 'FlowDesk · 应用连接设置', 0x124) == 6
        message = '\n\n'.join([prepared['summary'], '\n'.join(prepared['steps']), prepared['notice'], '是否继续？'])
        if not confirm(message):
            return {'cancelled': True}
    return execute(root, record, prepared)
