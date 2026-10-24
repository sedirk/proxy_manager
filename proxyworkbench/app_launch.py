"""Explicitly launch one application with a private proxy environment."""
import json
import os
from pathlib import Path
import subprocess
import threading
import sys
import ctypes
from contextlib import contextmanager

from .catalog import application_executable_path, _PROTECTED_EXES, _PROXY_NAMES

_LOCK = threading.Lock()


@contextmanager
def _external_libraries():
    # The frozen Windows bootloader's DLL search directory is inherited by
    # children. Restore standard search for CreateProcess, then our own search.
    if os.name != 'nt' or not getattr(sys, 'frozen', False):
        yield
        return
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetDllDirectoryW.argtypes = [wintypes.DWORD, wintypes.LPWSTR]
    kernel.GetDllDirectoryW.restype = wintypes.DWORD
    kernel.SetDllDirectoryW.argtypes = [wintypes.LPCWSTR]
    kernel.SetDllDirectoryW.restype = wintypes.BOOL
    length = kernel.GetDllDirectoryW(0, None)
    buffer = ctypes.create_unicode_buffer(length + 1)
    if length:
        kernel.GetDllDirectoryW(len(buffer), buffer)
    previous = buffer.value or None
    if not kernel.SetDllDirectoryW(None):
        raise OSError('Could not restore child DLL search path')
    try:
        yield
    finally:
        if not kernel.SetDllDirectoryW(previous):
            raise OSError('Could not restore workbench DLL search path')


def _running_images():
    if os.name != 'nt':
        raise ValueError('按方案启动仅支持 Windows；可以下载启动文件供审查。')
    script = "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); @(Get-CimInstance Win32_Process -Property Name,ExecutablePath,ProcessId -ErrorAction Stop | Select-Object Name,ExecutablePath,ProcessId) | ConvertTo-Json -Compress"
    shell = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    with _external_libraries():
        process = subprocess.Popen([str(shell), '-NoProfile', '-NonInteractive', '-Command', script],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8-sig',
                                   creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    try:
        stdout, _ = process.communicate(timeout=12)
    except subprocess.TimeoutExpired:
        process.kill()  # Only the read-only query helper created immediately above.
        process.communicate()
        raise
    if process.returncode:
        raise ValueError('未能确认现有软件实例，请重试或下载启动文件。')
    try:
        records = json.loads(stdout)
    except ValueError as exc:
        raise ValueError('未能读取现有软件实例，请重试。') from exc
    return records if isinstance(records, list) else [records]


def launch(executable, proxy_url):
    if not _LOCK.acquire(blocking=False):
        raise RuntimeError('另一项启动正在进行，请等待结果')
    try:
        executable = application_executable_path(executable)
        if Path(executable).name.casefold() in _PROTECTED_EXES:
            raise ValueError('该网络组件或工作连接受保护，请在软件自身界面操作。')
        key = os.path.normcase(os.path.abspath(executable))
        images = _running_images()
        if any((os.path.normcase(os.path.abspath(item['ExecutablePath'])) == key if item.get('ExecutablePath') else
                str(item.get('Name', '')).casefold() == Path(executable).name.casefold()) for item in images):
            raise ValueError('目标软件还在运行，请先关闭它，再点击“按方案启动”；工作台不会结束现有进程。')
        # The service accepts only a successful check's local HTTP entrance.
        from urllib.parse import urlsplit
        import ipaddress
        parsed = urlsplit(proxy_url)
        if (parsed.scheme != 'http' or not parsed.hostname or not ipaddress.ip_address(parsed.hostname).is_loopback
                or not parsed.port or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment):
            raise ValueError('启动方案的本机代理入口无效，请重新检测。')
        environment = {key: value for key, value in os.environ.items() if key.upper() not in _PROXY_NAMES}
        environment.update(HTTP_PROXY=proxy_url, HTTPS_PROXY=proxy_url, ALL_PROXY=proxy_url, NO_PROXY='localhost,127.0.0.1,::1')
        environment['PYINSTALLER_RESET_ENVIRONMENT'] = '1'
        bundled = getattr(sys, '_MEIPASS', None)
        if bundled:
            bundle_key = os.path.normcase(os.path.abspath(bundled))
            environment['PATH'] = os.pathsep.join(item for item in environment.get('PATH', '').split(os.pathsep)
                if item and not os.path.normcase(os.path.abspath(item)).startswith(bundle_key + os.sep)
                and os.path.normcase(os.path.abspath(item)) != bundle_key)
        with _external_libraries():
            child = subprocess.Popen([executable], cwd=str(Path(executable).parent), env=environment)
        return {'pid': child.pid, 'executable': executable,
                'notice': '已按方案创建新进程，请在目标软件里重试原操作；这还不代表安装或登录成功。'}
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError('未能启动目标软件：' + type(exc).__name__ + '。请检查路径或下载启动文件。') from exc
    finally:
        _LOCK.release()
