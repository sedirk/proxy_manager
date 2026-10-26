"""On-demand, read-only proxy evidence for an explicitly selected process.

Process command lines are used only for identity and are never returned to the UI.
The bounded environment read retains only proxy variables and non-secret Hermes
home identity fields. Neither complete environments nor command lines are saved.
"""
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess

from .proxy_environment import PROXY_NAMES

IDENTITY_NAMES = ('HERMES_HOME', 'HERMES_DESKTOP_USER_DATA_DIR', 'HERMES_DATA_DIR_SUFFIX', 'LOCALAPPDATA', 'USERPROFILE')


def records():
    if os.name != 'nt':
        raise ValueError('应用运行检查仅支持 Windows')
    from .app_launch import _external_libraries
    shell = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    script = "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); @(Get-CimInstance Win32_Process -ErrorAction Stop | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,@{n='Started';e={if($_.CreationDate){$_.CreationDate.ToFileTimeUtc().ToString()}}}) | ConvertTo-Json -Compress"
    with _external_libraries():
        result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-Command', script],
                                capture_output=True, encoding='utf-8-sig', timeout=15,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode:
        raise ValueError('未能读取进程身份；没有启动或停止软件')
    data = json.loads(result.stdout)
    return data if isinstance(data, list) else [data]


def commandline(item):
    """Only after the adapter has matched one specific installation-owned PID."""
    from .app_launch import _external_libraries
    pid = int(item['ProcessId'])
    shell = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    script = f"[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}' -ErrorAction Stop | Select-Object CommandLine,@{{n='Started';e={{$_.CreationDate.ToFileTimeUtc().ToString()}}}} | ConvertTo-Json -Compress"
    with _external_libraries():
        result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-Command', script],
                                capture_output=True, encoding='utf-8-sig', timeout=10,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode:
        raise ValueError('无法核对所选后台命令')
    data = json.loads(result.stdout)
    if not isinstance(data, dict) or data.get('Started') != item.get('Started'):
        raise ValueError('后台进程已变化')
    return data.get('CommandLine') or ''


def matching(items, executable):
    key = os.path.normcase(os.path.abspath(executable))
    return [p for p in items if p.get('ExecutablePath') and
            os.path.normcase(os.path.abspath(p['ExecutablePath'])) == key]


def argv(command):
    """Use Windows' own command-line parser; never identify by substring."""
    if not command or os.name != 'nt':
        return []
    shell = ctypes.WinDLL('shell32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    shell.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    shell.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    count = ctypes.c_int()
    pointer = shell.CommandLineToArgvW(command, ctypes.byref(count))
    if not pointer:
        return []
    try:
        return [pointer[i] for i in range(count.value)]
    finally:
        kernel.LocalFree(pointer)


def proxy_values(item):
    """A handle pins the identity; access/architecture errors stay unknown."""
    if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise ValueError('当前架构无法读取代理变量')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    ntdll = ctypes.WinDLL('ntdll')
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    kernel.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    ntdll.NtQueryInformationProcess.argtypes = [wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG)]
    handle = kernel.OpenProcess(0x410, False, int(item['ProcessId']))
    if not handle:
        raise ValueError('无法读取该进程；可能已退出或权限不足')
    try:
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buffer))
        times = [wintypes.FILETIME() for _ in range(4)]
        wow = wintypes.BOOL()
        if (not kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)) or
                not kernel.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]) or
                not kernel.IsWow64Process(handle, ctypes.byref(wow)) or wow.value):
            raise ValueError('无法核对进程身份或不支持该进程架构')
        started = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
        if (not matching([{'ExecutablePath': buffer.value}], item['ExecutablePath']) or
                started // 10 != int(item.get('Started') or 0) // 10):
            raise ValueError('进程已变化，请重新检查')

        def read(address, length):
            block = ctypes.create_string_buffer(length)
            count = ctypes.c_size_t()
            if not kernel.ReadProcessMemory(handle, address, block, length, ctypes.byref(count)):
                raise ValueError('进程代理环境不可读取')
            return block.raw[:count.value]

        basic = (ctypes.c_uint64 * 6)()
        returned = wintypes.ULONG()
        if ntdll.NtQueryInformationProcess(handle, 0, ctypes.byref(basic), ctypes.sizeof(basic), ctypes.byref(returned)):
            raise ValueError('进程代理环境不可读取')
        params = int.from_bytes(read(basic[1] + 0x20, 8), 'little')
        address = int.from_bytes(read(params + 0x80, 8), 'little')
        raw = bytearray()
        for offset in range(0, 256 * 1024, 256):
            raw.extend(read(address + offset, 256))
            if '\0\0' in raw.decode('utf-16le', errors='replace'):
                break
        else:
            raise ValueError('进程环境超过读取上限')
        result = {}
        for entry in raw.decode('utf-16le', errors='replace').split('\0'):
            if not entry:
                break
            key, separator, value = entry.partition('=')
            if separator and key.upper() in (*PROXY_NAMES, *IDENTITY_NAMES):
                result[key.upper()] = value[:4096]
        alive = wintypes.DWORD()
        if not kernel.GetExitCodeProcess(handle, ctypes.byref(alive)) or alive.value != 259:
            raise ValueError('进程已退出，请重新检查')
        return result
    finally:
        kernel.CloseHandle(handle)
