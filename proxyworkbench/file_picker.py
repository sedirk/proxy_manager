"""User-initiated Windows file chooser; never executes the selected program."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

_PICKER_LOCK = threading.Lock()
_SCRIPT = r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$owner = New-Object System.Windows.Forms.Form
try {
    $dialog.Title = '选择要添加到流向的软件'
    $dialog.Filter = 'Windows 程序 (*.exe)|*.exe'
    $dialog.CheckFileExists = $true
    $dialog.CheckPathExists = $true
    $dialog.Multiselect = $false
    $dialog.RestoreDirectory = $true
    $owner.Text = '流向 · 添加软件'
    $owner.ShowInTaskbar = $false
    $owner.TopMost = $true
    $owner.Opacity = 0
    $owner.Width = 1
    $owner.Height = 1
    $owner.StartPosition = 'CenterScreen'
    $owner.Show()
    $owner.Activate()
    if ($dialog.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) {
        @{cancelled=$false; executable=$dialog.FileName} | ConvertTo-Json -Compress
    } else {
        @{cancelled=$true} | ConvertTo-Json -Compress
    }
} finally {
    $dialog.Dispose()
    $owner.Dispose()
}
'''


def choose_executable():
    if sys.platform != 'win32':
        raise ValueError('文件选择窗口仅支持 Windows；请直接粘贴程序的完整路径。')
    if not _PICKER_LOCK.acquire(blocking=False):
        raise RuntimeError('已有一个文件选择窗口，请完成或取消该窗口。')
    try:
        powershell = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        command = [str(powershell), '-NoProfile', '-STA', '-EncodedCommand',
                   base64.b64encode(_SCRIPT.encode('utf-16le')).decode('ascii')]
        try:
            result = subprocess.run(command, capture_output=True, encoding='utf-8',
                                    timeout=120, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except subprocess.TimeoutExpired as exc:
            raise ValueError('文件选择窗口已超时，请重试或直接粘贴程序路径。') from exc
        except OSError as exc:
            raise ValueError('无法打开文件选择窗口，请直接粘贴程序路径。') from exc
        if result.returncode != 0:
            raise ValueError('文件选择窗口未能完成，请直接粘贴程序路径。')
        try:
            selected = json.loads(result.stdout.lstrip('\ufeff'))
        except (ValueError, TypeError) as exc:
            raise ValueError('未能读取选择结果，请直接粘贴程序路径。') from exc
        if isinstance(selected, dict) and selected.get('cancelled') is True:
            return {'cancelled': True}
        if (not isinstance(selected, dict) or selected.get('cancelled') is not False
                or not isinstance(selected.get('executable'), str) or not selected['executable']):
            raise ValueError('未能读取所选程序路径，请重试。')
        # Registration performs path validation. A selection alone changes nothing.
        return {'cancelled': False, 'executable': selected['executable']}
    finally:
        _PICKER_LOCK.release()
