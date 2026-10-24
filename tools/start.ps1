$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
try {
    $runtime = Get-Command pythonw.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $runtime) {
        $runtime = Get-Command pyw.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    if (-not $runtime) { throw '需要 Python 3.11 或更新版本。请安装 Python 后重新打开。' }
    $entryPath = Join-Path $projectRoot 'run.py'
    Start-Process -FilePath $runtime.Source -ArgumentList ('"' + $entryPath + '"') -WorkingDirectory $projectRoot -WindowStyle Hidden
} catch {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, '流向 · 启动未完成') | Out-Null
}
