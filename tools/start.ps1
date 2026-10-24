$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
try {
    $executable = Join-Path $projectRoot 'dist\FlowDesk.exe'
    if (Test-Path -LiteralPath $executable -PathType Leaf) {
        # A project launch always uses the project's saved plan, for both builds.
        Start-Process -FilePath $executable -ArgumentList ('--data-root "' + $projectRoot + '"') -WorkingDirectory $projectRoot -WindowStyle Hidden
        exit
    }
    $runtime = Get-Command pythonw.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $runtime) {
        $runtime = Get-Command pyw.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    if (-not $runtime) { throw '需要 Python 3.11 或更新版本。请安装 Python 后重新打开。' }
    $entryPath = Join-Path $projectRoot 'run.py'
    Start-Process -FilePath $runtime.Source -ArgumentList ('"' + $entryPath + '" --data-root "' + $projectRoot + '"') -WorkingDirectory $projectRoot -WindowStyle Hidden
} catch {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, '流向 · 启动未完成') | Out-Null
}
