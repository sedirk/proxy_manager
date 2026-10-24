$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    if (-not (Test-Path '.build-venv\Scripts\python.exe')) {
        python -m venv .build-venv
        if ($LASTEXITCODE -ne 0) { throw 'Could not create the build environment.' }
    }
    $buildPython = Join-Path $projectRoot '.build-venv\Scripts\python.exe'
    & $buildPython -m pip install --disable-pip-version-check -r tools/requirements-build.txt
    if ($LASTEXITCODE -ne 0) { throw 'Could not install the pinned build dependencies.' }
    & $buildPython -m PyInstaller --noconfirm FlowDesk.spec
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed.' }
    Write-Host ('Built: ' + (Join-Path $projectRoot 'dist\FlowDesk.exe'))
} finally {
    Pop-Location
}
