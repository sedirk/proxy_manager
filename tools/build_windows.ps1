param(
    [switch]$SkipDependencyInstall
)

$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$artifactsRoot = Join-Path $projectRoot 'artifacts'
$stagingRoot = Join-Path $artifactsRoot 'release-staging'
$workRoot = Join-Path $artifactsRoot 'pyinstaller-work'
$publishRoot = Join-Path $artifactsRoot 'release-publish'
$previousRoot = Join-Path $artifactsRoot 'release-previous'
$distRoot = Join-Path $projectRoot 'dist'
$stagingExe = Join-Path $stagingRoot 'FlowDesk.exe'
$distExe = Join-Path $distRoot 'FlowDesk.exe'
$smokeReport = Join-Path $artifactsRoot 'exe-smoke.json'
$buildPython = Join-Path $projectRoot '.build-venv\Scripts\python.exe'
$promotionExitCode = 0

function Assert-ProjectPath {
    param([Parameter(Mandatory = $true)][string]$TaskPath)
    $fullPath = [System.IO.Path]::GetFullPath($TaskPath)
    $prefix = $projectRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ('Build output must remain inside the project: ' + $fullPath)
    }
    $component = $fullPath
    while ($component -and $component.StartsWith($projectRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        if (Test-Path -LiteralPath $component) {
            $item = Get-Item -LiteralPath $component -Force
            if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                throw ('Build output must not traverse a reparse point: ' + $component)
            }
        }
        if ($component -eq $projectRoot) { break }
        $parent = [System.IO.Directory]::GetParent($component)
        $component = if ($parent) { $parent.FullName } else { $null }
    }
}

function Invoke-CheckedNative {
    param(
        [Parameter(Mandatory = $true)][string]$Program,
        [Parameter(Mandatory = $true)][string[]]$NativeArguments,
        [Parameter(Mandatory = $true)][string]$Description
    )
    & $Program @NativeArguments
    $nativeExitCode = $LASTEXITCODE
    if ($nativeExitCode -ne 0) {
        throw ($Description + ' failed; native exit code: ' + $nativeExitCode)
    }
}

function Get-DistBusyReason {
    foreach ($taskProcess in @(Get-Process -Name 'FlowDesk' -ErrorAction SilentlyContinue)) {
        try {
            $taskExecutable = $taskProcess.Path
            if (-not $taskExecutable) {
                return ('Cannot confirm the path of a running FlowDesk process (PID ' + $taskProcess.Id + ').')
            }
            if ([System.IO.Path]::GetFullPath($taskExecutable).Equals($distExe, [System.StringComparison]::OrdinalIgnoreCase)) {
                return ('The dist executable is running (PID ' + $taskProcess.Id + ').')
            }
        } catch {
            return ('Cannot safely inspect a running FlowDesk process (PID ' + $taskProcess.Id + ').')
        }
    }
    if (Test-Path -LiteralPath $distExe) {
        $taskFile = $null
        try {
            $taskFile = [System.IO.File]::Open($distExe, [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        } catch {
            return ('The dist executable is occupied, read-only, or inaccessible: ' + $_.Exception.Message)
        } finally {
            if ($null -ne $taskFile) { $taskFile.Dispose() }
        }
    }
    return $null
}

function Show-Candidate {
    param([Parameter(Mandatory = $true)][string]$Reason)
    Write-Warning ($Reason + ' The existing dist has been preserved; no process was stopped.')
    Write-Host ('Validated candidate: ' + $stagingExe)
    Write-Host ('Smoke report: ' + $smokeReport)
    Write-Host 'Exit the old application normally, then rerun the build to publish a newly verified candidate.'
}

Push-Location -LiteralPath $projectRoot
try {
    foreach ($taskDirectory in @($artifactsRoot, $stagingRoot, $workRoot, $publishRoot, $previousRoot, $distRoot)) {
        Assert-ProjectPath $taskDirectory
    }
    Assert-ProjectPath $buildPython
    if (-not (Test-Path -LiteralPath $buildPython -PathType Leaf)) {
        if ($SkipDependencyInstall) {
            throw 'Offline build requires an existing .build-venv with the build dependencies already installed.'
        }
        $basePython = (Get-Command 'python' -CommandType Application -ErrorAction Stop).Source
        Invoke-CheckedNative -Program $basePython -NativeArguments @('-m', 'venv', (Join-Path $projectRoot '.build-venv')) -Description 'Build environment creation'
        if (-not (Test-Path -LiteralPath $buildPython -PathType Leaf)) {
            throw 'Build environment creation did not produce Scripts\python.exe.'
        }
    }
    if ($SkipDependencyInstall) {
        Write-Host 'Skipping dependency installation; using the existing build environment.'
    } else {
        Invoke-CheckedNative -Program $buildPython -NativeArguments @('-m', 'pip', 'install', '--disable-pip-version-check', '-r', (Join-Path $projectRoot 'tools\requirements-build.txt')) -Description 'Pinned build dependency installation'
    }

    foreach ($taskDirectory in @($artifactsRoot, $stagingRoot, $workRoot)) {
        [System.IO.Directory]::CreateDirectory($taskDirectory) | Out-Null
    }
    foreach ($taskFile in @($stagingExe, $smokeReport, $distExe)) { Assert-ProjectPath $taskFile }
    # A report from an earlier candidate must never certify the current build.
    if (Test-Path -LiteralPath $smokeReport) { Remove-Item -LiteralPath $smokeReport }
    Invoke-CheckedNative -Program $buildPython -NativeArguments @('-m', 'PyInstaller', '--noconfirm', '--distpath', $stagingRoot, '--workpath', $workRoot, (Join-Path $projectRoot 'FlowDesk.spec')) -Description 'Staging build'
    if (-not (Test-Path -LiteralPath $stagingExe -PathType Leaf)) {
        throw 'PyInstaller succeeded without producing the staging executable; dist was not changed.'
    }
    $candidateHash = (Get-FileHash -LiteralPath $stagingExe -Algorithm SHA256).Hash
    # Run only after PyInstaller has exited. The harness launches an isolated copy.
    Invoke-CheckedNative -Program $buildPython -NativeArguments @('-X', 'utf8', (Join-Path $projectRoot 'tools\smoke_exe.py'), $stagingExe, '--report', $smokeReport) -Description 'Staging executable smoke test'
    if (-not (Test-Path -LiteralPath $smokeReport -PathType Leaf)) {
        throw 'Smoke test did not produce a report; dist was not changed.'
    }
    $report = Get-Content -LiteralPath $smokeReport -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($report.sha256 -ne $candidateHash -or $report.system_proxy_unchanged -ne $true -or
        $report.graceful_shutdown -ne $true -or
        (Get-FileHash -LiteralPath $stagingExe -Algorithm SHA256).Hash -ne $candidateHash) {
        throw 'The smoke report does not certify this unchanged candidate; dist was not changed.'
    }
    Write-Host ('Verified staging SHA-256: ' + $candidateHash)

    $busyReason = Get-DistBusyReason
    if ($busyReason) {
        Show-Candidate $busyReason
        $promotionExitCode = 2
    } else {
        foreach ($taskDirectory in @($publishRoot, $previousRoot, $distRoot)) {
            Assert-ProjectPath $taskDirectory
            [System.IO.Directory]::CreateDirectory($taskDirectory) | Out-Null
        }
        $publishFile = Join-Path $publishRoot ('FlowDesk-' + [System.Guid]::NewGuid().ToString('N') + '.pending')
        $previousExe = Join-Path $previousRoot ('FlowDesk-' + (Get-Date -Format 'yyyyMMddTHHmmss') + '-' + [System.Guid]::NewGuid().ToString('N') + '.exe')
        foreach ($taskFile in @($publishFile, $previousExe, $distExe)) { Assert-ProjectPath $taskFile }
        Copy-Item -LiteralPath $stagingExe -Destination $publishFile
        if ((Get-FileHash -LiteralPath $publishFile -Algorithm SHA256).Hash -ne $candidateHash) {
            throw 'Publication copy hash mismatch; dist was not changed.'
        }
        # Recheck after the verified copy, immediately before the atomic publish.
        $busyReason = Get-DistBusyReason
        if ($busyReason) {
            Show-Candidate $busyReason
            $promotionExitCode = 2
        } else {
            try {
                if (Test-Path -LiteralPath $distExe) {
                    [System.IO.File]::Replace($publishFile, $distExe, $previousExe)
                    Write-Host ('Previous executable: ' + $previousExe)
                } else {
                    [System.IO.File]::Move($publishFile, $distExe)
                }
                Write-Host ('Published: ' + $distExe)
            } catch [System.IO.IOException] {
                Show-Candidate ('Atomic publication could not proceed: ' + $_.Exception.Message)
                $promotionExitCode = 2
            } catch [System.UnauthorizedAccessException] {
                Show-Candidate ('Atomic publication was denied: ' + $_.Exception.Message)
                $promotionExitCode = 2
            }
        }
    }
} finally {
    Pop-Location
}

if ($promotionExitCode -ne 0) { exit $promotionExitCode }
