# Build on Windows x64: python -m PyInstaller --noconfirm FlowDesk.spec
from pathlib import Path

project = Path(SPECPATH)
a = Analysis(
    [str(project / 'run.py')],
    pathex=[str(project)],
    binaries=[],
    datas=[(str(project / 'web'), 'web'), (str(project / 'THIRD_PARTY_NOTICES.txt'), '.')],
    hiddenimports=['proxyworkbench.guardian'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name='FlowDesk',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    version=str(project / 'tools' / 'windows_version.txt'),
)
