"""Separate bundled read-only assets from persistent per-user state."""
import os
from pathlib import Path
import sys


def frozen():
    return bool(getattr(sys, 'frozen', False))


def asset_root():
    return Path(__file__).resolve().parent.parent


def data_root(override=None):
    if override is not None:
        return Path(override).expanduser().resolve()
    if frozen():
        base = os.environ.get('LOCALAPPDATA')
        return (Path(base) if base else Path.home() / 'AppData' / 'Local') / 'FlowDesk'
    return asset_root()


def guardian_launch(journal_path, identifier):
    path = Path(journal_path).resolve()
    environment = os.environ.copy()
    if frozen():
        # A one-file watchdog must keep its own extraction alive after the UI exits.
        environment['PYINSTALLER_RESET_ENVIRONMENT'] = '1'
        command = [sys.executable, '--guardian', str(path), identifier]
        directory = path.parent
    else:
        command = [sys.executable, '-m', 'proxyworkbench.guardian', str(path), identifier]
        directory = asset_root()
    return command, str(directory), environment
