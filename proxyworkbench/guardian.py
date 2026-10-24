"""Independent rollback watchdog. Never touches a different lease or writer."""
import json
from pathlib import Path
import sys
import time
from .system_proxy import (WinInet, atomic_json, _record, _restore_locked, read_backup,
                           lease_lock, lease_expired, heartbeat_stale, _ACTIVE_PHASES)


def step(journal_path, identifier, *, adapter=None, backup_reader=read_backup, now=None, monotonic=None):
    """One atomic watchdog decision; tests inject a fake WinINet adapter."""
    path = Path(journal_path)
    with lease_lock(path):
        record = _record(path)
        if record['id'] != identifier or record['phase'] not in _ACTIVE_PHASES:
            return {'action': 'finished', 'phase': record['phase']}
        expired = record['phase'] in {'armed', 'trial'} and lease_expired(record, now, monotonic)
        stale = heartbeat_stale(path, record, now, monotonic)
        if not (expired or stale or record['phase'] == 'restore_failed'):
            return {'action': 'wait', 'phase': record['phase']}
        try:
            restored = _restore_locked(path, record, adapter or WinInet(), backup_reader,
                                        '试用到期或后端心跳失联，独立守护已尝试恢复')
            return {'action': 'finished', 'phase': restored['phase']}
        except Exception as exc:
            return {'action': 'retry', 'phase': 'restore_failed', 'error_type': type(exc).__name__}


def watch(journal_path, identifier):
    path = Path(journal_path).resolve()
    with lease_lock(path):
        first = _record(path)
        if first['id'] != identifier or first['phase'] not in _ACTIVE_PHASES:
            return
        atomic_json(path.parent / (identifier + '.ready'), {'id': identifier, 'ready': True})
    while True:
        try:
            result = step(path, identifier)
            if result['action'] == 'finished':
                return
        except Exception:
            # Never write a stale copy of the journal from an exception path.
            # Atomic journal replacement means a transient read can be retried.
            pass
        time.sleep(1)


if __name__ == '__main__':
    watch(sys.argv[1], sys.argv[2])
