"""Lease/guardian fault tests use fake WinINet exclusively; never set networking."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from proxyworkbench import guardian, system_proxy as system

BEFORE = {'flags': 3, 'server': '127.0.0.1:10808', 'bypass': '<local>', 'pac_url': ''}


class FakeWinInet:
    def __init__(self, value=None):
        self.value = deepcopy(BEFORE if value is None else value)
        self.writes = []
        self.read_hook = None
        self.write_hook = None
        self.lock = threading.RLock()

    def read(self):
        if self.read_hook:
            self.read_hook()
        with self.lock:
            return deepcopy(self.value)

    def write(self, value):
        if self.write_hook:
            self.write_hook(value)
        with self.lock:
            self.value = deepcopy(value)
            self.writes.append(deepcopy(value))


class SystemLeaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='system-lease-fake-')
        self.root = Path(self.temp.name)
        self.adapter = FakeWinInet()
        self.objects = []
        # Cross-platform deterministic fake encryption for control-flow tests.
        # The real Windows DPAPI roundtrip is tested separately below.
        self.crypto = patch.object(system, '_dpapi', side_effect=lambda data, protect: bytes(value ^ 0xA5 for value in data))
        self.no_real_wininet = patch.object(system, 'WinInet', side_effect=AssertionError('real WinINet construction forbidden in lease tests'))
        self.no_real_guard_wininet = patch.object(guardian, 'WinInet', side_effect=AssertionError('real WinINet construction forbidden in guardian tests'))
        self.crypto.start()
        self.no_real_wininet.start()
        self.no_real_guard_wininet.start()

    def tearDown(self):
        self.adapter.read_hook = self.adapter.write_hook = None
        for lease in self.objects:
            try:
                lease.close()
            except Exception:
                lease.closed.set()
        self.no_real_guard_wininet.stop()
        self.no_real_wininet.stop()
        self.crypto.stop()
        self.temp.cleanup()

    def lease(self):
        lease = system.SystemLease(self.root, adapter=self.adapter, start_guardian=False)
        lease._start_heartbeat = lambda: None
        self.objects.append(lease)
        return lease

    def apply(self, port=49152):
        lease = self.lease()
        proposal = lease.preview('fixture-channel', port, safe_default=True)
        self.assertTrue(proposal['allowed'])
        result = lease.apply(proposal['preview_id'])
        self.assertEqual(result['phase'], 'trial')
        return lease

    def journal(self):
        return system._record(self.root / 'system-lease.json')

    def update(self, **fields):
        record = self.journal()
        record.update(fields)
        system.atomic_json(self.root / 'system-lease.json', record)
        return record

    def stale_heartbeat(self, record):
        system.atomic_json(system.heartbeat_path(self.root / 'system-lease.json', record['id']),
                           {'id': record['id'], 'wall': time.time() - 30, 'monotonic': time.monotonic() - 30})

    def test_constructor_status_preview_are_read_only(self):
        lease = self.lease()
        self.assertEqual(lease.status()['phase'], 'detached')
        proposal = lease.preview('fixture', 49152, safe_default=True)
        self.assertTrue(proposal['allowed'])
        self.assertEqual(self.adapter.writes, [])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_preview_preserves_pac_and_requires_safe_default(self):
        self.adapter.value.update(flags=13, pac_url='https://pac.example/private?token=PACSECRET')
        lease = self.lease()
        self.assertFalse(lease.preview('x', 49152, safe_default=True)['allowed'])
        self.adapter.value = deepcopy(BEFORE)
        self.assertFalse(lease.preview('x', 49152, safe_default=False)['allowed'])
        self.assertEqual(self.adapter.writes, [])

    def test_apply_backs_up_encrypted_then_restores_original(self):
        lease = self.apply()
        record = self.journal()
        backup = self.root / (record['id'] + '.dpapi')
        self.assertNotIn(BEFORE['server'].encode(), backup.read_bytes())
        self.assertEqual(system.read_backup(self.root, record['id']), BEFORE)
        self.assertEqual(self.adapter.value['server'], '127.0.0.1:49152')
        self.assertEqual(lease.restore()['phase'], 'restored')
        self.assertEqual(self.adapter.value, BEFORE)
        self.assertTrue(backup.exists())

    def test_preview_invalidated_by_external_writer_does_not_write(self):
        lease = self.lease()
        proposal = lease.preview('x', 49152, safe_default=True)
        self.adapter.value['server'] = 'third-party.example:9000'
        with self.assertRaises(RuntimeError):
            lease.apply(proposal['preview_id'])
        self.assertEqual(self.adapter.writes, [])

    def test_restore_detects_conflict_and_does_not_overwrite_other_writer(self):
        lease = self.apply()
        self.adapter.value['server'] = 'third-party.example:9000'
        writes = len(self.adapter.writes)
        self.assertEqual(lease.restore()['phase'], 'conflict')
        self.assertEqual(len(self.adapter.writes), writes)
        self.assertEqual(self.adapter.value['server'], 'third-party.example:9000')

    def test_explicit_restore_rechecks_conflict_without_overwriting_other_writer(self):
        lease = self.apply()
        self.adapter.value['server'] = 'third-party.example:9000'
        self.assertEqual(lease.restore()['phase'], 'conflict')
        writes = len(self.adapter.writes)
        self.assertEqual(lease.restore()['phase'], 'conflict')
        self.assertEqual(len(self.adapter.writes), writes)
        self.adapter.value = deepcopy(BEFORE)
        self.assertEqual(lease.restore()['phase'], 'restored')
        self.assertEqual(len(self.adapter.writes), writes)

    def test_conflict_is_not_automatically_retried_but_exact_lease_can_be_restored(self):
        lease = self.apply()
        applied = deepcopy(self.adapter.value)
        self.adapter.value['server'] = 'third-party.example:9000'
        self.assertEqual(lease.restore()['phase'], 'conflict')
        record = self.journal()
        self.adapter.value = applied
        self.stale_heartbeat(record)
        self.assertEqual(guardian.step(lease.journal_path, record['id'], adapter=self.adapter)['action'], 'finished')
        lease._heartbeat_once()
        self.assertEqual(self.adapter.value, applied)
        self.assertEqual(lease.restore()['phase'], 'restored')
        self.assertEqual(self.adapter.value, BEFORE)

    def test_restore_rechecks_after_decrypting_backup(self):
        lease = self.apply()
        def changed_during_decryption(directory, identifier):
            self.adapter.value['server'] = 'third-party.example:9001'
            return deepcopy(BEFORE)
        result = system.restore_lease(lease.journal_path, self.adapter, changed_during_decryption)
        self.assertEqual(result['phase'], 'conflict')
        self.assertEqual(self.adapter.value['server'], 'third-party.example:9001')
        self.assertEqual(len(self.adapter.writes), 1)

    def test_trial_expires_at_exact_deadline_and_backend_also_restores(self):
        lease = self.apply()
        record = self.journal()
        self.assertTrue(system.lease_expired(record, now=record['deadline'], monotonic=record['deadline_monotonic'] - 1))
        self.update(deadline=0)
        with self.assertRaises(RuntimeError):
            lease.confirm()
        lease._heartbeat_once()
        self.assertEqual(lease.status()['phase'], 'restored')
        self.assertEqual(self.adapter.value, BEFORE)

    def test_monotonic_deadline_prevents_wall_clock_rollback_extension(self):
        lease = self.apply()
        record = self.update(deadline=time.time() + 3600, deadline_monotonic=0)
        with self.assertRaises(RuntimeError):
            lease.confirm()
        result = guardian.step(lease.journal_path, record['id'], adapter=self.adapter)
        self.assertEqual(result['phase'], 'restored')
        self.assertEqual(self.adapter.value, BEFORE)

    def test_confirmation_rechecks_deadline_after_adapter_read(self):
        lease = self.apply()
        with patch.object(system, 'lease_expired', side_effect=[False, True]):
            with self.assertRaises(RuntimeError):
                lease.confirm()
        self.assertEqual(lease.status()['phase'], 'trial')

    def test_confirmed_lease_requires_fresh_heartbeat_after_trial_deadline(self):
        lease = self.apply()
        lease.confirm()
        record = self.update(deadline=0, deadline_monotonic=0)
        self.assertEqual(guardian.step(lease.journal_path, record['id'], adapter=self.adapter)['action'], 'wait')
        self.stale_heartbeat(record)
        self.assertEqual(guardian.step(lease.journal_path, record['id'], adapter=self.adapter)['phase'], 'restored')
        self.assertEqual(self.adapter.value, BEFORE)

    def test_backend_detects_guardian_crash_and_restores(self):
        lease = self.apply()
        lease.confirm()
        lease.start_guardian = True
        lease.guardian = SimpleNamespace(poll=lambda: 3)
        lease._heartbeat_once()
        self.assertEqual(lease.status()['phase'], 'restored')
        self.assertEqual(self.adapter.value, BEFORE)

    def test_confirmed_heartbeat_detects_external_writer_without_overwriting(self):
        lease = self.apply()
        lease.confirm()
        record = self.journal()
        beat_path = system.heartbeat_path(lease.journal_path, record['id'])
        before_beat = beat_path.read_bytes()
        self.adapter.value['server'] = 'third-party.example:9000'
        writes = len(self.adapter.writes)
        lease._heartbeat_once()
        self.assertEqual(lease.status()['phase'], 'conflict')
        self.assertEqual(self.adapter.value['server'], 'third-party.example:9000')
        self.assertEqual(len(self.adapter.writes), writes)
        self.assertEqual(beat_path.read_bytes(), before_beat)

    def test_trial_heartbeat_detects_original_state_already_restored_without_write(self):
        lease = self.apply()
        self.adapter.value = deepcopy(BEFORE)
        writes = len(self.adapter.writes)
        lease._heartbeat_once()
        self.assertEqual(lease.status()['phase'], 'restored')
        self.assertEqual(self.adapter.value, BEFORE)
        self.assertEqual(len(self.adapter.writes), writes)

    def test_armed_heartbeat_does_not_treat_prewrite_original_as_restored(self):
        lease = self.apply()
        self.update(phase='armed')
        self.adapter.value = deepcopy(BEFORE)
        writes = len(self.adapter.writes)
        lease._heartbeat_once()
        self.assertEqual(lease.status()['phase'], 'armed')
        self.assertEqual(len(self.adapter.writes), writes)

    def test_guardian_start_failure_does_not_change_proxy(self):
        lease = self.lease()
        lease.start_guardian = True
        proposal = lease.preview('x', 49152, safe_default=True)
        with patch.object(system.subprocess, 'Popen', side_effect=OSError('fake guardian failed')):
            with self.assertRaises(OSError):
                lease.apply(proposal['preview_id'])
        self.assertEqual(self.adapter.writes, [])
        self.assertEqual(lease.status()['phase'], 'restored')

    def test_expired_armed_record_cannot_be_overwritten_back_to_trial(self):
        lease = self.lease()
        lease.start_guardian = True
        proposal = lease.preview('x', 49152, safe_default=True)
        def fake_spawn(*args, **kwargs):
            record = self.journal()
            system.atomic_json(self.root / (record['id'] + '.ready'), {'id': record['id'], 'ready': True})
            guardian.step(lease.journal_path, record['id'], adapter=self.adapter,
                          now=record['deadline'], monotonic=record['deadline_monotonic'])
            return SimpleNamespace(poll=lambda: None)
        with patch.object(system.subprocess, 'Popen', side_effect=fake_spawn):
            with self.assertRaises(RuntimeError):
                lease.apply(proposal['preview_id'])
        self.assertEqual(self.adapter.writes, [])
        self.assertEqual(self.adapter.value, BEFORE)
        self.assertEqual(lease.status()['phase'], 'restored')

    def test_stale_owner_and_guardian_cannot_change_a_new_lease(self):
        old = self.apply()
        old_id = self.journal()['id']
        old.restore()
        current = self.apply(port=49153)
        current_id = self.journal()['id']
        before = deepcopy(self.adapter.value)
        beat_path = system.heartbeat_path(current.journal_path, current_id)
        beat = beat_path.read_bytes()
        old._heartbeat_once()
        old.close()
        result = guardian.step(current.journal_path, old_id, adapter=self.adapter, now=time.time() + 1000, monotonic=time.monotonic() + 1000)
        self.assertEqual(result['action'], 'finished')
        self.assertEqual(self.journal()['id'], current_id)
        self.assertEqual(self.journal()['phase'], 'trial')
        self.assertEqual(self.adapter.value, before)
        self.assertEqual(beat_path.read_bytes(), beat)
        with self.assertRaises(RuntimeError):
            current.confirm(identifier=old_id)

    def test_restore_failure_is_retryable_and_keeps_encrypted_backup(self):
        lease = self.apply()
        record = self.update(deadline=0)
        count = 0
        def fail_once(value):
            nonlocal count
            count += 1
            if count == 1:
                raise OSError('fake temporary OS failure')
        self.adapter.write_hook = fail_once
        first = guardian.step(lease.journal_path, record['id'], adapter=self.adapter)
        self.assertEqual(first['action'], 'retry')
        self.assertEqual(self.journal()['phase'], 'restore_failed')
        self.assertTrue((self.root / (record['id'] + '.dpapi')).exists())
        second = guardian.step(lease.journal_path, record['id'], adapter=self.adapter)
        self.assertEqual(second['phase'], 'restored')
        self.assertEqual(self.adapter.value, BEFORE)

    def test_guardian_restore_and_confirm_are_serialized(self):
        lease = self.apply()
        record = self.journal()
        self.stale_heartbeat(record)
        entered, release, errors = threading.Event(), threading.Event(), []
        def hook():
            if threading.current_thread().name == 'fake-guardian':
                entered.set()
                if not release.wait(2):
                    raise RuntimeError('test barrier timeout')
        self.adapter.read_hook = hook
        def auto_restore():
            guardian.step(lease.journal_path, record['id'], adapter=self.adapter)
        def confirm():
            try:
                lease.confirm()
            except RuntimeError as exc:
                errors.append(type(exc).__name__)
        first = threading.Thread(target=auto_restore, name='fake-guardian')
        second = threading.Thread(target=confirm, name='fake-confirm')
        first.start()
        self.assertTrue(entered.wait(2))
        second.start()
        release.set()
        first.join(3)
        second.join(3)
        self.assertFalse(first.is_alive() or second.is_alive())
        self.assertTrue(errors)
        self.assertEqual(self.journal()['phase'], 'restored')
        self.assertEqual(self.adapter.value, BEFORE)

    def test_confirm_then_manual_restore_cannot_leave_confirmed_stale_record(self):
        lease = self.apply()
        entered, release = threading.Event(), threading.Event()
        def hook():
            if threading.current_thread().name == 'fake-confirm':
                entered.set()
                if not release.wait(2):
                    raise RuntimeError('test barrier timeout')
        self.adapter.read_hook = hook
        first = threading.Thread(target=lease.confirm, name='fake-confirm')
        second = threading.Thread(target=lambda: system.restore_lease(lease.journal_path, self.adapter), name='fake-manual-restore')
        first.start()
        self.assertTrue(entered.wait(2))
        second.start()
        release.set()
        first.join(3)
        second.join(3)
        self.assertFalse(first.is_alive() or second.is_alive())
        self.assertEqual(self.journal()['phase'], 'restored')
        self.assertEqual(self.adapter.value, BEFORE)

    def test_cross_process_lock_blocks_independent_watchdog_writer(self):
        journal = self.root / 'system-lease.json'
        project = str(Path(__file__).resolve().parents[1])
        source = ("import sys\nsys.path.insert(0," + repr(project) + ")\n"
                  "from proxyworkbench.system_proxy import lease_lock\n"
                  "try:\n with lease_lock(sys.argv[1],timeout=.15): print('acquired')\n"
                  "except RuntimeError: print('blocked')\n")
        with system.lease_lock(journal):
            result = subprocess.run([sys.executable, '-c', source, str(journal)], capture_output=True, text=True, timeout=3,
                                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'blocked')

    def test_backup_identifier_rejects_directory_escape(self):
        with self.assertRaises(ValueError):
            system.read_backup(self.root, '../not-a-backup')


class RealReadOnlyWindowsTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'Windows DPAPI only')
    def test_dpapi_roundtrip_only_encrypts_private_fixture(self):
        example = {'flags': 1, 'server': 'fixture-user:fixture-password@127.0.0.1:1', 'bypass': '', 'pac_url': ''}
        encrypted = system.protect_snapshot(example)
        self.assertNotIn(b'fixture-password', encrypted)
        restored = json.loads(system._dpapi(encrypted, False))
        self.assertEqual(restored, example)

    @unittest.skipUnless(os.name == 'nt', 'Windows WinINet read only')
    def test_real_wininet_read_has_expected_shape_without_writing(self):
        adapter = system.WinInet()
        with patch.object(adapter, 'write', side_effect=AssertionError('real write forbidden')):
            observed = adapter.read()
        self.assertEqual(set(observed), {'flags', 'server', 'bypass', 'pac_url'})
        self.assertIsInstance(observed['flags'], int)


if __name__ == '__main__':
    unittest.main(verbosity=2)
