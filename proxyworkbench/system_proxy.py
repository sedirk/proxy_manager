"""Explicit WinINet attachment with a separate-process, conflict-aware lease.

Nothing is written on import, construction, preview, or status. WinHTTP, proxy
environment variables, VPN/TUN, routes and running applications are untouched.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes as wt
import contextlib
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import threading
import time

_ACTIVE_PHASES = {'armed', 'trial', 'confirmed', 'restore_failed'}
_THREAD_LOCKS = {}
_THREAD_LOCKS_LOCK = threading.Lock()


def _identifier(value):
    if not isinstance(value, str) or len(value) != 32 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('无效的备份标识')
    return value


@contextlib.contextmanager
def lease_lock(journal_path, timeout=5.0):
    """Serialize every decision/write across backend instances and watchdogs."""
    path = Path(journal_path).absolute()
    key = os.path.normcase(str(path))
    with _THREAD_LOCKS_LOCK:
        local = _THREAD_LOCKS.setdefault(key, threading.Lock())
    if not local.acquire(timeout=timeout):
        raise RuntimeError('系统接入操作正在进行，请稍后重试')
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.with_name('system-lease.lock').open('a+b') as stream:
            if stream.tell() == 0:
                stream.write(b'\0')
                stream.flush()
            stream.seek(0)
            deadline = time.monotonic() + timeout
            while True:
                try:
                    if os.name == 'nt':
                        import msvcrt
                        msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('独立守护正在处理系统接入，请稍后重试')
                    time.sleep(.02)
            try:
                yield
            finally:
                stream.seek(0)
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    finally:
        local.release()


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.' + secrets.token_hex(8) + '.tmp')
    try:
        with temporary.open('x', encoding='utf-8') as f:
            json.dump(value, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class WinInet:
    """Read/write the LAN per-connection options, not registry implementation."""
    def __init__(self):
        if os.name != 'nt':
            raise RuntimeError('系统接入仅支持 Windows；本地中继仍可使用')
        class Value(ctypes.Union):
            _fields_ = [('number', wt.DWORD), ('string', ctypes.c_void_p), ('time', wt.FILETIME)]
        class Option(ctypes.Structure):
            _fields_ = [('kind', wt.DWORD), ('value', Value)]
        class Options(ctypes.Structure):
            _fields_ = [('size', wt.DWORD), ('connection', wt.LPWSTR), ('count', wt.DWORD),
                        ('error', wt.DWORD), ('options', ctypes.POINTER(Option))]
        self.Option, self.Options = Option, Options
        self.api = ctypes.WinDLL('wininet', use_last_error=True)
        self.api.InternetQueryOptionW.argtypes = [wt.HANDLE, wt.DWORD, ctypes.c_void_p, ctypes.POINTER(wt.DWORD)]
        self.api.InternetQueryOptionW.restype = wt.BOOL
        self.api.InternetSetOptionW.argtypes = [wt.HANDLE, wt.DWORD, ctypes.c_void_p, wt.DWORD]
        self.api.InternetSetOptionW.restype = wt.BOOL
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.kernel.GlobalFree.argtypes = [ctypes.c_void_p]
        self.kernel.GlobalFree.restype = ctypes.c_void_p

    def read(self):
        options = (self.Option * 4)()
        for i in range(4):
            options[i].kind = i + 1
        block = self.Options(ctypes.sizeof(self.Options), None, 4, 0, options)
        size = wt.DWORD(ctypes.sizeof(block))
        if not self.api.InternetQueryOptionW(None, 75, ctypes.byref(block), ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        result = {'flags': int(options[0].value.number)}
        for index, name in enumerate(('server', 'bypass', 'pac_url'), 1):
            pointer = options[index].value.string
            try:
                result[name] = ctypes.wstring_at(pointer) if pointer else ''
            finally:
                if pointer:
                    self.kernel.GlobalFree(pointer)
        return result

    def write(self, value):
        options = (self.Option * 4)()
        options[0].kind, options[0].value.number = 1, int(value['flags'])
        buffers = []
        for index, name in enumerate(('server', 'bypass', 'pac_url'), 1):
            buf = ctypes.create_unicode_buffer(value.get(name, ''))
            buffers.append(buf)
            options[index].kind = index + 1
            options[index].value.string = ctypes.cast(buf, ctypes.c_void_p).value
        block = self.Options(ctypes.sizeof(self.Options), None, 4, 0, options)
        if not self.api.InternetSetOptionW(None, 75, ctypes.byref(block), ctypes.sizeof(block)):
            raise ctypes.WinError(ctypes.get_last_error())
        for option in (39, 37):
            if not self.api.InternetSetOptionW(None, option, None, 0):
                raise ctypes.WinError(ctypes.get_last_error())


def _dpapi(data, protect):
    if os.name != 'nt':
        raise RuntimeError('系统设置备份需要 Windows DPAPI')
    class Blob(ctypes.Structure):
        _fields_ = [('size', wt.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]
    source_buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    source, target = Blob(len(data), source_buffer), Blob()
    api = ctypes.WinDLL('crypt32', use_last_error=True)
    method = api.CryptProtectData if protect else api.CryptUnprotectData
    # CRYPTPROTECT_UI_FORBIDDEN: no prompts in a watchdog; user scope only.
    method.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
                       ctypes.c_void_p, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(Blob)]
    method.restype = wt.BOOL
    if not method(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(target.data, target.size)
    finally:
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree(target.data)


def protect_snapshot(value):
    return _dpapi(json.dumps(value, ensure_ascii=False).encode('utf-8'), True)


def read_backup(directory, identifier):
    _identifier(identifier)
    path = Path(directory) / (identifier + '.dpapi')
    if path.stat().st_size > 1024 * 1024:
        raise ValueError('代理配置备份异常过大')
    raw = path.read_bytes()
    return json.loads(_dpapi(raw, False).decode('utf-8'))


def _record(journal_path):
    record = json.loads(Path(journal_path).read_text(encoding='utf-8'))
    _identifier(record.get('id'))
    return record


def heartbeat_path(journal_path, identifier):
    return Path(journal_path).parent / (_identifier(identifier) + '.heartbeat.json')


def write_heartbeat(journal_path, identifier):
    atomic_json(heartbeat_path(journal_path, identifier), {'id': identifier, 'wall': time.time(), 'monotonic': time.monotonic()})


def lease_expired(record, now=None, monotonic=None):
    now = time.time() if now is None else now
    monotonic = time.monotonic() if monotonic is None else monotonic
    return (now >= record['deadline'] or (record.get('deadline_monotonic') is not None and monotonic >= record['deadline_monotonic']))


def heartbeat_stale(journal_path, record, now=None, monotonic=None):
    now = time.time() if now is None else now
    monotonic = time.monotonic() if monotonic is None else monotonic
    try:
        beat = json.loads(heartbeat_path(journal_path, record['id']).read_text(encoding='utf-8'))
        return (beat.get('id') != record['id'] or now - float(beat['wall']) > 12
                or monotonic - float(beat['monotonic']) > 12
                or float(beat['monotonic']) > monotonic + 1)
    except (OSError, ValueError, TypeError, KeyError):
        return True


def _restore_locked(journal_path, record, adapter, backup_reader, reason=None):
    """Caller holds lease_lock. External WinINet writers do not share this lock.

    The equality guard detects observed conflicts; Windows has no atomic WinINet
    compare-and-swap covering unrelated third-party configuration writers.
    """
    # An explicit retry may resolve a conflict after the other writer has
    # restored either the original state or this lease's exact applied state.
    # Watchdogs filter conflict out before calling this function.
    if record['phase'] not in _ACTIVE_PHASES | {'conflict'}:
        return record
    try:
        actual = adapter.read()
        if fingerprint(actual) == record['before_hash']:
            record.update(phase='restored', reason='系统已经是原状态')
        elif fingerprint(actual) != record['desired_hash']:
            record.update(phase='conflict', reason='其他程序已修改系统代理，保留原备份，不覆盖未知变化')
        else:
            previous = backup_reader(Path(journal_path).parent, record['id'])
            if fingerprint(previous) != record['before_hash']:
                raise RuntimeError('原配置备份与日志哈希不匹配')
            # Recheck after decrypting, immediately before the OS write.
            if fingerprint(adapter.read()) != record['desired_hash']:
                record.update(phase='conflict', reason='恢复前检测到其他程序变更，未覆盖')
            else:
                adapter.write(previous)
                if fingerprint(adapter.read()) != record['before_hash']:
                    raise RuntimeError('恢复后核对失败；保留日志与加密备份')
                record.update(phase='restored', reason=reason or '已恢复接入前的系统代理')
        record['finished_at'] = time.time()
        atomic_json(journal_path, record)
    except Exception as exc:
        record.update(phase='restore_failed', reason='恢复尚未完成：' + type(exc).__name__)
        atomic_json(journal_path, record)
        raise
    return record


def restore_lease(journal_path, adapter=None, backup_reader=read_backup, *, identifier=None, reason=None):
    """Restore this lease only; detected third-party state is never overwritten."""
    path = Path(journal_path)
    with lease_lock(path):
        record = _record(path)
        if identifier is not None and record['id'] != _identifier(identifier):
            return record
        return _restore_locked(path, record, adapter or WinInet(), backup_reader, reason)


class SystemLease:
    def __init__(self, directory, adapter=None, start_guardian=True):
        self.directory = Path(directory)
        self.adapter = adapter
        self.journal_path = self.directory / 'system-lease.json'
        self.start_guardian = start_guardian
        self.guardian = None
        self.lock = threading.RLock()
        self.previews = {}
        self.closed = threading.Event()
        self.thread = None
        self.active_id = None

    def _adapter(self):
        if self.adapter is None:
            self.adapter = WinInet()
        return self.adapter

    def status(self):
        if not self.journal_path.exists():
            return {'phase': 'detached', 'message': '未接管系统代理', 'supported': os.name == 'nt'}
        record = json.loads(self.journal_path.read_text(encoding='utf-8'))
        return {key: record.get(key) for key in ('id', 'phase', 'channel_id', 'deadline', 'reason', 'started_at', 'finished_at')}

    def preview(self, channel_id, port, *, safe_default=False):
        current = self._adapter().read()
        problems = []
        if current['flags'] & 12:
            problems.append('当前有 PAC/自动检测；此版本保留它，不自动替换为静态系统代理。可用应用专属入口。')
        if not safe_default:
            problems.append('该通道默认出口未保留当前系统代理入口；为保护现有连接，不能设为系统代理。')
        if self.status()['phase'] in ('armed', 'trial', 'confirmed', 'restore_failed', 'conflict'):
            problems.append('已有系统接入或待处理的回退记录。')
        if not isinstance(port, int) or not 1 <= port <= 65535:
            problems.append('请先启动通道，再应用系统接入。')
        desired = {'flags': 3, 'server': f'127.0.0.1:{port}',
                   'bypass': current.get('bypass', '') or '<local>;localhost;127.*;[::1]', 'pac_url': current.get('pac_url', '')}
        identifier = secrets.token_hex(16)
        with self.lock:
            self.previews[identifier] = {'current': current, 'desired': desired, 'channel_id': channel_id,
                                         'expires': time.time() + 120, 'allowed': not problems}
        return {'preview_id': identifier, 'allowed': not problems, 'issues': problems,
                'scope': '当前用户 WinINet 系统代理', 'before': {'flags': current['flags'], 'server': _public_server(current['server'])},
                'after': {'flags': desired['flags'], 'server': desired['server']},
                'notice': '试用 60 秒内需确认；未确认、后端退出或心跳丢失时独立守护进程尝试恢复。环境变量/WinHTTP/TUN/Codex 进程不变。'}

    def apply(self, preview_id):
        with self.lock:
            proposal = self.previews.pop(preview_id, None)
            if not proposal or not proposal['allowed'] or proposal['expires'] < time.time():
                raise ValueError('请重新查看可应用的变更预览')
            identifier = secrets.token_hex(16)
            with lease_lock(self.journal_path):
                if self.journal_path.exists() and _record(self.journal_path)['phase'] in _ACTIVE_PHASES | {'conflict'}:
                    raise RuntimeError('已有系统接入或冲突记录，尚未应用新配置')
                if fingerprint(self._adapter().read()) != fingerprint(proposal['current']):
                    raise RuntimeError('系统代理自预览后已改变，请重新检测')
                encrypted = protect_snapshot(proposal['current'])
                backup_path = self.directory / (identifier + '.dpapi')
                with backup_path.open('xb') as f:
                    f.write(encrypted)
                    f.flush()
                    os.fsync(f.fileno())
                if fingerprint(read_backup(self.directory, identifier)) != fingerprint(proposal['current']):
                    raise RuntimeError('加密备份回读失败，尚未应用配置')
                now = time.time()
                record = {'id': identifier, 'phase': 'armed', 'channel_id': proposal['channel_id'],
                          'before_hash': fingerprint(proposal['current']), 'desired_hash': fingerprint(proposal['desired']),
                          'started_at': now, 'deadline': now + 60, 'deadline_monotonic': time.monotonic() + 60,
                          'reason': '等待试用确认', 'conflict_guard': 'observed_compare_not_os_atomic'}
                atomic_json(self.journal_path, record)
                write_heartbeat(self.journal_path, identifier)
                self.active_id = identifier
            self.closed.clear()
            try:
                if self.start_guardian:
                    ready = self.directory / (identifier + '.ready')
                    self.guardian = subprocess.Popen([sys.executable, '-m', 'proxyworkbench.guardian', str(self.journal_path), identifier],
                        cwd=str(Path(__file__).resolve().parent.parent), stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
                    limit = time.monotonic() + 5
                    while not ready.exists() and self.guardian.poll() is None and time.monotonic() < limit:
                        time.sleep(.05)
                    if not ready.exists() or self.guardian.poll() is not None:
                        raise RuntimeError('回退守护未就绪，未修改系统代理')
                # Guardian readiness is waited for without holding its file lock.
                with lease_lock(self.journal_path):
                    record = _record(self.journal_path)
                    if record['id'] != identifier or record['phase'] != 'armed' or lease_expired(record):
                        raise RuntimeError('接入租约已结束，尚未写入系统代理')
                    if fingerprint(self._adapter().read()) != record['before_hash']:
                        raise RuntimeError('守护启动期间系统代理改变，尚未写入')
                    if self.start_guardian and self.guardian.poll() is not None:
                        raise RuntimeError('守护已退出，尚未写入系统代理')
                    self._adapter().write(proposal['desired'])
                    if fingerprint(self._adapter().read()) != record['desired_hash']:
                        raise RuntimeError('配置写入后核对失败')
                    record['phase'] = 'trial'
                    atomic_json(self.journal_path, record)
                    write_heartbeat(self.journal_path, identifier)
                self._start_heartbeat()
            except Exception:
                restore_lease(self.journal_path, self._adapter(), identifier=identifier)
                raise
            return self.status()

    def _heartbeat_once(self):
        with self.lock:
            if not self.active_id or not self.journal_path.exists():
                return
            with lease_lock(self.journal_path):
                record = _record(self.journal_path)
                if record['id'] != self.active_id or record['phase'] not in _ACTIVE_PHASES:
                    return
                expired = record['phase'] in {'armed', 'trial'} and lease_expired(record)
                guard_dead = self.start_guardian and self.guardian is not None and self.guardian.poll() is not None
                if expired or guard_dead or record['phase'] == 'restore_failed':
                    _restore_locked(self.journal_path, record, self._adapter(), read_backup,
                                    '试用到期或独立守护已退出，已尝试恢复')
                elif record['phase'] in {'trial', 'confirmed'} and fingerprint(self._adapter().read()) != record['desired_hash']:
                    _restore_locked(self.journal_path, record, self._adapter(), read_backup,
                                    '系统代理已离开本次接入状态')
                else:
                    write_heartbeat(self.journal_path, self.active_id)

    def _start_heartbeat(self):
        if self.thread and self.thread.is_alive():
            return
        def run():
            while not self.closed.wait(2):
                try:
                    self._heartbeat_once()
                except Exception:
                    # No fresh heartbeat -> independent guardian restores.
                    pass
        self.thread = threading.Thread(target=run, daemon=True, name='system-lease-heartbeat')
        self.thread.start()

    def confirm(self, identifier=None):
        with self.lock:
            with lease_lock(self.journal_path):
                record = _record(self.journal_path)
                if identifier is not None and record['id'] != identifier:
                    raise RuntimeError('确认按钮属于旧会话，未确认当前接入')
                if record['phase'] != 'trial' or lease_expired(record):
                    raise RuntimeError('试用已结束，请先检查系统状态')
                if fingerprint(self._adapter().read()) != record['desired_hash']:
                    raise RuntimeError('系统代理已被其他程序改变，不能确认')
                if lease_expired(record):
                    raise RuntimeError('确认读取期间试用到期，未延长试用期限')
                record.update(phase='confirmed', reason='已确认；中继退出或守护检测到失联后恢复')
                atomic_json(self.journal_path, record)
            return self.status()

    def restore(self, identifier=None):
        with self.lock:
            if not self.journal_path.exists():
                return self.status()
            restore_lease(self.journal_path, self._adapter(), identifier=identifier)
            return self.status()

    def close(self):
        try:
            if self.active_id:
                self.restore(identifier=self.active_id)
        finally:
            self.closed.set()
            if self.thread and self.thread is not threading.current_thread():
                self.thread.join(timeout=2)


def _public_server(value):
    return '<包含凭据的原代理地址，已隐藏>' if '@' in value else value
