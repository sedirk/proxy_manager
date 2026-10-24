"""Synthetic PKG fixtures: inspect bytes only, never run an executable."""
from pathlib import Path
import importlib.util
import struct
import tempfile
import unittest
import zlib

_spec = importlib.util.spec_from_file_location('flowdesk_smoke_tool', Path(__file__).resolve().parents[1] / 'tools' / 'smoke_exe.py')
_tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_tool)
IncompleteExecutableError = _tool.IncompleteExecutableError
validate_embedded_pkg = _tool.validate_embedded_pkg


MAGIC = b'MEI\014\013\012\013\016'
COOKIE = struct.Struct('!8sIIII64s')
ENTRY = struct.Struct('!IIIIBc')


def package():
    payload, toc = bytearray(), bytearray()
    for name, kind, content, compress in (
            ('python313.dll', b'b', b'fixture runtime library', True),
            ('run', b's', b'fixture entry code', True),
            ('PYZ.pyz', b'z', b'PYZ\0fixture module archive', False)):
        stored = zlib.compress(content) if compress else content
        label = name.encode() + b'\0'
        length = ((ENTRY.size + len(label) + 15) // 16) * 16
        toc.extend(ENTRY.pack(length, len(payload), len(stored), len(content), int(compress), kind))
        toc.extend(label.ljust(length - ENTRY.size, b'\0'))
        payload.extend(stored)
    body = bytes(payload + toc)
    return b'MZfixture bootloader\0' + body + COOKIE.pack(MAGIC, len(body) + COOKIE.size, len(payload), len(toc), 313, b'python313.dll')


class EmbeddedPkgTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='flowdesk-pkg-')
        self.exe = Path(self.temp.name) / 'fixture.exe'

    def tearDown(self):
        self.temp.cleanup()

    def validate(self, data):
        self.exe.write_bytes(data)
        return validate_embedded_pkg(self.exe)

    def test_complete_package_and_post_cookie_signing_data_are_accepted(self):
        self.assertEqual(self.validate(package())['entries'], 3)
        self.assertEqual(self.validate(package() + b'fixture Authenticode bytes')['python_library'], 'python313.dll')

    def test_missing_or_truncated_archive_fails_before_any_launch(self):
        data = package()
        for damaged in (b'MZunfinished bootloader', data[:-1], data[:-40], data[:40], data[:-COOKIE.size]):
            with self.subTest(length=len(damaged)), self.assertRaises(IncompleteExecutableError):
                self.validate(damaged)

    def test_cookie_and_toc_ranges_cannot_point_outside_completed_bytes(self):
        data = bytearray(package())
        cookie_at = len(data) - COOKIE.size
        # A completed-looking cookie with a larger data area than the file.
        struct.pack_into('!I', data, cookie_at + 8, len(data) + 100)
        with self.assertRaises(IncompleteExecutableError):
            self.validate(data)
        data = bytearray(package())
        values = COOKIE.unpack_from(data, len(data) - COOKIE.size)
        archive_start = len(data) - values[1]
        toc_at = archive_start + values[2]
        struct.pack_into('!I', data, toc_at + 4, values[2] + 1)
        with self.assertRaises(IncompleteExecutableError):
            self.validate(data)

    def test_truncated_payload_cannot_be_hidden_by_an_intact_cookie(self):
        data = bytearray(package())
        archive_start = len(data) - COOKIE.unpack_from(data, len(data) - COOKIE.size)[1]
        # Preserve file length and every structural range, but corrupt a
        # compressed member as an in-progress placeholder write might do.
        data[archive_start + 3] ^= 0xff
        with self.assertRaises(IncompleteExecutableError):
            self.validate(data)


if __name__ == '__main__':
    unittest.main()
