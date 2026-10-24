import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import run
from proxyworkbench import runtime
from proxyworkbench.server import ControlServer


class RuntimeTests(unittest.TestCase):
    def test_source_keeps_existing_project_state(self):
        with patch.object(sys, 'frozen', False, create=True):
            self.assertEqual(runtime.data_root(), runtime.asset_root())

    def test_frozen_state_is_outside_temporary_assets(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {'LOCALAPPDATA': folder}), \
                patch.object(sys, 'frozen', True, create=True):
            self.assertEqual(runtime.data_root(), Path(folder) / 'FlowDesk')
            self.assertNotEqual(runtime.data_root(), runtime.asset_root())

    def test_data_override_is_explicit_and_absolute(self):
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(runtime.data_root(folder), Path(folder).resolve())

    def test_frozen_guardian_is_independent_of_main_extraction(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(sys, 'frozen', True, create=True):
            journal = Path(folder) / 'system-lease.json'
            command, cwd, env = runtime.guardian_launch(journal, 'a' * 32)
            self.assertEqual(command, [sys.executable, '--guardian', str(journal.resolve()), 'a' * 32])
            self.assertEqual(cwd, str(journal.parent.resolve()))
            self.assertEqual(env['PYINSTALLER_RESET_ENVIRONMENT'], '1')
            self.assertIsNot(env, os.environ)

    def test_source_guardian_uses_package_module(self):
        with patch.object(sys, 'frozen', False, create=True):
            command, cwd, _ = runtime.guardian_launch('lease.json', 'a' * 32)
            self.assertEqual(command[:3], [sys.executable, '-m', 'proxyworkbench.guardian'])
            self.assertEqual(cwd, str(runtime.asset_root()))

    def test_guardian_dispatch_never_starts_ui_or_creates_data(self):
        with patch('proxyworkbench.guardian.watch') as watch, patch('run.ControlServer') as server, \
                patch('run.data_root') as root:
            run.main(['--guardian', 'lease.json', 'a' * 32])
            watch.assert_called_once_with('lease.json', 'a' * 32)
            server.assert_not_called()
            root.assert_not_called()

    def test_server_assets_and_persistent_state_are_separate(self):
        with tempfile.TemporaryDirectory() as state, tempfile.TemporaryDirectory() as assets:
            server = ControlServer(('127.0.0.1', 0), state, discover=False, assets=assets)
            try:
                self.assertEqual(server.root, Path(assets))
                self.assertEqual(server.service.store.root, Path(state) / '.local')
                self.assertFalse((Path(assets) / '.local').exists())
            finally:
                server.service.close()
                server.server_close()


if __name__ == '__main__':
    unittest.main()
