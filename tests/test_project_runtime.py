import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from proxyworkbench import runtime


class ProjectRuntimeTests(unittest.TestCase):
    def test_project_executable_and_source_share_project_state(self):
        with tempfile.TemporaryDirectory(prefix='flowdesk-project-') as folder:
            root = Path(folder)
            (root / 'dist').mkdir()
            (root / 'flowdesk-project.json').write_text(json.dumps({'schema_version': 1, 'data_root': '.'}), encoding='utf-8')
            with patch.object(runtime.sys, 'frozen', True, create=True), patch.object(runtime.sys, 'executable', str(root / 'dist' / 'FlowDesk.exe')):
                self.assertEqual(runtime.data_root(), root)
                self.assertEqual(runtime.data_root(root / 'explicit'), root / 'explicit')

    def test_marker_cannot_redirect_to_arbitrary_directory(self):
        with tempfile.TemporaryDirectory(prefix='flowdesk-marker-') as folder:
            root = Path(folder)
            (root / 'flowdesk-project.json').write_text(json.dumps({'schema_version': 1, 'data_root': '..'}), encoding='utf-8')
            with patch.object(runtime.sys, 'frozen', True, create=True), patch.object(runtime.sys, 'executable', str(root / 'FlowDesk.exe')), patch.dict(runtime.os.environ, {'LOCALAPPDATA': str(root / 'appdata')}):
                self.assertEqual(runtime.data_root(), root / 'appdata' / 'FlowDesk')


if __name__ == '__main__':
    unittest.main()
