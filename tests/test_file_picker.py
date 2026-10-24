import json
import subprocess
import unittest
from unittest.mock import patch

from proxyworkbench import file_picker


class FilePickerTests(unittest.TestCase):
    def test_selection_returns_only_path_without_running_selected_program(self):
        selected = r'C:\中文目录 with spaces\app.exe'
        result = subprocess.CompletedProcess([], 0, json.dumps({'cancelled': False, 'executable': selected}), '')
        with patch.object(file_picker.sys, 'platform', 'win32'), patch.object(file_picker.subprocess, 'run', return_value=result) as runner:
            self.assertEqual(file_picker.choose_executable(), {'cancelled': False, 'executable': selected})
        command = runner.call_args.args[0]
        self.assertTrue(command[0].lower().endswith('powershell.exe'))
        self.assertNotIn(selected, command)
        self.assertIn('-STA', command)

    def test_cancel_and_errors_release_picker_for_next_request(self):
        with patch.object(file_picker.sys, 'platform', 'win32'), patch.object(file_picker.subprocess, 'run') as runner:
            runner.return_value = subprocess.CompletedProcess([], 0, '{"cancelled":true}', '')
            self.assertEqual(file_picker.choose_executable(), {'cancelled': True})
            runner.side_effect = subprocess.TimeoutExpired('picker', 120)
            with self.assertRaisesRegex(ValueError, '超时'):
                file_picker.choose_executable()
            runner.side_effect = None
            runner.return_value = subprocess.CompletedProcess([], 0, 'invalid', '')
            with self.assertRaisesRegex(ValueError, '选择结果'):
                file_picker.choose_executable()
            self.assertFalse(file_picker._PICKER_LOCK.locked())

    def test_only_one_picker_can_be_open_at_once(self):
        with patch.object(file_picker.sys, 'platform', 'win32'):
            file_picker._PICKER_LOCK.acquire()
            try:
                with self.assertRaisesRegex(RuntimeError, '已有一个'):
                    file_picker.choose_executable()
            finally:
                file_picker._PICKER_LOCK.release()


if __name__ == '__main__':
    unittest.main()
