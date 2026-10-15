"""Exercise CLI pipe decoding under a simulated Windows ANSI locale."""

import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location(
    'cli_e2e', Path(__file__).resolve().parents[1] / 'cli_e2e.py')
cli_e2e = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = cli_e2e
spec.loader.exec_module(cli_e2e)


class CliEncodingTests(unittest.TestCase):
    def setUp(self):
        # Use the real subprocess transport without creating locker/database fixtures.
        self.runner = cli_e2e.CliE2E.__new__(cli_e2e.CliE2E)
        self.runner.cli = Path(sys.executable)
        self.runner.env = os.environ.copy()

    def test_unicode_stdout_and_stderr_survive_an_ansi_parent_locale(self):
        message = 'Avalonia — MIT; café; Δοκιμή; 測試'
        script = (
            f'import sys; data = {message!r}.encode("utf-8"); '
            'sys.stdout.buffer.write(data); sys.stderr.buffer.write(data)'
        )
        with mock.patch('subprocess._text_encoding', return_value='cp1252'):
            result = self.runner.run_cli('-c', script)
        self.assertEqual(message, result.stdout)
        self.assertEqual(message, result.stderr)

    def test_failure_diagnostics_preserve_unicode_under_an_ansi_parent_locale(self):
        message = 'Missing directory — café/測試'
        script = (
            f'import sys; sys.stderr.buffer.write({message!r}.encode("utf-8")); '
            'sys.exit(7)'
        )
        with mock.patch('subprocess._text_encoding', return_value='cp1252'):
            with self.assertRaises(AssertionError) as failure:
                self.runner.run_cli('-c', script)
        self.assertIn('exit code 7', str(failure.exception))
        self.assertIn(message, str(failure.exception).split('\nstderr:\n', 1)[1])


if __name__ == '__main__':
    unittest.main()
