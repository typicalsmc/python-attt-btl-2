import getpass
import io
import json
import subprocess
import tempfile
import unittest
import warnings
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import security_monitor as monitor
from caesar_cipher import caesar_encrypt

PASSWORD = "P@ssw0rd2026"
NETWORK = "TCP 192.168.1.15:52341 203.0.113.50:443 ESTABLISHED 4120"
PROCESSES = json.dumps({"ProcessId": 3210, "Name": "powershell.exe\r\nFAKE",
                        "CommandLine": "powershell.exe -enc JABzA..."})


def completed(output):
    return subprocess.CompletedProcess([], 0, stdout=output)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        monitor.initialize(self.state, PASSWORD)

    def invoke(self, results, password=PASSWORD, once=True, sleep=None):
        console = io.StringIO()
        args = ["--state-dir", str(self.state), "run"]
        if once:
            args.append("--once")
        with patch.object(monitor.sys, "platform", "win32"), \
             patch.object(monitor.getpass, "getpass", return_value=password), \
             patch("subprocess.run", side_effect=results) as collector, \
             patch.object(monitor.time, "sleep", side_effect=sleep), \
             redirect_stdout(console):
            code = monitor.main(args)
        return code, console.getvalue(), collector

    def write_config(self, config):
        (self.state / "config.caesar").write_text(
            caesar_encrypt(json.dumps(config), monitor.CAESAR_SHIFT), encoding="utf-8")

    def test_authentication_salt_and_no_overwrite(self):
        credentials = self.state / "credentials.json"
        self.assertTrue(monitor.authenticate(PASSWORD, credentials))
        self.assertFalse(monitor.authenticate("WrongPass1!", credentials))
        before = {path.name: path.read_bytes() for path in self.state.iterdir()}
        with self.assertRaises(FileExistsError):
            monitor.initialize(self.state, "AnotherPass1!")
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.state.iterdir()})
        with tempfile.TemporaryDirectory() as second:
            monitor.initialize(Path(second), PASSWORD)
            self.assertNotEqual(json.loads(credentials.read_text())["salt"],
                                json.loads((Path(second) / "credentials.json").read_text())["salt"])
        self.assertNotIn(PASSWORD, credentials.read_text())

    def test_partial_initialization_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            original_open = Path.open

            def race_open(path, mode="r", *args, **kwargs):
                if path == state / "config.caesar" and mode == "x":
                    with original_open(path, "w") as stream:
                        stream.write("concurrent content")
                return original_open(path, mode, *args, **kwargs)

            with patch.object(Path, "open", race_open), self.assertRaises(FileExistsError):
                monitor.initialize(state, PASSWORD)
            self.assertFalse((state / "credentials.json").exists())
            self.assertEqual((state / "config.caesar").read_text(), "concurrent content")

    def test_invalid_credentials_never_reset(self):
        credential = self.state / "credentials.json"
        for contents in ("{", "null", json.dumps({"salt": "00" * 16, "password_hash": "00"}),
                         json.dumps({"salt": "zz" * 16, "password_hash": "00" * 32})):
            credential.write_text(contents)
            with self.assertRaises(ValueError):
                monitor.authenticate(PASSWORD, credential)
            self.assertEqual(credential.read_text(), contents)
        credential.unlink()
        with self.assertRaises(FileNotFoundError):
            monitor.authenticate(PASSWORD, credential)
        self.assertFalse(credential.exists())

    def test_configuration_validation_and_paths(self):
        config = monitor.load_config(self.state)
        self.assertEqual(config["interval_seconds"], 10)
        self.assertEqual(config["log_file"], str(self.state / "security_monitor.log"))
        for interval in (0, -1, float("nan"), float("inf"), True, "10", None):
            self.write_config({"interval_seconds": interval, "log_file": "x.log"})
            with self.assertRaises(ValueError):
                monitor.load_config(self.state)
        for log_file in ("", "  ", None, 2):
            self.write_config({"interval_seconds": 1, "log_file": log_file})
            with self.assertRaises(ValueError):
                monitor.load_config(self.state)
        absolute = str(self.state / "absolute.log")
        self.write_config({"interval_seconds": 0.5, "log_file": absolute})
        self.assertEqual(monitor.load_config(self.state)["log_file"], absolute)
        (self.state / "config.caesar").write_text("broken")
        with self.assertRaises(ValueError):
            monitor.load_config(self.state)

    def test_wrong_password_cannot_open_configuration_or_log(self):
        # Removing config proves authentication must reject before trying to read it.
        (self.state / "config.caesar").unlink()
        code, output, collector = self.invoke([], password="WrongPass1!")
        self.assertEqual(code, 1)
        self.assertIn("Mật khẩu Admin không đúng", output)
        collector.assert_not_called()
        self.assertFalse((self.state / "security_monitor.log").exists())

    def test_bad_configuration_and_unopenable_log_block_collectors(self):
        (self.state / "config.caesar").write_text("broken")
        code, _, collector = self.invoke([])
        self.assertEqual(code, 1)
        collector.assert_not_called()
        self.write_config({"interval_seconds": 10, "log_file": "missing/monitor.log"})
        code, _, collector = self.invoke([])
        self.assertEqual(code, 1)
        collector.assert_not_called()
        self.assertFalse((self.state / "missing").exists())

    def test_each_source_failure_preserves_other_source(self):
        cases = [([OSError("secret output"), completed(PROCESSES)], "netstat", "[ALERT]"),
                 ([completed(NETWORK), completed("{secret output")], "PowerShell", "[NETWORK]"),
                 ([subprocess.TimeoutExpired("secret output", 15), completed(PROCESSES)],
                  "netstat", "[ALERT]")]
        for results, source, surviving in cases:
            with self.subTest(source=source):
                code, console, _ = self.invoke(results)
                self.assertEqual(code, 1)
                self.assertIn(source, console)
                self.assertIn(surviving, console)
                self.assertIn("không thu thập được", console)
                self.assertIn("Lượt quét không đầy đủ", console)
                self.assertNotIn("secret output", console)
                self.assertNotIn(PASSWORD, console)
                self.assertNotIn("JABzA", console)
                self.assertNotIn("\nFAKE", console)

    def test_success_logs_same_events_and_closes_handlers(self):
        for _ in range(2):
            code, console, _ = self.invoke([completed(NETWORK), completed(PROCESSES)])
            self.assertEqual(code, 0)
            self.assertEqual(console.count("[NETWORK]"), 1)
            self.assertEqual(console.count("[ALERT]"), 1)
            self.assertIn("\\r\\nFAKE", console)
            self.assertIn("Base64 (-enc)", console)
        log = self.state / "security_monitor.log"
        contents = log.read_text(encoding="utf-8")
        self.assertEqual(contents.count("[NETWORK]"), 2)
        self.assertEqual(contents.count("[ALERT]"), 2)
        self.assertTrue(contents.endswith(console))
        self.assertNotIn(PASSWORD, contents)
        self.assertNotIn("JABzA", contents)
        log.unlink()  # Also exercises closed file handles on Windows.

    def test_loop_recovers_and_interrupts_cleanly(self):
        results = [OSError(), completed("[]"), completed(NETWORK), completed(PROCESSES)]
        code, console, collector = self.invoke(results, once=False, sleep=[None, KeyboardInterrupt])
        self.assertEqual(code, 0)
        self.assertEqual(collector.call_count, 4)
        self.assertEqual(console.count("[NETWORK]"), 1)
        self.assertEqual(console.count("[ALERT]"), 1)
        self.assertIn("Lượt quét không đầy đủ", console)
        self.assertIn("Đã dừng", console)
        self.assertNotIn("Traceback", console)

    def test_non_windows_gates_before_prompt(self):
        with patch.object(monitor.sys, "platform", "linux"), \
             patch.object(monitor.getpass, "getpass") as prompt, redirect_stdout(io.StringIO()):
            self.assertEqual(monitor.main(["run", "--once"]), 1)
            prompt.assert_not_called()

    def test_prompt_cancellation_and_echo_warning(self):
        def echo_warning(*args):
            warnings.warn("echo", getpass.GetPassWarning)
            self.fail("Password prompt continued with echo enabled")

        for failure in (EOFError, echo_warning):
            with patch.object(monitor.getpass, "getpass", side_effect=failure), \
                 redirect_stdout(io.StringIO()):
                self.assertEqual(monitor.main(["init"]), 1)

    def test_invalid_initial_passwords_create_no_files(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "new-state"
            for passwords in (("admin123", "admin123"), (PASSWORD, "Mismatch1!")):
                with patch.object(monitor.getpass, "getpass", side_effect=passwords), \
                     redirect_stdout(io.StringIO()):
                    self.assertEqual(monitor.main(["--state-dir", str(state), "init"]), 1)
                self.assertFalse(state.exists())


if __name__ == "__main__":
    unittest.main()
