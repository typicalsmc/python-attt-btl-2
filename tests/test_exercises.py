import json
import unittest

from password_validator import validate_password
from caesar_cipher import caesar_encrypt, caesar_decrypt
from network_monitor import parse_netstat
from threat_hunter import parse_processes, find_suspicious_processes


class PasswordTests(unittest.TestCase):
    def test_policy_boundaries(self):
        self.assertFalse(validate_password("Aa1!aaa")[0])
        self.assertEqual(validate_password("Aa1!aaaa"), (True, "Mật khẩu hợp lệ"))
        self.assertEqual(validate_password("admin123"),
                         (False, "Thiếu chữ hoa, thiếu ký tự đặc biệt"))
        self.assertEqual(validate_password(""), (False,
            "Thiếu chữ hoa, thiếu chữ thường, thiếu chữ số, thiếu ký tự đặc biệt, ngắn hơn 8 ký tự"))
        self.assertFalse(validate_password("Aa1?aaaa")[0])
        self.assertTrue(validate_password("Đậ1!aaaa")[0])
        self.assertTrue(validate_password("Aa1!    ")[0])
        self.assertFalse(validate_password("Aa1     ")[0])


class CaesarTests(unittest.TestCase):
    def test_shift_and_roundtrip(self):
        self.assertEqual(caesar_encrypt("Zz", 1), "Aa")
        self.assertEqual(caesar_encrypt("Aa", -1), "Zz")
        self.assertEqual(caesar_encrypt("Az", 29), "Dc")
        self.assertEqual(caesar_encrypt("", 3), "")
        text = "Az 09! Tiếng Việt\n😀"
        for shift in (-53, 0, 1, 29):
            self.assertEqual(caesar_decrypt(caesar_encrypt(text, shift), shift), text)
        self.assertEqual(caesar_encrypt("ếệ 09!\n😀", 3), "ếệ 09!\n😀")


class NetstatTests(unittest.TestCase):
    def test_mixed_windows_output(self):
        rows = [
            "Active Connections", "Proto Local Address Foreign Address State PID",
            "TCP 192.168.1.15:52341 203.0.113.50:443 ESTABLISHED 4120",
            "TCP 192.168.1.15:10 192.168.1.20:443 ESTABLISHED 8",
            "TCP [2001:db8::1]:11 [2001:db8::50]:443 ESTABLISHED 9",
            "UDP 0.0.0.0:123 *:* 2", "TCP 0.0.0.0:80 0.0.0.0:0 LISTENING 3",
            "TCP missing columns", "TCP 1.1.1.1:1 2.2.2.2:65536 ESTABLISHED 4",
            "TCP 1.1.1.1:x 2.2.2.2:80 ESTABLISHED 4",
            "TCP bad:1 2.2.2.2:80 ESTABLISHED 4",
            "TCP 1.1.1.1:1 2.2.2.2:80 ESTABLISHED ٤",
            "TCP 1.1.1.1:1 2.2.2.2:８０ ESTABLISHED 4",
        ]
        for remote in ("127.0.0.1", "127.0.0.2", "0.0.0.0", "[::1]", "[::]",
                       "[::ffff:127.0.0.1]", "[::ffff:0.0.0.0]"):
            rows.append(f"TCP 192.168.1.15:10 {remote}:443 ESTABLISHED 10")
        self.assertEqual(parse_netstat("\n".join(rows)), [
            {"local_ip": "192.168.1.15", "local_port": "52341",
             "remote_ip": "203.0.113.50", "remote_port": "443", "pid": "4120"},
            {"local_ip": "192.168.1.15", "local_port": "10",
             "remote_ip": "192.168.1.20", "remote_port": "443", "pid": "8"},
            {"local_ip": "2001:db8::1", "local_port": "11",
             "remote_ip": "2001:db8::50", "remote_port": "443", "pid": "9"},
        ])
        self.assertEqual(parse_netstat(""), [])


class ProcessTests(unittest.TestCase):
    def test_json_shapes_and_detection(self):
        record = {"ProcessId": 3210, "Name": "powershell.exe",
                  "CommandLine": "-ENC payload IEX DownloadString bypass"}
        expected = [{"pid": "3210", "name": "powershell.exe",
                     "keywords": ["-enc", "downloadstring", "iex", "bypass"]}]
        for data in (record, [record]):
            self.assertEqual(find_suspicious_processes(parse_processes(json.dumps(data))), expected)
        for output in ("", "  ", "null", "[]"):
            self.assertEqual(parse_processes(output), [])
        for output in ("{", "12", "true", '"text"'):
            with self.assertRaises(ValueError):
                parse_processes(output)

    def test_invalid_records_and_missing_commands(self):
        valid = {"ProcessId": 0, "Name": "idle", "CommandLine": ""}
        records = [None, 1, {}, {**valid, "ProcessId": True},
                   {**valid, "ProcessId": -1}, {**valid, "ProcessId": "1"},
                   {**valid, "Name": ""}, {**valid, "CommandLine": 1},
                   {"ProcessId": 0, "Name": "idle"},
                   {**valid, "CommandLine": None}, valid]
        parsed = parse_processes(json.dumps(records))
        self.assertEqual(parsed, [valid, valid, valid])
        self.assertEqual(find_suspicious_processes(parsed), [])
        self.assertEqual(find_suspicious_processes(parse_processes(json.dumps(
            {**valid, "CommandLine": "notepad.exe document.txt"}))), [])


if __name__ == "__main__":
    unittest.main()
