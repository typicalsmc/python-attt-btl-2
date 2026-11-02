"""Authenticated Windows monitoring pipeline; Caesar is exercise-only obfuscation."""

import argparse
import getpass
import hashlib
import hmac
import json
import logging
import math
import secrets
import subprocess
import sys
import time
import warnings
from pathlib import Path

from caesar_cipher import caesar_decrypt, caesar_encrypt
from network_monitor import scan_connections
from password_validator import validate_password
from threat_hunter import REASONS, scan_processes

CAESAR_SHIFT = 3
PBKDF2_ITERATIONS = 600_000
PBKDF2_ALGORITHM = "sha256"


def _password_hash(password: str, salt: bytes) -> bytes:
    if not hasattr(hashlib, "pbkdf2_hmac"):
        raise ValueError("Cần Python có OpenSSL hỗ trợ PBKDF2-HMAC")
    return hashlib.pbkdf2_hmac(
        PBKDF2_ALGORITHM, password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32,
    )


def initialize(state_dir: Path, password: str) -> None:
    valid, message = validate_password(password)
    if not valid:
        raise ValueError(message)
    state_dir.mkdir(parents=True, exist_ok=True)
    credential_path = state_dir / "credentials.json"
    config_path = state_dir / "config.caesar"
    if credential_path.exists() or config_path.exists():
        raise FileExistsError("Đã có credential hoặc cấu hình; từ chối ghi đè")
    salt = secrets.token_bytes(16)
    credentials = json.dumps({
        "salt": salt.hex(), "password_hash": _password_hash(password, salt).hex(),
    })
    config = caesar_encrypt(json.dumps({
        "interval_seconds": 10, "log_file": "security_monitor.log",
    }), CAESAR_SHIFT)
    created = []
    try:
        for path, content in ((credential_path, credentials), (config_path, config)):
            with path.open("x", encoding="utf-8") as stream:
                created.append(path)
                stream.write(content)
    except BaseException:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise


def authenticate(password: str, credential_path: Path) -> bool:
    data = json.loads(credential_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) != {"salt", "password_hash"}:
        raise ValueError("Credential không hợp lệ")
    values = []
    for field, size in (("salt", 16), ("password_hash", 32)):
        value = data[field]
        if not isinstance(value, str) or len(value) != size * 2:
            raise ValueError("Credential có salt/hash không hợp lệ")
        try:
            decoded = bytes.fromhex(value)
        except ValueError:
            raise ValueError("Credential có salt/hash không hợp lệ") from None
        if len(decoded) != size:
            raise ValueError("Credential có salt/hash không hợp lệ")
        values.append(decoded)
    salt, expected = values
    return hmac.compare_digest(_password_hash(password, salt), expected)


def load_config(state_dir: Path) -> dict:
    encrypted = (state_dir / "config.caesar").read_text(encoding="utf-8")
    config = json.loads(caesar_decrypt(encrypted, CAESAR_SHIFT))
    if not isinstance(config, dict):
        raise ValueError("Cấu hình phải là JSON object")
    interval = config.get("interval_seconds")
    if type(interval) not in (int, float):
        raise ValueError("interval_seconds phải hữu hạn và lớn hơn 0")
    try:
        valid_interval = math.isfinite(interval) and interval > 0
    except OverflowError:
        valid_interval = False
    if not valid_interval:
        raise ValueError("interval_seconds phải hữu hạn và lớn hơn 0")
    log_file = config.get("log_file")
    if not isinstance(log_file, str) or not log_file.strip():
        raise ValueError("log_file phải là chuỗi không rỗng")
    log_path = Path(log_file)
    if not log_path.is_absolute():
        log_path = (state_dir / log_path).resolve()
    return {"interval_seconds": interval, "log_file": str(log_path)}


def run_scan(logger: logging.Logger) -> bool:
    network_count = process_count = "không thu thập được"
    complete = True
    try:
        connections = scan_connections()
        network_count = len(connections)
        for connection in connections:
            logger.info(
                "[NETWORK] %s:%s -> %s:%s PID %s",
                connection["local_ip"], connection["local_port"],
                connection["remote_ip"], connection["remote_port"], connection["pid"],
            )
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        # Exception text may include captured command lines or output.
        logger.error("[ERROR] Nguồn netstat thu thập thất bại (%s)", type(error).__name__)
        complete = False
    try:
        processes = scan_processes()
        process_count = len(processes)
        for process in processes:
            reason = "; ".join(
                f"{REASONS[keyword]} ({keyword})" for keyword in process["keywords"]
            )
            name = process["name"].replace("\r", "\\r").replace("\n", "\\n")
            logger.warning(
                "[ALERT] Phát hiện tiến trình nghi vấn PID %s (%s) chứa %s",
                process["pid"], name, reason,
            )
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        logger.error("[ERROR] Nguồn PowerShell thu thập thất bại (%s)", type(error).__name__)
        complete = False
    logger.info(
        "[SUMMARY] Kết nối: %s; tiến trình nghi vấn: %s",
        network_count, process_count,
    )
    if not complete:
        logger.error("[SUMMARY] Lượt quét không đầy đủ")
    return complete


def _read_password(prompt: str) -> str:
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        return getpass.getpass(prompt)


def _run(state_dir: Path, once: bool) -> int:
    if sys.platform != "win32":
        print("Thu thập trực tiếp chỉ hỗ trợ Windows (netstat -ano và PowerShell).")
        return 1
    password = _read_password("Mật khẩu Admin: ")
    valid, message = validate_password(password)
    if not valid:
        print(message)
        return 1
    if not authenticate(password, state_dir / "credentials.json"):
        print("Mật khẩu Admin không đúng")
        return 1
    del password
    config = load_config(state_dir)
    # A per-run logger prevents duplicate handlers across repeated main() calls.
    logger = logging.Logger("security_monitor", level=logging.INFO)
    logger.propagate = False
    try:
        file_handler = logging.FileHandler(config["log_file"], encoding="utf-8")
        logger.addHandler(file_handler)
        logger.addHandler(logging.StreamHandler(sys.stdout))
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        for handler in logger.handlers:
            handler.setFormatter(formatter)
        while True:
            complete = run_scan(logger)
            if once:
                return 0 if complete else 1
            time.sleep(config["interval_seconds"])
    finally:
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
            handler.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Giám sát bảo mật Windows bằng Python")
    parser.add_argument("--state-dir", type=Path, default=Path(".security_monitor"))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Thiết lập mật khẩu Admin và cấu hình")
    run_parser = commands.add_parser("run", help="Xác thực và quét Windows")
    run_parser.add_argument("--once", action="store_true", help="Chỉ quét một lượt")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            password = _read_password("Thiết lập mật khẩu Admin: ")
            confirmation = _read_password("Xác nhận mật khẩu Admin: ")
            valid, message = validate_password(password)
            if not valid:
                print(message)
                return 1
            if password != confirmation:
                print("Mật khẩu xác nhận không khớp")
                return 1
            initialize(args.state_dir, password)
            print("Đã thiết lập Admin và cấu hình.")
            return 0
        return _run(args.state_dir, args.once)
    except KeyboardInterrupt:
        print("\nĐã dừng.")
        return 0
    except EOFError:
        print("Đã hủy: kết thúc đầu vào.")
        return 1
    except getpass.GetPassWarning:
        print("Đã hủy: terminal không thể ẩn mật khẩu.")
        return 1
    except (OSError, ValueError) as error:
        print(f"Lỗi: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
