"""Substring heuristics for Windows process command lines, not malware verdicts."""

import json
import subprocess

SUSPICIOUS = ["-enc", "encodedcommand", "downloadstring", "iex", "bypass"]
REASONS = {
    "-enc": "tham số mã hóa Base64",
    "encodedcommand": "tham số mã hóa Base64",
    "downloadstring": "tải nội dung từ mạng",
    "iex": "thực thi biểu thức động",
    "bypass": "bỏ qua chính sách thực thi",
}
POWERSHELL_COMMAND = (
    "$ErrorActionPreference = 'Stop'; "
    "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); "
    "$processes = @(Get-CimInstance Win32_Process | "
    "Select-Object ProcessId, Name, CommandLine); "
    "ConvertTo-Json -InputObject $processes -Compress -Depth 3"
)


def parse_processes(output: str) -> list[dict]:
    if not output.strip():
        return []
    data = json.loads(output)
    if data is None:
        return []
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise ValueError("Dữ liệu PowerShell phải là object, array hoặc null")
    processes = []
    for record in data:
        if not isinstance(record, dict):
            continue
        pid, name = record.get("ProcessId"), record.get("Name")
        command = record.get("CommandLine")
        if type(pid) is not int or pid < 0 or not isinstance(name, str) or not name:
            continue
        if command is None:
            command = ""
        if not isinstance(command, str):
            continue
        processes.append({"ProcessId": pid, "Name": name, "CommandLine": command})
    return processes


def find_suspicious_processes(processes: list[dict]) -> list[dict]:
    results = []
    for process in processes:
        command = process["CommandLine"].lower()
        keywords = [keyword for keyword in SUSPICIOUS if keyword in command]
        if keywords:
            results.append({
                "pid": str(process["ProcessId"]),
                "name": process["Name"],
                "keywords": keywords,
            })
    return results


def scan_processes() -> list[dict]:
    result = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
         "-Command", POWERSHELL_COMMAND],
        capture_output=True, text=True, encoding="utf-8-sig", errors="replace",
        check=True, timeout=15,
    )
    return find_suspicious_processes(parse_processes(result.stdout))
