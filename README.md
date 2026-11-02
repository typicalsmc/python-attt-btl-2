# Python Security Monitor

Bốn bài tập Python độc lập và pipeline giám sát Windows có xác thực Admin. Python 3.10+ có OpenSSL; chỉ dùng thư viện chuẩn, không cần cài dependency.

## Chạy chương trình

Thu thập trực tiếp cần Windows, `netstat.exe`, Windows PowerShell 5.1 (`powershell.exe`) và terminal tương tác. Không tự nâng quyền. Linux chạy được các hàm thuần, `init` và bộ kiểm thử, nhưng không chạy collector qua CLI.

```powershell
python security_monitor.py --state-dir .security_monitor init
python security_monitor.py --state-dir .security_monitor run --once
python security_monitor.py --state-dir .security_monitor run
```

`--state-dir` phải đứng trước `init`/`run`; mặc định là `.security_monitor` trong thư mục làm việc. Không có subcommand: hiển thị usage, không chạy ngầm. `init` hỏi mật khẩu và xác nhận bằng prompt ẩn; không nhận mật khẩu qua argv/env. Mật khẩu phải có ít nhất 8 ký tự, chữ hoa, chữ thường, chữ số và ít nhất một ký tự trong `!@#$%^&*()_+-=`. Không strip khoảng trắng; phân loại chữ/số theo Unicode.

`init` tạo đúng hai file, từ chối ghi đè nếu đã có một trong hai:

- `credentials.json`: salt ngẫu nhiên 16 byte và hash PBKDF2-HMAC-SHA256 32 byte, 600000 vòng. Không lưu mật khẩu thô.
- `config.caesar`: JSON được Caesar dịch 3, mặc định `{"interval_seconds": 10, "log_file": "security_monitor.log"}`.

`run` kiểm tra Windows trước prompt, kiểm tra chính sách và xác thực trước khi giải cấu hình hoặc mở log. Không retry đăng nhập. Cấu hình hoặc credential thiếu/hỏng: dừng, không tự reset hoặc dùng mặc định.

Quét ngay khi đăng nhập thành công, sau mỗi lượt nghỉ `interval_seconds`. Console và file UTF-8 append cùng nhận timestamp, level, sự kiện `[NETWORK]`, `[ALERT]` và `[SUMMARY]`. Hai nguồn được thử độc lập: một nguồn lỗi không ngăn nguồn còn lại; summary ghi `không thu thập được` thay vì số 0. Lượt định kỳ vẫn tiếp tục sau lỗi nguồn.

- `--once`: exit 0 nếu cả hai nguồn thành công, exit 1 nếu thiếu nguồn.
- Lỗi thiết lập/xác thực/cấu hình, EOF hoặc terminal không ẩn được mật khẩu: exit 1.
- Ctrl+C: dừng sạch, exit 0.

## Các module và API

| Module | API | Hành vi |
| --- | --- | --- |
| `password_validator.py` | `validate_password(password)` | `(bool, message)`; gom toàn bộ lỗi theo thứ tự hoa, thường, số, đặc biệt, độ dài. `admin123` dài đủ 8 nhưng thiếu hoa và đặc biệt. |
| `caesar_cipher.py` | `caesar_encrypt(text, k)`, `caesar_decrypt(text, k)` | Chỉ dịch A–Z/a–z; k âm/lớn được modulo 26; giữ nguyên mọi ký tự ngoài ASCII alphabet. |
| `network_monitor.py` | `parse_netstat(output)`, `scan_connections()` | Parser Windows `netstat -ano`; chỉ TCP ESTABLISHED hợp lệ, trả IP/cổng nguồn và đích cùng PID, tất cả dạng chuỗi. |
| `threat_hunter.py` | `parse_processes(output)`, `find_suspicious_processes(processes)`, `scan_processes()` | JSON từ `Get-CimInstance Win32_Process`; parser chuẩn hóa record để đưa vào detector; kết quả chỉ có `pid`, `name`, `keywords`, không chứa CommandLine. |
| `security_monitor.py` | `initialize`, `authenticate`, `load_config`, `run_scan`, `main` | Thiết lập, xác thực, cấu hình, tổng hợp sự kiện và CLI. |

Netstat bỏ dòng lỗi, UDP, trạng thái khác và IP đích loopback/unspecified, kể cả IPv4-mapped IPv6. **Không lọc IP private**: kết nối tới `192.168.1.20` vẫn được ghi. Log kết nối không phải kết luận kết nối độc hại. Collector có timeout 15 giây; lỗi chạy lệnh không bị chuyển thành danh sách rỗng.

Heuristic dò substring không phân biệt hoa/thường: `-enc`, `encodedcommand`, `downloadstring`, `iex`, `bypass`. Một tiến trình khớp nhiều từ chỉ tạo một cảnh báo có tất cả lý do. JSON không hợp lệ gây lỗi nguồn; record không hợp lệ bị bỏ. CommandLine thiếu/null không cảnh báo. Tên tiến trình được escape CR/LF trước khi ghi log.

## Cấu hình và giới hạn bảo mật

Caesar chỉ là bài tập, **không bảo vệ bí mật hoặc tính toàn vẹn**. Không đưa mật khẩu/token vào cấu hình. Để thay cấu hình bằng API:

```python
import json
from pathlib import Path
from caesar_cipher import caesar_encrypt
from security_monitor import CAESAR_SHIFT

state = Path(".security_monitor")
config = {"interval_seconds": 10, "log_file": "security_monitor.log"}
(state / "config.caesar").write_text(
    caesar_encrypt(json.dumps(config), CAESAR_SHIFT), encoding="utf-8"
)
```

`interval_seconds` phải là int/float hữu hạn > 0, không nhận bool. `log_file` là chuỗi không rỗng; đường dẫn tương đối tính từ state directory, tuyệt đối dùng nguyên. Thư mục cha của log phải tồn tại. Log không mở được thì dừng trước khi thu thập.

Admin ở đây là cổng kiểm soát ứng dụng, không phải tài khoản Windows và không thay thế ACL. Người có quyền sửa mã/credential có thể vượt cổng này. Bảo vệ state và log bằng quyền truy cập hệ điều hành; không đưa chúng vào version control. Python thiếu PBKDF2/OpenSSL sẽ báo lỗi, không fallback hash yếu.

Substring heuristic có false positive (ví dụ `iex` chỉ nằm trong comment) và false negative; quyền truy cập có thể khiến CommandLine không có dữ liệu. Không coi kết quả là bằng chứng malware hay chứng nhận hệ thống sạch. Không lưu toàn bộ dòng lệnh, không giải mã/thực thi payload, không kill tiến trình.

## Kiểm chứng đã thực hiện

Trên Linux:

```sh
python3 -m unittest discover -s tests -v
python3 security_monitor.py --help
python3 security_monitor.py run --once
```

- 17 kiểm thử đạt: ranh giới bài tập, credential/config hỏng, salt, xác thực, init không ghi đè/rollback khi tranh chấp, lỗi từng nguồn, phục hồi vòng lặp, log và prompt an toàn.
- Smoke API thực cho bốn bài tập và credential/config.
- CLI `init` thật qua PTY: echo bị tắt ở cả hai prompt, tạo đúng hai file, lần hai exit 1 và giữ nguyên nội dung; API xác thực đúng/sai và giải cấu hình interval=10.
- CLI `run --once` trên Linux: exit 1 với thông báo chỉ hỗ trợ Windows, không hỏi mật khẩu, không tạo state.
- Smoke pipeline mô phỏng platform Windows và đầu ra subprocess: parser/detector/auth/config/logger chạy thật; exit 0, console và file có cùng network PID 4120 và alert PID 3210, lý do Base64; không ghi mật khẩu hoặc payload.

**Chưa xác minh thu thập trực tiếp trên Windows.** Fixture không phải bằng chứng đã chạy netstat/PowerShell thật. Chưa xác minh thời gian chờ thực 10 giây hoặc quyền truy cập Win32_Process trên Windows.

### Checklist smoke trên Windows

Dùng state thử riêng, không dùng credential thật:

```powershell
python security_monitor.py --state-dir .smoke-state init
python security_monitor.py --state-dir .smoke-state run --once
python security_monitor.py --state-dir .smoke-state run
```

Thử mật khẩu sai (bị chặn), đúng (có summary); để định kỳ ít nhất hai lượt với khoảng nghỉ 10 giây rồi Ctrl+C, xác nhận không traceback và console/file cùng sự kiện.

Để tạo tín hiệu vô hại, chạy ở terminal thứ hai rồi quét trong 60 giây:

```powershell
powershell.exe -NoProfile -Command "Start-Sleep -Seconds 60 # iex"
```

Kỳ vọng alert có `iex`; từ khóa chỉ nằm trong comment, không thực thi biểu thức động.

Nếu có Internet, mở kết nối TCP để đối chiếu endpoint/PID:

```powershell
python -c "import os,socket,time; s=socket.create_connection(('example.com',443),timeout=10); print(os.getpid(),s.getsockname(),s.getpeername(),flush=True); time.sleep(60); s.close()"
```

Trong 60 giây, chạy `run --once`, đối chiếu `[NETWORK]` với PID và endpoint vừa in. Nếu Internet bị chặn, dùng kết nối ESTABLISHED tới host không loopback sẵn có từ `netstat -ano`. Không có kết nối phù hợp thì ghi rõ nhánh network chưa xác minh, không thay bằng Linux netstat.
