"""Unicode-aware password policy for the password exercise."""

SPECIAL_CHARS = "!@#$%^&*()_+-="


def validate_password(password: str) -> tuple[bool, str]:
    errors = []
    for passed, message in (
        (any(c.isupper() for c in password), "thiếu chữ hoa"),
        (any(c.islower() for c in password), "thiếu chữ thường"),
        (any(c.isdigit() for c in password), "thiếu chữ số"),
        (any(c in SPECIAL_CHARS for c in password), "thiếu ký tự đặc biệt"),
        (len(password) >= 8, "ngắn hơn 8 ký tự"),
    ):
        if not passed:
            errors.append(message)
    if errors:
        message = ", ".join(errors)
        return False, message[0].upper() + message[1:]
    return True, "Mật khẩu hợp lệ"
