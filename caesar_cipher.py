"""Exercise-only Caesar cipher; not secure encryption."""


def caesar_encrypt(text: str, k: int) -> str:
    shift = k % 26
    result = []
    for char in text:
        if "A" <= char <= "Z":
            char = chr((ord(char) - ord("A") + shift) % 26 + ord("A"))
        elif "a" <= char <= "z":
            char = chr((ord(char) - ord("a") + shift) % 26 + ord("a"))
        result.append(char)
    return "".join(result)


def caesar_decrypt(text: str, k: int) -> str:
    return caesar_encrypt(text, -k)
