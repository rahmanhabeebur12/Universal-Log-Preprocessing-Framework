import hashlib


def digest(raw: str) -> tuple[str, int]:
    data = raw.encode("utf-8")
    return hashlib.sha256(data).hexdigest(), len(data)
