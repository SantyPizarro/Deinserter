from __future__ import annotations

import hashlib
import math
from collections import Counter
from pathlib import Path


def sha256_file(path: Path, block_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(block_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def magic_hex(data: bytes, length: int = 16) -> str:
    return data[:length].hex()


def shannon_entropy(data: bytes) -> float | None:
    if not data:
        return None
    counts = Counter(data)
    size = len(data)
    entropy = -sum((count / size) * math.log2(count / size) for count in counts.values())
    return round(entropy, 4)


def strings_preview(data: bytes, min_length: int, limit: int = 20) -> list[str]:
    strings: list[str] = []
    current = bytearray()

    def flush() -> None:
        nonlocal current
        if len(current) >= min_length:
            text = current.decode("utf-8", errors="ignore").strip()
            if text:
                strings.append(text[:160])
        current = bytearray()

    for byte in data:
        if byte in (9, 10, 13) or 32 <= byte <= 126:
            current.append(byte)
        else:
            flush()
            if len(strings) >= limit:
                return strings[:limit]
    flush()
    return strings[:limit]


def compression_hints(data: bytes, entropy: float | None) -> list[str]:
    hints: list[str] = []
    if data.startswith(b"PK\x03\x04"):
        hints.append("zip")
    if data.startswith(b"\x1f\x8b"):
        hints.append("gzip")
    if len(data) >= 2 and data[:2] in {b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"}:
        hints.append("zlib")
    if entropy is not None and entropy >= 7.5 and not hints:
        hints.append("possible_encrypted_or_compressed")
    return hints


def safe_relative_path(path: Path, root: Path) -> Path:
    try:
        return path.resolve().relative_to(root.resolve())
    except ValueError:
        return Path(path.name)


def ensure_unique(path: Path) -> Path:
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    parent = path.parent
    index = 1
    while True:
        candidate = parent / f"{stem}_{index}{suffix}"
        if not candidate.exists():
            return candidate
        index += 1

