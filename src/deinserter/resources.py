from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterator


class ByteSource:
    def __init__(self, path: str | Path, chunk_size: int = 8 * 1024 * 1024):
        self.path = Path(path)
        self.chunk_size = chunk_size
        self.size = self.path.stat().st_size

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0:
            raise ValueError("offset must be non-negative")
        if length < 0:
            raise ValueError("length must be non-negative")
        with self.path.open("rb") as handle:
            handle.seek(offset)
            return handle.read(length)

    def iter_chunks(self, offset: int = 0, length: int | None = None) -> Iterator[tuple[int, bytes]]:
        if offset < 0:
            raise ValueError("offset must be non-negative")
        remaining = self.size - offset if length is None else length
        with self.path.open("rb") as handle:
            handle.seek(offset)
            cursor = offset
            while remaining > 0:
                chunk = handle.read(min(self.chunk_size, remaining))
                if not chunk:
                    break
                yield cursor, chunk
                cursor += len(chunk)
                remaining -= len(chunk)


def copy_file_streaming(
    source: str | Path,
    destination: str | Path,
    chunk_size: int = 1024 * 1024,
    hash_output: bool = True,
) -> str:
    digest = hashlib.sha256() if hash_output else None
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with Path(source).open("rb") as src, dest.open("wb") as out:
        while True:
            chunk = src.read(chunk_size)
            if not chunk:
                break
            out.write(chunk)
            if digest is not None:
                digest.update(chunk)
    return digest.hexdigest() if digest is not None else ""


def copy_range_streaming(
    source: str | Path,
    destination: str | Path,
    offset: int,
    length: int,
    chunk_size: int = 1024 * 1024,
    hash_output: bool = True,
) -> str:
    digest = hashlib.sha256() if hash_output else None
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)
    remaining = length
    with Path(source).open("rb") as src, dest.open("wb") as out:
        src.seek(offset)
        while remaining:
            chunk = src.read(min(chunk_size, remaining))
            if not chunk:
                raise EOFError(f"unexpected EOF while copying range from {source}")
            out.write(chunk)
            if digest is not None:
                digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest() if digest is not None else ""
