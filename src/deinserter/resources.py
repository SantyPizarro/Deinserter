from __future__ import annotations

import hashlib
import io
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Callable, ContextManager, Iterator


def _validate_chunk_size(chunk_size: int) -> None:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")


def _resolved(path: Path) -> Path:
    return path.resolve(strict=False)


def ensure_distinct_paths(source: str | Path, destination: str | Path) -> None:
    source = Path(source)
    destination = Path(destination)
    if _resolved(source) == _resolved(destination):
        raise ValueError(f"source and destination resolve to the same path: {source}")
    try:
        if source.exists() and destination.exists() and os.path.samefile(source, destination):
            raise ValueError(f"source and destination refer to the same file: {source}")
    except OSError:
        pass


@contextmanager
def atomic_binary_writer(destination: str | Path) -> Iterator[BinaryIO]:
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "wb") as handle:
            yield handle
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, destination)
    except BaseException:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


@contextmanager
def atomic_text_writer(destination: str | Path, *, encoding: str = "utf-8") -> Iterator[io.TextIOWrapper]:
    with atomic_binary_writer(destination) as binary_handle:
        text_handle = io.TextIOWrapper(binary_handle, encoding=encoding)
        try:
            yield text_handle
            text_handle.flush()
        finally:
            text_handle.detach()


class ByteSource:
    def __init__(self, path: str | Path, chunk_size: int = 8 * 1024 * 1024):
        _validate_chunk_size(chunk_size)
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

class ArtifactSource:
    """Seekable, bounded input used by streaming and container capabilities."""

    def __init__(
        self,
        *,
        size: int,
        name: str,
        opener: Callable[[], ContextManager[BinaryIO]],
        source_path: str | Path | None = None,
        source_offset: int = 0,
        chunk_size: int = 8 * 1024 * 1024,
        is_direct_file: bool = False,
    ) -> None:
        if size < 0:
            raise ValueError("artifact size must be non-negative")
        if source_offset < 0:
            raise ValueError("artifact source_offset must be non-negative")
        _validate_chunk_size(chunk_size)
        self.size = size
        self.name = name
        self.source_path = Path(source_path) if source_path is not None else None
        self.source_offset = source_offset
        self.chunk_size = chunk_size
        self.is_direct_file = is_direct_file
        self._opener = opener

    @classmethod
    def from_path(
        cls,
        path: str | Path,
        *,
        offset: int = 0,
        length: int | None = None,
        name: str | None = None,
        chunk_size: int = 8 * 1024 * 1024,
    ) -> "ArtifactSource":
        file_path = Path(path)
        file_size = file_path.stat().st_size
        if offset < 0 or offset > file_size:
            raise ValueError("artifact offset is outside the source file")
        artifact_size = file_size - offset if length is None else length
        if artifact_size < 0 or offset + artifact_size > file_size:
            raise ValueError("artifact range is outside the source file")

        @contextmanager
        def open_range() -> Iterator[BinaryIO]:
            with file_path.open("rb") as handle:
                handle.seek(offset)
                yield handle

        return cls(
            size=artifact_size,
            name=name or file_path.name,
            opener=open_range,
            source_path=file_path,
            source_offset=offset,
            chunk_size=chunk_size,
            is_direct_file=offset == 0 and artifact_size == file_size,
        )

    @contextmanager
    def open(self) -> Iterator[BinaryIO]:
        with self._opener() as handle:
            yield handle

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise ValueError("artifact reads require non-negative offset and length")
        if offset >= self.size or length == 0:
            return b""
        read_length = min(length, self.size - offset)
        with self.open() as handle:
            if offset:
                handle.seek(offset, os.SEEK_CUR)
            return handle.read(read_length)

    def read_all(self, max_bytes: int | None = None) -> bytes:
        if max_bytes is not None and self.size > max_bytes:
            raise ValueError(f"artifact exceeds materialization limit: {self.size} > {max_bytes}")
        return self.read_at(0, self.size)

    def iter_chunks(self, offset: int = 0, length: int | None = None) -> Iterator[tuple[int, bytes]]:
        if offset < 0 or offset > self.size:
            raise ValueError("artifact chunk offset is outside the source")
        remaining = self.size - offset if length is None else min(length, self.size - offset)
        if remaining < 0:
            raise ValueError("artifact chunk length must be non-negative")
        with self.open() as handle:
            if offset:
                handle.seek(offset, os.SEEK_CUR)
            cursor = offset
            while remaining:
                chunk = handle.read(min(self.chunk_size, remaining))
                if not chunk:
                    raise EOFError(f"unexpected EOF while reading artifact {self.name}")
                yield cursor, chunk
                cursor += len(chunk)
                remaining -= len(chunk)

    @contextmanager
    def materialized(self, suffix: str = "") -> Iterator[Path]:
        if (
            self.is_direct_file
            and self.source_path is not None
        ):
            yield self.source_path
            return
        file_descriptor, temporary_name = tempfile.mkstemp(prefix="deinserter-artifact-", suffix=suffix)
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(file_descriptor, "wb") as output:
                for _offset, chunk in self.iter_chunks():
                    output.write(chunk)
            yield temporary_path
        finally:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass


def copy_file_streaming(
    source: str | Path,
    destination: str | Path,
    chunk_size: int = 1024 * 1024,
    hash_output: bool = True,
) -> str:
    _validate_chunk_size(chunk_size)
    digest = hashlib.sha256() if hash_output else None
    source_path = Path(source)
    dest = Path(destination)
    ensure_distinct_paths(source_path, dest)
    with source_path.open("rb") as src, atomic_binary_writer(dest) as out:
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
    _validate_chunk_size(chunk_size)
    if offset < 0:
        raise ValueError("offset must be non-negative")
    if length < 0:
        raise ValueError("length must be non-negative")
    digest = hashlib.sha256() if hash_output else None
    source_path = Path(source)
    dest = Path(destination)
    ensure_distinct_paths(source_path, dest)
    file_size = source_path.stat().st_size
    if offset + length > file_size:
        raise EOFError(f"range {offset}:{offset + length} exceeds source size {file_size}: {source}")
    remaining = length
    with source_path.open("rb") as src, atomic_binary_writer(dest) as out:
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


def sha256_range(
    source: str | Path,
    offset: int,
    length: int,
    chunk_size: int = 1024 * 1024,
) -> str:
    _validate_chunk_size(chunk_size)
    if offset < 0 or length < 0:
        raise ValueError("hash range must be non-negative")
    source_path = Path(source)
    if offset + length > source_path.stat().st_size:
        raise EOFError(f"hash range exceeds source size: {source}")
    digest = hashlib.sha256()
    remaining = length
    with source_path.open("rb") as handle:
        handle.seek(offset)
        while remaining:
            chunk = handle.read(min(chunk_size, remaining))
            if not chunk:
                raise EOFError(f"unexpected EOF while hashing range from {source}")
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def copy_artifact_range(
    source: ArtifactSource,
    destination: str | Path,
    offset: int,
    length: int,
    *,
    hash_output: bool = True,
) -> str:
    if offset < 0 or length < 0 or offset + length > source.size:
        raise ValueError(f"artifact range is outside {source.name}")
    destination_path = Path(destination)
    if source.is_direct_file and source.source_path is not None:
        ensure_distinct_paths(source.source_path, destination_path)
    digest = hashlib.sha256() if hash_output else None
    remaining = length
    with source.open() as input_handle, atomic_binary_writer(destination_path) as output_handle:
        if offset:
            input_handle.seek(offset, os.SEEK_CUR)
        while remaining:
            chunk = input_handle.read(min(source.chunk_size, remaining))
            if not chunk:
                raise EOFError(f"unexpected EOF while copying artifact range from {source.name}")
            output_handle.write(chunk)
            if digest is not None:
                digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest() if digest is not None else ""


def sha256_artifact_range(source: ArtifactSource, offset: int, length: int) -> str:
    if offset < 0 or length < 0 or offset + length > source.size:
        raise ValueError(f"artifact hash range is outside {source.name}")
    digest = hashlib.sha256()
    remaining = length
    with source.open() as handle:
        if offset:
            handle.seek(offset, os.SEEK_CUR)
        while remaining:
            chunk = handle.read(min(source.chunk_size, remaining))
            if not chunk:
                raise EOFError(f"unexpected EOF while hashing artifact range from {source.name}")
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def write_bytes_atomic(destination: str | Path, data: bytes) -> None:
    dest = Path(destination)
    with atomic_binary_writer(dest) as handle:
        handle.write(data)


def write_text_atomic(destination: str | Path, data: str, encoding: str = "utf-8") -> None:
    write_bytes_atomic(destination, data.encode(encoding))
