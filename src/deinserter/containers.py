from __future__ import annotations

import hashlib
import struct
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import BinaryIO, Iterable, Iterator, Protocol

from .classification import classify_asset
from .gpak import parse_gpak_index
from .resources import ArtifactSource, atomic_binary_writer, copy_range_streaming, ensure_distinct_paths
from .utils import ensure_unique


UNREAL_PAK_FOOTER_MAGIC = 0x5A6F12E1
UNREAL_PAK_FOOTER_MAGIC_BYTES = struct.pack("<I", UNREAL_PAK_FOOTER_MAGIC)
IOSTORE_TOC_MAGIC = b"-==--==--==--==-"


@dataclass(slots=True)
class ContainerEntry:
    name: str
    size: int
    offset: int | None
    type: str
    category: str
    decompile_value: str
    role: str
    source_container: str
    original_name: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "size": self.size,
            "offset": self.offset,
            "type": self.type,
            "category": self.category,
            "decompile_value": self.decompile_value,
            "role": self.role,
            "source_container": self.source_container,
            "original_name": self.original_name or self.name,
        }


@dataclass(slots=True)
class VpkEntry(ContainerEntry):
    preload_offset: int | None = None
    preload_size: int = 0
    archive_offset: int | None = None
    archive_size: int = 0
    archive_path: str = ""

    def to_dict(self) -> dict[str, object]:
        item = ContainerEntry.to_dict(self)
        item.update(
            {
                "preload_offset": self.preload_offset,
                "preload_size": self.preload_size,
                "archive_offset": self.archive_offset,
                "archive_size": self.archive_size,
                "archive_path": self.archive_path,
            }
        )
        return item


@dataclass(slots=True)
class ContainerInfo:
    path: str
    type: str
    entry_count: int
    payload_bytes: int
    data_offset: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "type": self.type,
            "entry_count": self.entry_count,
            "payload_bytes": self.payload_bytes,
            "data_offset": self.data_offset,
        }


@dataclass(slots=True)
class OpenContainer:
    info: ContainerInfo
    entries: Iterable[ContainerEntry]

    def iter_entries(self) -> Iterator[ContainerEntry]:
        return iter(self.entries)


class ContainerHandler(Protocol):
    type_name: str

    def sniff(self, path: Path) -> bool:
        ...

    def open(self, path: Path) -> OpenContainer:
        ...

    def inspect(self, path: Path) -> ContainerInfo:
        ...

    def iter_entries(self, path: Path) -> Iterator[ContainerEntry]:
        ...

    def extract_entry(
        self,
        path: Path,
        entry: ContainerEntry,
        output_dir: Path,
        overwrite: bool,
        chunk_size: int,
        hash_output: bool,
    ) -> tuple[Path, str]:
        ...


def _entry_type(name: str) -> str:
    suffix = Path(name).suffix.lower()
    return suffix.lstrip(".") if suffix else "unknown"


def _safe_archive_name(name: str) -> str:
    normalized = name.replace("\\", "/")
    posix_path = PurePosixPath(normalized)
    windows_path = PureWindowsPath(name)
    if (
        not normalized
        or normalized.startswith("/")
        or normalized.startswith("//")
        or posix_path.is_absolute()
        or windows_path.is_absolute()
        or bool(windows_path.drive)
    ):
        raise ValueError(f"unsafe absolute archive path: {name}")
    raw_parts = posix_path.parts
    if any(
        part in {"..", "/", "\\", "//"}
        or part.endswith(":")
        or PureWindowsPath(part).is_reserved()
        for part in raw_parts
    ):
        raise ValueError(f"unsafe archive path: {name}")
    parts = [part for part in raw_parts if part not in {"", "."}]
    return "/".join(parts) if parts else "unnamed"


def _safe_mount_prefix(name: str) -> str:
    """Normalize archive metadata mount points without trusting their roots."""
    normalized = name.replace("\\", "/")
    parts = [
        part
        for part in PurePosixPath(normalized).parts
        if part not in {"", ".", "..", "/", "\\", "//"} and not part.endswith(":")
    ]
    return "/".join(parts)


def _safe_output_path(output_dir: Path, name: str, overwrite: bool) -> Path:
    root = output_dir.resolve(strict=False)
    relative = Path(*Path(_safe_archive_name(name)).parts)
    if relative.is_absolute():
        raise ValueError(f"unsafe rooted archive path: {name}")
    destination = root / relative
    try:
        destination.resolve(strict=False).relative_to(root)
    except ValueError as exc:
        raise ValueError(f"archive output escapes destination root: {name}") from exc
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        destination.resolve(strict=False).relative_to(root)
    except ValueError as exc:
        raise ValueError(f"archive output traverses outside destination root: {name}") from exc
    if destination.exists() and not overwrite:
        destination = ensure_unique(destination)
    return destination


def _container_entry(container_path: Path, name: str, size: int, offset: int | None) -> ContainerEntry:
    original_name = name
    safe_name = _safe_archive_name(name)
    detected_type = _entry_type(safe_name)
    classification = classify_asset(safe_name, detected_type)
    return ContainerEntry(
        name=safe_name,
        size=size,
        offset=offset,
        type=detected_type,
        category=classification["category"],
        decompile_value=classification["decompile_value"],
        role=classification["role"],
        source_container=str(container_path),
        original_name=original_name,
    )


class GpakContainerHandler:
    type_name = "gpak"

    def sniff(self, path: Path) -> bool:
        return path.suffix.lower() == ".gpak"

    def open(self, path: Path) -> OpenContainer:
        entries, data_offset = parse_gpak_index(path)
        info = ContainerInfo(
            path=str(path),
            type=self.type_name,
            entry_count=len(entries),
            payload_bytes=sum(entry.size for entry in entries),
            data_offset=data_offset,
        )
        container_entries = [_container_entry(path, entry.name, entry.size, entry.offset) for entry in entries]
        return OpenContainer(info=info, entries=container_entries)

    def inspect(self, path: Path) -> ContainerInfo:
        return self.open(path).info

    def iter_entries(self, path: Path) -> Iterator[ContainerEntry]:
        return self.open(path).iter_entries()

    def extract_entry(
        self,
        path: Path,
        entry: ContainerEntry,
        output_dir: Path,
        overwrite: bool,
        chunk_size: int,
        hash_output: bool,
    ) -> tuple[Path, str]:
        if entry.offset is None:
            raise ValueError(f"GPAK entry has no offset: {entry.name}")
        destination = _safe_output_path(output_dir, entry.name, overwrite)
        digest = copy_range_streaming(path, destination, entry.offset, entry.size, chunk_size, hash_output)
        return destination, digest


class ZipContainerHandler:
    type_name = "zip"

    def sniff(self, path: Path) -> bool:
        try:
            if path.suffix.lower() == ".zip":
                return zipfile.is_zipfile(path)
            with path.open("rb") as handle:
                magic = handle.read(4)
            return magic.startswith(b"PK") and zipfile.is_zipfile(path)
        except OSError:
            return False

    def open(self, path: Path) -> OpenContainer:
        with zipfile.ZipFile(path) as archive:
            infos = [info for info in archive.infolist() if not info.is_dir()]
        info = ContainerInfo(
            path=str(path),
            type=self.type_name,
            entry_count=len(infos),
            payload_bytes=sum(info.file_size for info in infos),
            data_offset=None,
        )
        entries = [_container_entry(path, info.filename, info.file_size, info.header_offset) for info in infos]
        return OpenContainer(info=info, entries=entries)

    def inspect(self, path: Path) -> ContainerInfo:
        return self.open(path).info

    def iter_entries(self, path: Path) -> Iterator[ContainerEntry]:
        return self.open(path).iter_entries()

    def extract_entry(
        self,
        path: Path,
        entry: ContainerEntry,
        output_dir: Path,
        overwrite: bool,
        chunk_size: int,
        hash_output: bool,
    ) -> tuple[Path, str]:
        digest = hashlib.sha256() if hash_output else None
        destination = _safe_output_path(output_dir, entry.name, overwrite)
        archive_name = entry.original_name or entry.name
        ensure_distinct_paths(path, destination)
        with zipfile.ZipFile(path) as archive, archive.open(archive_name) as src, atomic_binary_writer(destination) as out:
            while True:
                chunk = src.read(chunk_size)
                if not chunk:
                    break
                out.write(chunk)
                if digest is not None:
                    digest.update(chunk)
        return destination, digest.hexdigest() if digest is not None else ""

    def source_for_entry(self, path: Path, entry: ContainerEntry, chunk_size: int) -> ArtifactSource:
        archive_name = entry.original_name or entry.name

        @contextmanager
        def open_entry() -> Iterator[BinaryIO]:
            with zipfile.ZipFile(path) as archive:
                with archive.open(archive_name) as handle:
                    yield handle

        return ArtifactSource(
            size=entry.size,
            name=entry.name,
            opener=open_entry,
            source_path=path,
            source_offset=entry.offset or 0,
            chunk_size=chunk_size,
        )


class PakContainerHandler:
    type_name = "pak"

    def sniff(self, path: Path) -> bool:
        try:
            with path.open("rb") as handle:
                return handle.read(4) == b"PACK"
        except OSError:
            return False

    def open(self, path: Path) -> OpenContainer:
        with path.open("rb") as handle:
            header = handle.read(12)
            if len(header) != 12 or not header.startswith(b"PACK"):
                raise ValueError("not a Quake PACK archive")
            directory_offset, directory_size = struct.unpack_from("<II", header, 4)
            if directory_size % 64:
                raise ValueError("invalid PACK directory size")
            handle.seek(directory_offset)
            directory = handle.read(directory_size)
        entries: list[ContainerEntry] = []
        for index in range(directory_size // 64):
            cursor = index * 64
            name = directory[cursor : cursor + 56].split(b"\0", 1)[0].decode("utf-8", errors="replace")
            offset, size = struct.unpack_from("<II", directory, cursor + 56)
            entries.append(_container_entry(path, name, size, offset))
        info = ContainerInfo(
            path=str(path),
            type=self.type_name,
            entry_count=len(entries),
            payload_bytes=sum(entry.size for entry in entries),
            data_offset=None,
        )
        return OpenContainer(info=info, entries=entries)

    def inspect(self, path: Path) -> ContainerInfo:
        return self.open(path).info

    def iter_entries(self, path: Path) -> Iterator[ContainerEntry]:
        return self.open(path).iter_entries()

    def extract_entry(
        self,
        path: Path,
        entry: ContainerEntry,
        output_dir: Path,
        overwrite: bool,
        chunk_size: int,
        hash_output: bool,
    ) -> tuple[Path, str]:
        if entry.offset is None:
            raise ValueError(f"PAK entry has no offset: {entry.name}")
        destination = _safe_output_path(output_dir, entry.name, overwrite)
        digest = copy_range_streaming(path, destination, entry.offset, entry.size, chunk_size, hash_output)
        return destination, digest


class VpkContainerHandler:
    type_name = "vpk"
    magic = 0x55AA1234

    def sniff(self, path: Path) -> bool:
        try:
            with path.open("rb") as handle:
                header = handle.read(4)
            return len(header) == 4 and struct.unpack("<I", header)[0] == self.magic
        except (OSError, struct.error):
            return False

    def _archive_path(self, path: Path, archive_index: int) -> Path:
        if archive_index == 0x7FFF:
            return path
        stem = path.stem
        base = stem[:-4] if stem.endswith("_dir") else stem
        return path.with_name(f"{base}_{archive_index:03d}{path.suffix}")

    def _read_c_string(self, data: bytes, cursor: int) -> tuple[str, int]:
        end = data.find(b"\0", cursor)
        if end == -1:
            raise ValueError("unterminated VPK directory string")
        return data[cursor:end].decode("utf-8", errors="replace"), end + 1

    def open(self, path: Path) -> OpenContainer:
        data = path.read_bytes()
        if len(data) < 12 or struct.unpack_from("<I", data, 0)[0] != self.magic:
            raise ValueError("not a VPK archive")
        version = struct.unpack_from("<I", data, 4)[0]
        tree_size = struct.unpack_from("<I", data, 8)[0]
        header_size = 12 if version == 1 else 28 if version == 2 else 0
        if header_size == 0 or header_size + tree_size > len(data):
            raise ValueError("unsupported or invalid VPK header")
        data_offset = header_size + tree_size
        cursor = header_size
        entries: list[ContainerEntry] = []
        while cursor < data_offset:
            extension, cursor = self._read_c_string(data, cursor)
            if not extension:
                break
            while cursor < data_offset:
                directory, cursor = self._read_c_string(data, cursor)
                if not directory:
                    break
                while cursor < data_offset:
                    filename, cursor = self._read_c_string(data, cursor)
                    if not filename:
                        break
                    if cursor + 18 > len(data):
                        raise ValueError("truncated VPK entry")
                    _crc, preload_bytes, archive_index, entry_offset, entry_length, terminator = struct.unpack_from(
                        "<IHHIIH", data, cursor
                    )
                    cursor += 18
                    if terminator != 0xFFFF:
                        raise ValueError("invalid VPK entry terminator")
                    preload_offset = cursor
                    cursor += preload_bytes
                    name = f"{filename}.{extension}" if extension != " " else filename
                    if directory not in {"", " "}:
                        name = f"{directory}/{name}"
                    archive_path = self._archive_path(path, archive_index)
                    archive_offset = data_offset + entry_offset if archive_index == 0x7FFF else entry_offset
                    source_offset: int | None = preload_offset if preload_bytes else archive_offset
                    source_container = str(path if preload_bytes and entry_length == 0 else archive_path)
                    size = preload_bytes + entry_length
                    detected_type = _entry_type(name)
                    classification = classify_asset(name, detected_type)
                    entries.append(
                        VpkEntry(
                            name=name,
                            size=size,
                            offset=source_offset,
                            type=detected_type,
                            category=classification["category"],
                            decompile_value=classification["decompile_value"],
                            role=classification["role"],
                            source_container=source_container,
                            preload_offset=preload_offset if preload_bytes else None,
                            preload_size=preload_bytes,
                            archive_offset=archive_offset if entry_length else None,
                            archive_size=entry_length,
                            archive_path=str(archive_path),
                        )
                    )
        info = ContainerInfo(
            path=str(path),
            type=self.type_name,
            entry_count=len(entries),
            payload_bytes=sum(entry.size for entry in entries),
            data_offset=data_offset,
        )
        return OpenContainer(info=info, entries=entries)

    def inspect(self, path: Path) -> ContainerInfo:
        return self.open(path).info

    def iter_entries(self, path: Path) -> Iterator[ContainerEntry]:
        return self.open(path).iter_entries()

    def extract_entry(
        self,
        path: Path,
        entry: ContainerEntry,
        output_dir: Path,
        overwrite: bool,
        chunk_size: int,
        hash_output: bool,
    ) -> tuple[Path, str]:
        destination = _safe_output_path(output_dir, entry.name, overwrite)
        if not isinstance(entry, VpkEntry):
            if entry.offset is None:
                raise ValueError(f"VPK entry has no offset: {entry.name}")
            source = Path(entry.source_container)
            digest = copy_range_streaming(source, destination, entry.offset, entry.size, chunk_size, hash_output)
            return destination, digest

        digest = hashlib.sha256() if hash_output else None
        ensure_distinct_paths(path, destination)
        if entry.archive_path:
            ensure_distinct_paths(entry.archive_path, destination)
        with atomic_binary_writer(destination) as out:
            if entry.preload_size:
                if entry.preload_offset is None:
                    raise ValueError(f"VPK preload has no offset: {entry.name}")
                with path.open("rb") as src:
                    src.seek(entry.preload_offset)
                    remaining = entry.preload_size
                    while remaining:
                        chunk = src.read(min(chunk_size, remaining))
                        if not chunk:
                            raise EOFError(entry.name)
                        out.write(chunk)
                        if digest is not None:
                            digest.update(chunk)
                        remaining -= len(chunk)
            if entry.archive_size:
                if entry.archive_offset is None:
                    raise ValueError(f"VPK archive payload has no offset: {entry.name}")
                archive = Path(entry.archive_path)
                if not archive.exists():
                    raise FileNotFoundError(archive)
                with archive.open("rb") as src:
                    src.seek(entry.archive_offset)
                    remaining = entry.archive_size
                    while remaining:
                        chunk = src.read(min(chunk_size, remaining))
                        if not chunk:
                            raise EOFError(entry.name)
                        out.write(chunk)
                        if digest is not None:
                            digest.update(chunk)
                        remaining -= len(chunk)
        return destination, digest.hexdigest() if digest is not None else ""


class RpfContainerHandler:
    type_name = "rpf"
    supported_magics = {b"RPF0", b"RPF2", b"RPF3", b"RPF4"}

    def sniff(self, path: Path) -> bool:
        try:
            with path.open("rb") as handle:
                header = handle.read(16)
            if len(header) < 16 or header[:4] not in self.supported_magics:
                return False
            entry_count, directory_offset, directory_size = struct.unpack_from(">III", header, 4)
            return 0 < entry_count <= 1_000_000 and directory_size >= entry_count * 20 and directory_offset + directory_size <= path.stat().st_size
        except (OSError, struct.error):
            return False

    def open(self, path: Path) -> OpenContainer:
        size = path.stat().st_size
        with path.open("rb") as handle:
            header = handle.read(16)
            if len(header) < 16 or header[:4] not in self.supported_magics:
                raise ValueError("unsupported or encrypted RPF index")
            entry_count, directory_offset, directory_size = struct.unpack_from(">III", header, 4)
            if entry_count <= 0 or directory_offset + directory_size > size:
                raise ValueError("invalid RPF directory range")
            handle.seek(directory_offset)
            directory = handle.read(directory_size)
        entries: list[ContainerEntry] = []
        cursor = 0
        for _ in range(entry_count):
            if cursor + 20 > len(directory):
                raise ValueError("truncated RPF directory")
            name_length = struct.unpack_from(">H", directory, cursor)[0]
            cursor += 2
            if name_length <= 0 or cursor + name_length + 16 > len(directory):
                raise ValueError("invalid RPF entry name")
            name = directory[cursor : cursor + name_length].decode("utf-8", errors="replace")
            cursor += name_length
            offset, entry_size = struct.unpack_from(">QQ", directory, cursor)
            cursor += 16
            if offset + entry_size > size:
                raise ValueError(f"RPF entry range exceeds archive: {name}")
            entries.append(_container_entry(path, name, int(entry_size), int(offset)))
        info = ContainerInfo(
            path=str(path),
            type=self.type_name,
            entry_count=len(entries),
            payload_bytes=sum(entry.size for entry in entries),
            data_offset=None,
        )
        return OpenContainer(info=info, entries=entries)

    def inspect(self, path: Path) -> ContainerInfo:
        return self.open(path).info

    def iter_entries(self, path: Path) -> Iterator[ContainerEntry]:
        return self.open(path).iter_entries()

    def extract_entry(
        self,
        path: Path,
        entry: ContainerEntry,
        output_dir: Path,
        overwrite: bool,
        chunk_size: int,
        hash_output: bool,
    ) -> tuple[Path, str]:
        if entry.offset is None:
            raise ValueError(f"RPF entry has no offset: {entry.name}")
        destination = _safe_output_path(output_dir, entry.name, overwrite)
        digest = copy_range_streaming(path, destination, entry.offset, entry.size, chunk_size, hash_output)
        return destination, digest


class UnrealPakContainerHandler:
    type_name = "unreal_pak"
    magic = b"UPAK"

    def sniff(self, path: Path) -> bool:
        try:
            with path.open("rb") as handle:
                header = handle.read(20)
            if len(header) >= 20 and header[:4] == self.magic:
                entry_count, directory_offset, directory_size, flags = struct.unpack_from("<IIII", header, 4)
                return flags & 1 == 0 and 0 < entry_count <= 1_000_000 and directory_offset + directory_size <= path.stat().st_size
            return self._real_footer(path) is not None
        except (OSError, struct.error):
            return False

    def _read_fstring(self, data: bytes, cursor: int) -> tuple[str, int]:
        if cursor + 4 > len(data):
            raise ValueError("truncated Unreal PAK string length")
        length = struct.unpack_from("<i", data, cursor)[0]
        cursor += 4
        if length == 0:
            return "", cursor
        if length > 0:
            if cursor + length > len(data):
                raise ValueError("truncated Unreal PAK string")
            raw = data[cursor : cursor + length]
            cursor += length
            return raw.rstrip(b"\0").decode("utf-8", errors="replace"), cursor
        byte_length = abs(length) * 2
        if cursor + byte_length > len(data):
            raise ValueError("truncated Unreal PAK UTF-16 string")
        raw = data[cursor : cursor + byte_length]
        cursor += byte_length
        return raw.rstrip(b"\0").decode("utf-16-le", errors="replace"), cursor

    def _real_footer(self, path: Path) -> dict[str, int] | None:
        size = path.stat().st_size
        tail_size = min(size, 512)
        with path.open("rb") as handle:
            handle.seek(size - tail_size)
            tail = handle.read(tail_size)
        cursor = 0
        while True:
            match = tail.find(UNREAL_PAK_FOOTER_MAGIC_BYTES, cursor)
            if match == -1:
                return None
            footer_offset = size - tail_size + match
            if match + 44 <= len(tail):
                magic, version, index_offset, index_size = struct.unpack_from("<IIQQ", tail, match)
                if (
                    magic == UNREAL_PAK_FOOTER_MAGIC
                    and 0 < version < 1_000
                    and index_size > 0
                    and index_offset >= 0
                    and index_offset + index_size <= footer_offset
                ):
                    encrypted = False
                    if match + 45 <= len(tail) and footer_offset + 45 <= size:
                        encrypted = tail[match + 44] not in {0}
                    if not encrypted:
                        return {
                            "version": version,
                            "index_offset": int(index_offset),
                            "index_size": int(index_size),
                            "footer_offset": footer_offset,
                        }
            cursor = match + 1

    def _parse_real_entry(self, data: bytes, cursor: int, archive_size: int) -> tuple[ContainerEntry, int]:
        filename, cursor = self._read_fstring(data, cursor)
        errors: list[str] = []
        for has_timestamp in (False, True):
            try:
                pos = cursor
                if pos + 28 > len(data):
                    raise ValueError("truncated Unreal PAK entry")
                offset, compressed_size, uncompressed_size, compression_method = struct.unpack_from("<QQQI", data, pos)
                pos += 28
                if has_timestamp:
                    if pos + 8 > len(data):
                        raise ValueError("truncated Unreal PAK timestamp")
                    pos += 8
                if pos + 20 + 4 + 1 + 4 > len(data):
                    raise ValueError("truncated Unreal PAK entry metadata")
                pos += 20
                block_count = struct.unpack_from("<I", data, pos)[0]
                pos += 4
                if block_count:
                    raise ValueError("unsupported Unreal PAK compressed entry")
                encrypted = data[pos] != 0
                pos += 1
                _compression_block_size = struct.unpack_from("<I", data, pos)[0]
                pos += 4
                if encrypted:
                    raise ValueError("encrypted_or_unsupported_index")
                if compression_method != 0:
                    raise ValueError("unsupported Unreal PAK compression")
                if compressed_size != uncompressed_size:
                    raise ValueError("unsupported Unreal PAK compressed size")
                if offset + compressed_size > archive_size:
                    raise ValueError(f"Unreal PAK entry range exceeds archive: {filename}")
                return _container_entry(Path(""), filename, int(uncompressed_size), int(offset)), pos
            except ValueError as exc:
                errors.append(str(exc))
        raise ValueError(errors[-1] if errors else "invalid Unreal PAK entry")

    def _open_real(self, path: Path) -> OpenContainer:
        footer = self._real_footer(path)
        if footer is None:
            raise ValueError("not an unencrypted Unreal PAK index")
        archive_size = path.stat().st_size
        with path.open("rb") as handle:
            handle.seek(footer["index_offset"])
            index = handle.read(footer["index_size"])
        mount_point, cursor = self._read_fstring(index, 0)
        if cursor + 4 > len(index):
            raise ValueError("truncated Unreal PAK index count")
        entry_count = struct.unpack_from("<i", index, cursor)[0]
        cursor += 4
        if entry_count <= 0 or entry_count > 1_000_000:
            raise ValueError(f"unreasonable Unreal PAK index count: {entry_count}")
        entries: list[ContainerEntry] = []
        for _ in range(entry_count):
            entry, cursor = self._parse_real_entry(index, cursor, archive_size)
            if mount_point:
                safe_mount = _safe_mount_prefix(mount_point)
                entry.name = _safe_archive_name(f"{safe_mount}/{entry.name}" if safe_mount else entry.name)
            entry.source_container = str(path)
            entries.append(entry)
        info = ContainerInfo(
            path=str(path),
            type=self.type_name,
            entry_count=len(entries),
            payload_bytes=sum(entry.size for entry in entries),
            data_offset=None,
        )
        return OpenContainer(info=info, entries=entries)

    def open(self, path: Path) -> OpenContainer:
        size = path.stat().st_size
        with path.open("rb") as handle:
            header = handle.read(20)
            if len(header) < 20 or header[:4] != self.magic:
                return self._open_real(path)
            entry_count, directory_offset, directory_size, flags = struct.unpack_from("<IIII", header, 4)
            if flags & 1:
                raise ValueError("encrypted_or_unsupported_index")
            if directory_offset + directory_size > size:
                raise ValueError("invalid Unreal PAK directory range")
            handle.seek(directory_offset)
            directory = handle.read(directory_size)
        entries: list[ContainerEntry] = []
        cursor = 0
        for _ in range(entry_count):
            if cursor + 18 > len(directory):
                raise ValueError("truncated Unreal PAK directory")
            name_length = struct.unpack_from("<H", directory, cursor)[0]
            cursor += 2
            if name_length <= 0 or cursor + name_length + 16 > len(directory):
                raise ValueError("invalid Unreal PAK entry name")
            name = directory[cursor : cursor + name_length].decode("utf-8", errors="replace")
            cursor += name_length
            offset, entry_size = struct.unpack_from("<QQ", directory, cursor)
            cursor += 16
            if offset + entry_size > size:
                raise ValueError(f"Unreal PAK entry range exceeds archive: {name}")
            entries.append(_container_entry(path, name, int(entry_size), int(offset)))
        info = ContainerInfo(
            path=str(path),
            type=self.type_name,
            entry_count=len(entries),
            payload_bytes=sum(entry.size for entry in entries),
            data_offset=None,
        )
        return OpenContainer(info=info, entries=entries)

    def inspect(self, path: Path) -> ContainerInfo:
        return self.open(path).info

    def iter_entries(self, path: Path) -> Iterator[ContainerEntry]:
        return self.open(path).iter_entries()

    def extract_entry(
        self,
        path: Path,
        entry: ContainerEntry,
        output_dir: Path,
        overwrite: bool,
        chunk_size: int,
        hash_output: bool,
    ) -> tuple[Path, str]:
        if entry.offset is None:
            raise ValueError(f"Unreal PAK entry has no offset: {entry.name}")
        destination = _safe_output_path(output_dir, entry.name, overwrite)
        digest = copy_range_streaming(path, destination, entry.offset, entry.size, chunk_size, hash_output)
        return destination, digest


class UtocContainerHandler:
    type_name = "utoc"
    magic = b"UTOC"

    def sniff(self, path: Path) -> bool:
        try:
            with path.open("rb") as handle:
                header = handle.read(64)
            ucas = path.with_suffix(".ucas")
            if not ucas.exists():
                return False
            if len(header) >= 20 and header[:4] == self.magic:
                entry_count, directory_offset, directory_size, flags = struct.unpack_from("<IIII", header, 4)
                return flags & 1 == 0 and 0 < entry_count <= 1_000_000 and directory_offset + directory_size <= path.stat().st_size
            if len(header) >= 56 and header[:16] == IOSTORE_TOC_MAGIC:
                entry_count = struct.unpack_from("<I", header, 24)[0]
                compressed_blocks = struct.unpack_from("<I", header, 28)[0]
                directory_index_size = struct.unpack_from("<I", header, 48)[0]
                return 0 < entry_count <= 1_000_000 and compressed_blocks == 0 and directory_index_size == 0
            return False
        except (OSError, struct.error):
            return False

    def _uint40(self, data: bytes, cursor: int) -> int:
        if cursor + 5 > len(data):
            raise ValueError("truncated IoStore offset/length")
        return int.from_bytes(data[cursor : cursor + 5], "little")

    def _open_iostore(self, path: Path) -> OpenContainer:
        table_size = path.stat().st_size
        table = path.read_bytes()
        ucas = path.with_suffix(".ucas")
        ucas_size = ucas.stat().st_size
        if len(table) < 56 or table[:16] != IOSTORE_TOC_MAGIC:
            raise ValueError("not an unencrypted UTOC table")
        header_size = struct.unpack_from("<I", table, 20)[0]
        entry_count = struct.unpack_from("<I", table, 24)[0]
        compressed_block_count = struct.unpack_from("<I", table, 28)[0]
        compressed_block_entry_size = struct.unpack_from("<I", table, 32)[0]
        method_count = struct.unpack_from("<I", table, 36)[0]
        method_name_length = struct.unpack_from("<I", table, 40)[0]
        directory_index_size = struct.unpack_from("<I", table, 48)[0]
        if header_size < 56 or header_size > table_size:
            raise ValueError("invalid UTOC header range")
        if entry_count <= 0 or entry_count > 1_000_000:
            raise ValueError(f"unreasonable UTOC entry count: {entry_count}")
        if compressed_block_count:
            raise ValueError("unsupported UTOC compression")
        if directory_index_size:
            raise ValueError("unsupported UTOC directory index")
        cursor = header_size
        chunk_ids_size = entry_count * 12
        offset_lengths_size = entry_count * 10
        skip_size = compressed_block_count * compressed_block_entry_size + method_count * method_name_length
        if cursor + chunk_ids_size + offset_lengths_size + skip_size > table_size:
            raise ValueError("truncated UTOC table")
        chunk_ids = table[cursor : cursor + chunk_ids_size]
        cursor += chunk_ids_size + skip_size
        offset_lengths = table[cursor : cursor + offset_lengths_size]
        entries: list[ContainerEntry] = []
        for index in range(entry_count):
            chunk_id = chunk_ids[index * 12 : (index + 1) * 12].hex()
            item_cursor = index * 10
            offset = self._uint40(offset_lengths, item_cursor)
            entry_size = self._uint40(offset_lengths, item_cursor + 5)
            if offset + entry_size > ucas_size:
                raise ValueError(f"UTOC chunk range exceeds UCAS payload: {chunk_id}")
            entry = _container_entry(path, f"{chunk_id}.ucasbin", int(entry_size), int(offset))
            entry.source_container = str(ucas)
            entries.append(entry)
        info = ContainerInfo(
            path=str(path),
            type=self.type_name,
            entry_count=len(entries),
            payload_bytes=sum(entry.size for entry in entries),
            data_offset=None,
        )
        return OpenContainer(info=info, entries=entries)

    def open(self, path: Path) -> OpenContainer:
        table_size = path.stat().st_size
        ucas = path.with_suffix(".ucas")
        ucas_size = ucas.stat().st_size
        with path.open("rb") as handle:
            header = handle.read(20)
            if len(header) < 20 or header[:4] != self.magic:
                return self._open_iostore(path)
            entry_count, directory_offset, directory_size, flags = struct.unpack_from("<IIII", header, 4)
            if flags & 1:
                raise ValueError("encrypted_or_unsupported_index")
            if directory_offset + directory_size > table_size:
                raise ValueError("invalid UTOC directory range")
            handle.seek(directory_offset)
            directory = handle.read(directory_size)
        entries: list[ContainerEntry] = []
        cursor = 0
        for _ in range(entry_count):
            if cursor + 18 > len(directory):
                raise ValueError("truncated UTOC directory")
            name_length = struct.unpack_from("<H", directory, cursor)[0]
            cursor += 2
            if name_length <= 0 or cursor + name_length + 16 > len(directory):
                raise ValueError("invalid UTOC chunk name")
            name = directory[cursor : cursor + name_length].decode("utf-8", errors="replace")
            cursor += name_length
            offset, entry_size = struct.unpack_from("<QQ", directory, cursor)
            cursor += 16
            if offset + entry_size > ucas_size:
                raise ValueError(f"UTOC chunk range exceeds UCAS payload: {name}")
            entry = _container_entry(path, name, int(entry_size), int(offset))
            entry.source_container = str(ucas)
            entries.append(entry)
        info = ContainerInfo(
            path=str(path),
            type=self.type_name,
            entry_count=len(entries),
            payload_bytes=sum(entry.size for entry in entries),
            data_offset=None,
        )
        return OpenContainer(info=info, entries=entries)

    def inspect(self, path: Path) -> ContainerInfo:
        return self.open(path).info

    def iter_entries(self, path: Path) -> Iterator[ContainerEntry]:
        return self.open(path).iter_entries()

    def extract_entry(
        self,
        path: Path,
        entry: ContainerEntry,
        output_dir: Path,
        overwrite: bool,
        chunk_size: int,
        hash_output: bool,
    ) -> tuple[Path, str]:
        if entry.offset is None:
            raise ValueError(f"UTOC entry has no UCAS offset: {entry.name}")
        destination = _safe_output_path(output_dir, entry.name, overwrite)
        digest = copy_range_streaming(Path(entry.source_container), destination, entry.offset, entry.size, chunk_size, hash_output)
        return destination, digest


def build_builtin_container_handlers() -> list[ContainerHandler]:
    return [
        GpakContainerHandler(),
        ZipContainerHandler(),
        PakContainerHandler(),
        VpkContainerHandler(),
        RpfContainerHandler(),
        UnrealPakContainerHandler(),
        UtocContainerHandler(),
    ]


CONTAINER_HANDLERS: list[ContainerHandler] = build_builtin_container_handlers()


DEEP_CONTAINER_TYPES = {"rpf", "unreal_pak", "utoc"}


def find_container_handler(
    path: str | Path,
    deep_scan: bool = True,
    handlers: list[ContainerHandler] | None = None,
) -> ContainerHandler | None:
    file_path = Path(path)
    for handler in handlers or CONTAINER_HANDLERS:
        if not deep_scan and handler.type_name in DEEP_CONTAINER_TYPES:
            continue
        if handler.sniff(file_path):
            return handler
    return None


def source_for_container_entry(
    handler: object,
    container_path: Path,
    entry: ContainerEntry,
    chunk_size: int,
) -> ArtifactSource | None:
    source_factory = getattr(handler, "source_for_entry", None)
    if callable(source_factory):
        return source_factory(container_path, entry, chunk_size)
    if entry.offset is None:
        return None
    source_path = Path(entry.source_container or container_path)
    return ArtifactSource.from_path(
        source_path,
        offset=entry.offset,
        length=entry.size,
        name=entry.name,
        chunk_size=chunk_size,
    )
