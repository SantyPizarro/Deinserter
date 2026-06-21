from __future__ import annotations

import hashlib
import lzma
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .lz4 import decompress_lz4_block


COMPRESSION_NAMES = {
    0: "none",
    1: "lzma",
    2: "lz4",
    3: "lz4hc",
}


@dataclass(slots=True)
class UnityBundleBlock:
    uncompressed_size: int
    compressed_size: int
    flags: int

    @property
    def compression(self) -> str:
        return COMPRESSION_NAMES.get(self.flags & 0x3F, f"unknown:{self.flags & 0x3F}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "uncompressed_size": self.uncompressed_size,
            "compressed_size": self.compressed_size,
            "flags": self.flags,
            "compression": self.compression,
        }


@dataclass(slots=True)
class UnityBundleEntry:
    name: str
    offset: int
    size: int
    flags: int

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "offset": self.offset, "size": self.size, "flags": self.flags}


@dataclass(slots=True)
class _UnityBundleBlockSpan:
    block: UnityBundleBlock
    compressed_offset: int
    uncompressed_start: int
    uncompressed_end: int


@dataclass(slots=True)
class UnityBundleInfo:
    path: str
    signature: str
    format_version: int
    player_version: str
    unity_version: str
    declared_file_size: int
    compressed_blocks_info_size: int
    uncompressed_blocks_info_size: int
    flags: int
    compression: str
    status: str
    file_size: int
    cab_name: str = ""
    blocks_info_offset: int | None = None
    data_offset: int | None = None
    blocks: list[UnityBundleBlock] = field(default_factory=list)
    entries: list[UnityBundleEntry] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "parser": "unity_bundle",
            "path": self.path,
            "status": self.status,
            "file_size": self.file_size,
            "signature": self.signature,
            "format_version": self.format_version,
            "player_version": self.player_version,
            "unity_version": self.unity_version,
            "declared_file_size": self.declared_file_size,
            "compressed_blocks_info_size": self.compressed_blocks_info_size,
            "uncompressed_blocks_info_size": self.uncompressed_blocks_info_size,
            "flags": self.flags,
            "compression": self.compression,
            "cab_name": self.cab_name,
            "blocks_info_offset": self.blocks_info_offset,
            "data_offset": self.data_offset,
            "block_count": len(self.blocks),
            "file_count": len(self.entries),
            "blocks": [block.to_dict() for block in self.blocks[:64]],
            "files": [entry.to_dict() for entry in self.entries[:256]],
            **({"error": self.error} if self.error else {}),
        }


def _c_string(data: bytes, cursor: int) -> tuple[str, int]:
    end = data.find(b"\0", cursor)
    if end == -1:
        return "", len(data)
    return data[cursor:end].decode("utf-8", errors="replace"), end + 1


def _u32_be(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def _u64_be(data: bytes, offset: int) -> int:
    return struct.unpack_from(">Q", data, offset)[0]


def _i64_be(data: bytes, offset: int) -> int:
    return struct.unpack_from(">q", data, offset)[0]


def _decompress(data: bytes, compression: str, expected_size: int | None) -> bytes:
    if compression == "none":
        if expected_size is not None and len(data) != expected_size:
            raise ValueError(f"uncompressed size mismatch: expected {expected_size}, got {len(data)}")
        return data
    if compression == "lzma":
        result = lzma.decompress(data)
        if expected_size is not None and len(result) != expected_size:
            raise ValueError(f"lzma size mismatch: expected {expected_size}, got {len(result)}")
        return result
    if compression in {"lz4", "lz4hc"}:
        return decompress_lz4_block(data, expected_size)
    raise ValueError(f"unsupported UnityFS compression: {compression}")


def _block_spans(info: UnityBundleInfo) -> list[_UnityBundleBlockSpan]:
    spans: list[_UnityBundleBlockSpan] = []
    compressed_cursor = 0
    uncompressed_cursor = 0
    for block in info.blocks:
        block_end = uncompressed_cursor + block.uncompressed_size
        spans.append(
            _UnityBundleBlockSpan(
                block=block,
                compressed_offset=compressed_cursor,
                uncompressed_start=uncompressed_cursor,
                uncompressed_end=block_end,
            )
        )
        compressed_cursor += block.compressed_size
        uncompressed_cursor = block_end
    return spans


def _parse_blocks_info(info: UnityBundleInfo, raw: bytes) -> None:
    if len(raw) < 20:
        raise ValueError("UnityFS block info too small")
    cursor = 16
    block_count = _u32_be(raw, cursor)
    cursor += 4
    if block_count > 1_000_000:
        raise ValueError(f"UnityFS block count too large: {block_count}")
    blocks: list[UnityBundleBlock] = []
    for _ in range(block_count):
        if cursor + 10 > len(raw):
            raise ValueError("truncated UnityFS block table")
        blocks.append(
            UnityBundleBlock(
                uncompressed_size=_u32_be(raw, cursor),
                compressed_size=_u32_be(raw, cursor + 4),
                flags=struct.unpack_from(">H", raw, cursor + 8)[0],
            )
        )
        cursor += 10
    if cursor + 4 > len(raw):
        raise ValueError("truncated UnityFS directory count")
    directory_count = _u32_be(raw, cursor)
    cursor += 4
    if directory_count > 1_000_000:
        raise ValueError(f"UnityFS directory count too large: {directory_count}")
    entries: list[UnityBundleEntry] = []
    for _ in range(directory_count):
        if cursor + 20 > len(raw):
            raise ValueError("truncated UnityFS directory entry")
        offset = _i64_be(raw, cursor)
        size = _i64_be(raw, cursor + 8)
        flags = _u32_be(raw, cursor + 16)
        name, cursor = _c_string(raw, cursor + 20)
        if offset < 0 or size < 0:
            raise ValueError("invalid UnityFS directory entry range")
        entries.append(UnityBundleEntry(name=name, offset=offset, size=size, flags=flags))
    info.blocks = blocks
    info.entries = entries


def inspect_bundle(path: str | Path) -> UnityBundleInfo:
    bundle_path = Path(path)
    file_size = bundle_path.stat().st_size
    with bundle_path.open("rb") as handle:
        header = handle.read(min(file_size, 4096))
    signature, cursor = _c_string(header, 0)
    if signature not in {"UnityFS", "UnityWeb", "UnityRaw"}:
        return UnityBundleInfo(
            path=str(bundle_path),
            signature=signature,
            format_version=0,
            player_version="",
            unity_version="",
            declared_file_size=file_size,
            compressed_blocks_info_size=0,
            uncompressed_blocks_info_size=0,
            flags=0,
            compression="unknown",
            status="unknown_bundle_signature",
            file_size=file_size,
        )
    try:
        format_version = _u32_be(header, cursor)
        cursor += 4
        player_version, cursor = _c_string(header, cursor)
        unity_version, cursor = _c_string(header, cursor)
        declared_file_size = _u64_be(header, cursor)
        compressed_info_size = _u32_be(header, cursor + 8)
        uncompressed_info_size = _u32_be(header, cursor + 12)
        flags = _u32_be(header, cursor + 16)
        cursor += 20
        compression = COMPRESSION_NAMES.get(flags & 0x3F, f"unknown:{flags & 0x3F}")
        cab_offset = header.find(b"CAB-", cursor)
        cab_name = _c_string(header, cab_offset)[0] if cab_offset != -1 else ""
        info = UnityBundleInfo(
            path=str(bundle_path),
            signature=signature,
            format_version=format_version,
            player_version=player_version,
            unity_version=unity_version,
            declared_file_size=declared_file_size,
            compressed_blocks_info_size=compressed_info_size,
            uncompressed_blocks_info_size=uncompressed_info_size,
            flags=flags,
            compression=compression,
            status="parsed_header",
            file_size=file_size,
            cab_name=cab_name,
        )
        if compressed_info_size <= 0 or uncompressed_info_size <= 0:
            return info
        block_info_at_end = bool(flags & 0x80)
        info.blocks_info_offset = max(0, file_size - compressed_info_size) if block_info_at_end else cursor
        info.data_offset = cursor if block_info_at_end else cursor + compressed_info_size
        if info.blocks_info_offset + compressed_info_size > file_size:
            return info
        try:
            with bundle_path.open("rb") as handle:
                handle.seek(info.blocks_info_offset)
                compressed = handle.read(compressed_info_size)
            raw = _decompress(compressed, compression, uncompressed_info_size)
            _parse_blocks_info(info, raw)
            info.status = "parsed"
        except (OSError, struct.error, ValueError, lzma.LZMAError) as exc:
            info.error = str(exc)
        return info
    except (OSError, struct.error, ValueError, lzma.LZMAError) as exc:
        return UnityBundleInfo(
            path=str(bundle_path),
            signature=signature,
            format_version=0,
            player_version="",
            unity_version="",
            declared_file_size=file_size,
            compressed_blocks_info_size=0,
            uncompressed_blocks_info_size=0,
            flags=0,
            compression="unknown",
            status="parse_error",
            file_size=file_size,
            error=str(exc),
        )


def _bundle_data(path: Path, info: UnityBundleInfo) -> bytes:
    if info.data_offset is None:
        raise ValueError("UnityFS data offset unavailable")
    out = bytearray()
    with path.open("rb") as handle:
        for span in _block_spans(info):
            block = span.block
            handle.seek(info.data_offset + span.compressed_offset)
            compressed = handle.read(block.compressed_size)
            out.extend(_decompress(compressed, block.compression, block.uncompressed_size))
    return bytes(out)


def extract_bundle_entry(
    bundle_path: str | Path,
    info: UnityBundleInfo,
    entry: UnityBundleEntry,
    output_dir: str | Path,
    overwrite: bool = False,
    hash_output: bool = True,
) -> tuple[Path, str]:
    path = Path(bundle_path)
    total_uncompressed = sum(block.uncompressed_size for block in info.blocks)
    if entry.offset + entry.size > total_uncompressed:
        raise ValueError(f"UnityFS entry range exceeds bundle data: {entry.name}")
    relative = Path(*Path(entry.name.replace("\\", "/")).parts)
    destination = Path(output_dir) / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not overwrite:
        stem = destination.stem
        suffix = destination.suffix
        index = 1
        while True:
            candidate = destination.with_name(f"{stem}_{index}{suffix}")
            if not candidate.exists():
                destination = candidate
                break
            index += 1
    digest = hashlib.sha256() if hash_output else None
    remaining_start = entry.offset
    remaining_end = entry.offset + entry.size
    uncompressed_cursor = 0
    if info.data_offset is None:
        raise ValueError("UnityFS data offset unavailable")
    with path.open("rb") as handle, destination.open("wb") as out:
        for span in _block_spans(info):
            block = span.block
            block_start = span.uncompressed_start
            block_end = span.uncompressed_end
            overlap_start = max(remaining_start, block_start)
            overlap_end = min(remaining_end, block_end)
            if overlap_start >= overlap_end:
                uncompressed_cursor = block_end
                continue

            if block.compression == "none":
                payload_offset = span.compressed_offset + overlap_start - block_start
                payload_size = overlap_end - overlap_start
                handle.seek(info.data_offset + payload_offset)
                payload = handle.read(payload_size)
                if len(payload) != payload_size:
                    raise ValueError(f"truncated UnityFS entry payload: {entry.name}")
            else:
                handle.seek(info.data_offset + span.compressed_offset)
                compressed = handle.read(block.compressed_size)
                block_data = _decompress(compressed, block.compression, block.uncompressed_size)
                payload = block_data[overlap_start - block_start : overlap_end - block_start]

            out.write(payload)
            if digest is not None:
                digest.update(payload)
            uncompressed_cursor = block_end
            if uncompressed_cursor >= remaining_end:
                break
    return destination, digest.hexdigest() if digest is not None else ""
