from __future__ import annotations

import struct
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .classification import classify_asset
from .models import DecompilationReport, ExtractionOptions

GPAK_VERSION = "gpak-v1-flat-index"
CHUNK_SIZE = 1024 * 1024


@dataclass(slots=True)
class GpakEntry:
    name: str
    size: int
    offset: int
    index: int

    @property
    def extension(self) -> str:
        return Path(self.name).suffix.lower() or "<none>"

    @property
    def category(self) -> str:
        return classify_asset(self.name)["category"]


def parse_gpak_index(path: str | Path) -> tuple[list[GpakEntry], int]:
    file_path = Path(path)
    file_size = file_path.stat().st_size
    with file_path.open("rb") as handle:
        count_bytes = handle.read(4)
        if len(count_bytes) != 4:
            raise ValueError("missing GPAK entry count")
        count = struct.unpack("<I", count_bytes)[0]
        if count == 0 or count > 1_000_000:
            raise ValueError(f"unreasonable GPAK entry count: {count}")
        raw_entries: list[tuple[str, int]] = []
        index_offset = 4
        for index in range(count):
            raw_len = handle.read(2)
            if len(raw_len) != 2:
                raise ValueError(f"missing GPAK name length at entry {index}")
            name_len = struct.unpack("<H", raw_len)[0]
            if name_len == 0 or name_len > 4096:
                raise ValueError(f"unreasonable GPAK name length at entry {index}: {name_len}")
            name_bytes = handle.read(name_len)
            size_bytes = handle.read(4)
            if len(name_bytes) != name_len or len(size_bytes) != 4:
                raise ValueError(f"truncated GPAK index entry {index}")
            try:
                name = name_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError(f"GPAK entry {index} has non-utf8 name") from exc
            if Path(name).is_absolute() or ".." in Path(name.replace("\\", "/")).parts:
                raise ValueError(f"unsafe GPAK entry path: {name}")
            size = struct.unpack("<I", size_bytes)[0]
            raw_entries.append((name, size))
            index_offset += 2 + name_len + 4

    cursor = index_offset
    entries: list[GpakEntry] = []
    for index, (name, size) in enumerate(raw_entries):
        entries.append(GpakEntry(name=name, size=size, offset=cursor, index=index))
        cursor += size
    if cursor != file_size:
        raise ValueError(f"GPAK payload end {cursor} does not match file size {file_size}")
    return entries, index_offset


def is_gpak(path: str | Path) -> bool:
    try:
        parse_gpak_index(path)
        return True
    except (OSError, ValueError):
        return False


def _inventory(entries: list[GpakEntry]) -> dict[str, Any]:
    extension_counts = Counter(entry.extension for entry in entries)
    category_counts = Counter(entry.category for entry in entries)
    directory_counts = Counter(entry.name.split("/", 1)[0] for entry in entries)
    bytes_by_category: defaultdict[str, int] = defaultdict(int)
    largest: list[dict[str, Any]] = []
    for entry in entries:
        bytes_by_category[entry.category] += entry.size
        largest.append(
            {
                "name": entry.name,
                "size": entry.size,
                "extension": entry.extension,
                **classify_asset(entry.name),
            }
        )
    largest.sort(key=lambda item: int(item["size"]), reverse=True)
    return {
        "entry_count": len(entries),
        "extension_counts": dict(extension_counts.most_common()),
        "category_counts": dict(category_counts.most_common()),
        "top_dirs": dict(directory_counts.most_common()),
        "bytes_by_category": dict(sorted(bytes_by_category.items())),
        "largest_entries": largest[:30],
        "recommended_focus": [
            "data/*.gon, *.csv, *.ini, *.txt for game rules, tuning, item tables, and readable config",
            "levels/*.lvl for level/map structure after format-specific decoding",
            "swfs/*.swf for UI and possible compiled ActionScript; requires a SWF parser/decompiler layer",
            "textures/*.png and audio/* for media extraction, usually not behavioral decompilation",
            "shaders/*.shader for rendering behavior if shader text is readable",
        ],
    }


def inspect_gpak(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)
    entries, data_offset = parse_gpak_index(file_path)
    return {
        "path": str(file_path),
        "format": GPAK_VERSION,
        "file_size": file_path.stat().st_size,
        "data_offset": data_offset,
        **_inventory(entries),
    }


def extract_gpak(
    input_path: str | Path,
    output_dir: str | Path,
    options: ExtractionOptions | None = None,
) -> DecompilationReport:
    from .pipeline import decompile_path

    extraction_options = options or ExtractionOptions()
    extraction_options.mode = "full"
    return decompile_path(input_path, output_dir, extraction_options)
