from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class _Stream:
    name: str
    offset: int
    size: int


def _read_at(path: Path, offset: int, length: int) -> bytes:
    with path.open("rb") as handle:
        handle.seek(offset)
        return handle.read(length)


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def _heap_index_size(heap_sizes: int, bit: int) -> int:
    return 4 if heap_sizes & bit else 2


def _table_index_size(rows: dict[int, int], table: int) -> int:
    return 4 if rows.get(table, 0) >= 0xFFFF else 2


def _coded_index_size(rows: dict[int, int], tables: tuple[int, ...], tag_bits: int) -> int:
    limit = 1 << (16 - tag_bits)
    return 4 if any(rows.get(table, 0) >= limit for table in tables) else 2


def _table_row_size(table: int, rows: dict[int, int], heap_sizes: int) -> int:
    string = _heap_index_size(heap_sizes, 0x01)
    guid = _heap_index_size(heap_sizes, 0x02)
    blob = _heap_index_size(heap_sizes, 0x04)
    resolution_scope = _coded_index_size(rows, (0, 26, 35, 1), 2)
    type_def_or_ref = _coded_index_size(rows, (2, 1, 27), 2)
    has_constant = _coded_index_size(rows, (4, 8, 23), 2)
    has_custom_attribute = _coded_index_size(rows, (6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43), 5)
    has_field_marshal = _coded_index_size(rows, (4, 8), 1)
    has_decl_security = _coded_index_size(rows, (2, 6, 32), 2)
    member_ref_parent = _coded_index_size(rows, (2, 1, 26, 6, 27), 3)
    has_semantics = _coded_index_size(rows, (20, 23), 1)
    method_def_or_ref = _coded_index_size(rows, (6, 10), 1)
    member_forwarded = _coded_index_size(rows, (4, 6), 1)
    implementation = _coded_index_size(rows, (38, 35, 39), 2)
    custom_attribute_type = _coded_index_size(rows, (6, 10), 3)
    resolution_scope_or_type = resolution_scope

    sizes = {
        0: 2 + string + guid * 3,
        1: resolution_scope_or_type + string + string,
        2: 4 + string + string + type_def_or_ref + _table_index_size(rows, 4) + _table_index_size(rows, 6),
        3: _table_index_size(rows, 4),
        4: 2 + string + blob,
        5: _table_index_size(rows, 6),
        6: 4 + 2 + 2 + string + blob + _table_index_size(rows, 8),
        7: _table_index_size(rows, 8),
        8: 2 + 2 + string,
        9: _table_index_size(rows, 2) + type_def_or_ref,
        10: member_ref_parent + string + blob,
        11: 2 + has_constant + blob,
        12: has_custom_attribute + custom_attribute_type + blob,
        13: has_field_marshal + blob,
        14: 2 + has_decl_security + blob,
        15: 2 + 4 + _table_index_size(rows, 2),
        16: 4 + _table_index_size(rows, 4),
        17: blob,
        18: _table_index_size(rows, 2) + _table_index_size(rows, 20),
        19: _table_index_size(rows, 20),
        20: 2 + string + blob,
        21: 2 + 2 + has_semantics,
        22: _table_index_size(rows, 6) + method_def_or_ref,
        23: 4 + string + blob,
        24: 4 + _table_index_size(rows, 4),
        25: _table_index_size(rows, 2) + _table_index_size(rows, 26),
        26: 4 + string + string,
        27: blob,
        28: 2 + _table_index_size(rows, 2) + _table_index_size(rows, 28),
        29: _table_index_size(rows, 2) + type_def_or_ref,
        30: string,
        31: 4 + 4,
        32: 4 + 2 + 2 + 2 + 2 + 4 + blob + string + string,
        33: 4 + 4 + 4,
        34: 4 + 4 + 4,
        35: 4 + 2 + 2 + 2 + 2 + 4 + blob + string + string,
        36: 4 + 4 + 4,
        37: 4 + 4 + 4,
        38: 4 + string + string + implementation,
        39: 4 + 4 + string + string + implementation,
        40: 4 + 4 + string + implementation,
        41: 2 + 2 + 2 + 2 + 4 + blob + string + string,
        42: 2 + 2 + string,
        43: _table_index_size(rows, 2) + _table_index_size(rows, 4),
        44: 4 + _table_index_size(rows, 4),
    }
    return sizes.get(table, 0)


def _stream_map(parse_info: dict[str, Any]) -> dict[str, _Stream]:
    metadata = parse_info.get("dotnet_metadata") or {}
    streams = metadata.get("streams") or []
    return {
        str(item.get("name", "")): _Stream(str(item.get("name", "")), int(item.get("offset", 0)), int(item.get("size", 0)))
        for item in streams
    }


def _read_string(strings: bytes, index: int) -> str:
    if index <= 0 or index >= len(strings):
        return ""
    end = strings.find(b"\0", index)
    if end == -1:
        end = len(strings)
    return strings[index:end].decode("utf-8", errors="replace")


def inspect_assembly(path: str | Path, parse_info: dict[str, Any]) -> dict[str, Any]:
    assembly_path = Path(path)
    if not parse_info.get("is_dotnet"):
        return {"parser": "dotnet_tables", "status": "not_dotnet"}
    metadata_offset = ((parse_info.get("clr_header") or {}).get("metadata_offset"))
    if metadata_offset is None:
        return {"parser": "dotnet_tables", "status": "metadata_offset_unavailable"}
    streams = _stream_map(parse_info)
    table_stream = streams.get("#~") or streams.get("#-")
    strings_stream = streams.get("#Strings")
    if table_stream is None:
        return {"parser": "dotnet_tables", "status": "tables_stream_unavailable"}
    try:
        tables_data = _read_at(assembly_path, int(metadata_offset) + table_stream.offset, table_stream.size)
        strings_data = (
            _read_at(assembly_path, int(metadata_offset) + strings_stream.offset, strings_stream.size)
            if strings_stream is not None
            else b""
        )
        if len(tables_data) < 24:
            return {"parser": "dotnet_tables", "status": "tables_stream_too_small"}
        heap_sizes = tables_data[6]
        valid_mask = _u64(tables_data, 8)
        cursor = 24
        present = [table for table in range(64) if valid_mask & (1 << table)]
        rows: dict[int, int] = {}
        for table in present:
            if cursor + 4 > len(tables_data):
                return {"parser": "dotnet_tables", "status": "truncated_row_counts"}
            rows[table] = _u32(tables_data, cursor)
            cursor += 4
        table_offsets: dict[int, int] = {}
        for table in present:
            table_offsets[table] = cursor
            cursor += _table_row_size(table, rows, heap_sizes) * rows.get(table, 0)
            if cursor > len(tables_data):
                return {"parser": "dotnet_tables", "status": "truncated_tables"}
        return {
            "parser": "dotnet_tables",
            "status": "parsed",
            "type_def_count": rows.get(2, 0),
            "method_def_count": rows.get(6, 0),
            "field_count": rows.get(4, 0),
            "member_ref_count": rows.get(10, 0),
            "strings_heap_size": len(strings_data),
            "heap_sizes": heap_sizes,
            "rows": {str(key): value for key, value in rows.items()},
            "table_offsets": {str(key): value for key, value in table_offsets.items()},
        }
    except (OSError, struct.error, ValueError) as exc:
        return {"parser": "dotnet_tables", "status": "parse_error", "error": str(exc)}


def iter_assembly_types(path: str | Path, parse_info: dict[str, Any], limit: int | None = None) -> list[dict[str, Any]]:
    assembly_path = Path(path)
    summary = inspect_assembly(assembly_path, parse_info)
    if summary.get("status") != "parsed":
        return []
    metadata_offset = int((parse_info.get("clr_header") or {}).get("metadata_offset"))
    streams = _stream_map(parse_info)
    table_stream = streams.get("#~") or streams.get("#-")
    strings_stream = streams.get("#Strings")
    if table_stream is None:
        return []
    try:
        tables_data = _read_at(assembly_path, metadata_offset + table_stream.offset, table_stream.size)
        strings_data = (
            _read_at(assembly_path, metadata_offset + strings_stream.offset, strings_stream.size)
            if strings_stream is not None
            else b""
        )
        heap_sizes = tables_data[6]
        rows = {int(key): int(value) for key, value in (summary.get("rows") or {}).items()}
        offsets = {int(key): int(value) for key, value in (summary.get("table_offsets") or {}).items()}
        string_index = _heap_index_size(heap_sizes, 0x01)
        blob_index = _heap_index_size(heap_sizes, 0x04)
        type_def_or_ref = _coded_index_size(rows, (2, 1, 27), 2)
        field_index = _table_index_size(rows, 4)
        method_index = _table_index_size(rows, 6)
        type_row_size = _table_row_size(2, rows, heap_sizes)
        method_row_size = _table_row_size(6, rows, heap_sizes)

        method_names: list[str] = []
        method_offset = offsets.get(6)
        if method_offset is not None:
            for index in range(rows.get(6, 0)):
                row = method_offset + index * method_row_size
                name_offset = row + 4 + 2 + 2
                name_index = _u32(tables_data, name_offset) if string_index == 4 else _u16(tables_data, name_offset)
                method_names.append(_read_string(strings_data, name_index))

        records: list[dict[str, Any]] = []
        type_offset = offsets.get(2)
        if type_offset is None:
            return records
        count = rows.get(2, 0)
        for index in range(count):
            if limit is not None and len(records) >= limit:
                break
            row = type_offset + index * type_row_size
            name_offset = row + 4
            namespace_offset = name_offset + string_index
            name_index = _u32(tables_data, name_offset) if string_index == 4 else _u16(tables_data, name_offset)
            namespace_index = _u32(tables_data, namespace_offset) if string_index == 4 else _u16(tables_data, namespace_offset)
            list_offset = namespace_offset + string_index + type_def_or_ref
            field_list = _u32(tables_data, list_offset) if field_index == 4 else _u16(tables_data, list_offset)
            method_list_offset = list_offset + field_index
            method_list = _u32(tables_data, method_list_offset) if method_index == 4 else _u16(tables_data, method_list_offset)
            if index + 1 < count:
                next_row = type_offset + (index + 1) * type_row_size
                next_list_offset = next_row + 4 + string_index + string_index + type_def_or_ref + field_index
                next_method_list = _u32(tables_data, next_list_offset) if method_index == 4 else _u16(tables_data, next_list_offset)
            else:
                next_method_list = rows.get(6, 0) + 1
            method_count = max(0, next_method_list - method_list)
            method_start = max(0, method_list - 1)
            methods_sample = [name for name in method_names[method_start : method_start + min(method_count, 25)] if name]
            records.append(
                {
                    "assembly_path": str(assembly_path),
                    "kind": "type",
                    "token": f"0x{0x02000000 + index + 1:08x}",
                    "namespace": _read_string(strings_data, namespace_index),
                    "name": _read_string(strings_data, name_index),
                    "field_list": field_list,
                    "method_list": method_list,
                    "method_count": method_count,
                    "methods_sample": methods_sample,
                }
            )
        return records
    except (OSError, struct.error, ValueError) as exc:
        return [
            {
                "assembly_path": str(assembly_path),
                "kind": "parse_error",
                "reason": str(exc),
            }
        ]

