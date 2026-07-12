from __future__ import annotations

import json
import hashlib
import io
import lzma
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from deinserter import (
    ExtractionOptions,
    FileIdentification,
    FormatSpec,
    ScanOptions,
    build_capability_registry,
    decompile_path,
    identify_file,
    inspect_gpak,
    iter_manifest_records,
    load_manifest_summary,
    plan_path,
    probe_file,
    read_manifest,
    scan_path,
    extract_path,
)
from deinserter.detectors import ExtensionDetector
from deinserter.registry import CAPABILITY_API_VERSION, register_plugin_callable
import deinserter.unity.bundle as unity_bundle
from deinserter.unity.bundle import extract_bundle_entry, inspect_bundle
from deinserter.unity.lz4 import decompress_lz4_block


PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR"
    b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"
    b"\x90wS\xde"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)


def make_glb(payload: bytes = b"") -> bytes:
    total = 12 + len(payload)
    return b"glTF" + struct.pack("<II", 2, total) + payload


def make_glb_with_json(document: bytes = b'{"asset":{"version":"2.0"}}') -> bytes:
    padding = b" " * ((4 - len(document) % 4) % 4)
    chunk = struct.pack("<II", len(document) + len(padding), 0x4E4F534A) + document + padding
    return b"glTF" + struct.pack("<II", 2, 12 + len(chunk)) + chunk


def make_wav() -> bytes:
    body = b"fmt " + struct.pack("<I", 16) + b"\x01\x00\x01\x00\x40\x1f\x00\x00\x80>\x00\x00\x02\x00\x10\x00"
    body += b"data" + struct.pack("<I", 2) + b"\x00\x00"
    return b"RIFF" + struct.pack("<I", len(body) + 4) + b"WAVE" + body


def make_jpeg() -> bytes:
    return b"\xff\xd8" + b"\xff\xe0\x00\x04JF" + b"\xff\xda\x00\x02" + b"\x01\x02\x03" + b"\xff\xd9"


def make_dds() -> bytes:
    header = bytearray(128)
    header[:4] = b"DDS "
    struct.pack_into("<I", header, 4, 124)
    struct.pack_into("<I", header, 8, 0x1007)
    struct.pack_into("<II", header, 12, 1, 1)
    struct.pack_into("<I", header, 20, 4)
    struct.pack_into("<I", header, 76, 32)
    struct.pack_into("<I", header, 80, 0x41)
    struct.pack_into("<I", header, 88, 32)
    struct.pack_into("<IIII", header, 92, 0x00FF0000, 0x0000FF00, 0x000000FF, 0xFF000000)
    struct.pack_into("<I", header, 108, 0x1000)
    return bytes(header) + b"\x00\x00\x00\xff"


def make_tga() -> bytes:
    header = bytearray(18)
    header[2] = 2
    struct.pack_into("<HH", header, 12, 1, 1)
    header[16] = 24
    return bytes(header) + b"\x00\x00\xff"


def make_fsb5_valid() -> bytes:
    return b"FSB5" + struct.pack("<IIIIII", 1, 0, 0, 0, 4, 0) + b"\0" * 32 + b"data"


def make_mo() -> bytes:
    original = b"hello"
    translated = b"hola"
    header_size = 28
    original_table = header_size
    translated_table = original_table + 8
    original_offset = translated_table + 8
    translated_offset = original_offset + len(original)
    return (
        b"\xde\x12\x04\x95"
        + struct.pack("<IIIIII", 0, 1, original_table, translated_table, 0, 0)
        + struct.pack("<II", len(original), original_offset)
        + struct.pack("<II", len(translated), translated_offset)
        + original
        + translated
    )


def make_ttf() -> bytes:
    payload = b"name"
    header = bytearray(b"\x00\x01\x00\x00" + struct.pack(">HHHH", 1, 16, 0, 16))
    header.extend(b"name" + struct.pack(">III", 0, 28, len(payload)))
    return bytes(header) + payload


def make_wasm() -> bytes:
    return b"\0asm\x01\0\0\0" + b"\0\x04name"


def make_elf() -> bytes:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[6] = 1
    struct.pack_into("<HHIQQQIHHHHHH", header, 16, 3, 0x3E, 1, 0, 0, 0, 0, 64, 0, 0, 64, 0, 0)
    return bytes(header)


def make_pdb() -> bytes:
    block_size = 512
    block_count = 2
    data = bytearray(block_size * block_count)
    data[:32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"
    struct.pack_into("<IIIIII", data, 32, block_size, 1, block_count, 0, 0, 1)
    return bytes(data)


def make_pe_exact() -> bytes:
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 224, 0x010F)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    section = optional + 224
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x200, 0x1000, 0x200, 0x200)
    data[0x200:0x204] = b"code"
    return bytes(data)


def make_bank() -> bytes:
    return b"BKHD" + struct.pack("<I", 4) + b"\x01\0\0\0" + b"DATA" + struct.pack("<I", 3) + b"abc"


def make_unreal_package() -> bytes:
    data = bytearray(128)
    data[:4] = b"\xc1\x83\x2a\x9e"
    struct.pack_into("<iiiii", data, 4, -4, 0, 522, 0, 0)
    return bytes(data)


def make_rpf() -> bytes:
    return b"RPF7" + struct.pack(">III", 1, 0, 0) + b"\0" * 48


def make_gpak(path: Path, entries: dict[str, bytes]) -> None:
    index = bytearray(struct.pack("<I", len(entries)))
    payload = bytearray()
    for name, data in entries.items():
        encoded = name.encode("utf-8")
        index.extend(struct.pack("<H", len(encoded)))
        index.extend(encoded)
        index.extend(struct.pack("<I", len(data)))
        payload.extend(data)
    path.write_bytes(bytes(index + payload))


def make_unity_assets_v22(path: Path, unity_version: str = "2022.3.67f2") -> None:
    content = bytearray(160)
    struct.pack_into(">I", content, 8, 22)
    struct.pack_into(">Q", content, 16, 64)
    struct.pack_into(">Q", content, 24, len(content))
    struct.pack_into(">Q", content, 32, 128)
    content[40] = 0
    encoded = unity_version.encode("utf-8") + b"\0"
    content[48 : 48 + len(encoded)] = encoded
    struct.pack_into(">I", content, 48 + len(encoded), 19)
    path.write_bytes(content)


def make_unity_assets_v22_with_object(
    path: Path,
    payload: bytes = b"hello from unity\n",
    class_id: int = 49,
    unity_version: str = "2022.3.67f2",
) -> None:
    metadata = bytearray()
    metadata.extend(unity_version.encode("utf-8") + b"\0")
    metadata.extend(struct.pack(">i", 19))
    metadata.extend(b"\0")
    metadata.extend(struct.pack(">i", 1))
    metadata.extend(struct.pack(">i", class_id))
    metadata.extend(b"\0")
    metadata.extend(struct.pack(">h", -1))
    if class_id == 114:
        metadata.extend(b"\0" * 16)
    metadata.extend(b"\0" * 16)
    while len(metadata) % 4:
        metadata.extend(b"\0")
    metadata.extend(struct.pack(">i", 1))
    while len(metadata) % 4:
        metadata.extend(b"\0")
    metadata.extend(struct.pack(">qQIi", 1001, 0, len(payload), 0))
    data_offset = 256
    content = bytearray(48)
    struct.pack_into(">I", content, 8, 22)
    struct.pack_into(">Q", content, 16, len(metadata))
    struct.pack_into(">Q", content, 24, data_offset + len(payload))
    struct.pack_into(">Q", content, 32, data_offset)
    content[40] = 0
    content.extend(metadata)
    content.extend(b"\0" * (data_offset - len(content)))
    content.extend(payload)
    path.write_bytes(content)


def make_unityfs_bundle(path: Path, entries: dict[str, bytes], compression: str = "none") -> None:
    data = bytearray()
    directory = []
    for name, payload in entries.items():
        directory.append((name, len(data), len(payload)))
        data.extend(payload)
    compression_flag = {"none": 0, "lzma": 1}[compression]
    block_payload = bytes(data)
    compressed_block = lzma.compress(block_payload) if compression == "lzma" else block_payload
    block_info = bytearray(b"\0" * 16)
    block_info.extend(struct.pack(">I", 1))
    block_info.extend(struct.pack(">IIH", len(block_payload), len(compressed_block), compression_flag))
    block_info.extend(struct.pack(">I", len(directory)))
    for name, offset, size in directory:
        block_info.extend(struct.pack(">qqI", offset, size, 0))
        block_info.extend(name.encode("utf-8") + b"\0")
    compressed_info = lzma.compress(bytes(block_info)) if compression == "lzma" else bytes(block_info)
    header = bytearray()
    header.extend(b"UnityFS\0")
    header.extend(struct.pack(">I", 8))
    header.extend(b"5.x.x\0")
    header.extend(b"2022.3.67f2\0")
    declared_size_offset = len(header)
    header.extend(struct.pack(">QIII", 0, len(compressed_info), len(block_info), compression_flag))
    declared_size = len(header) + len(compressed_info) + len(compressed_block)
    struct.pack_into(">Q", header, declared_size_offset, declared_size)
    path.write_bytes(bytes(header) + compressed_info + compressed_block)


def make_unityfs_multiblock_bundle(
    path: Path,
    blocks: list[bytes],
    entries: list[tuple[str, int, int]],
    compression: str = "none",
) -> None:
    compression_flag = {"none": 0, "lzma": 1}[compression]
    compressed_blocks = [lzma.compress(block) if compression == "lzma" else block for block in blocks]
    block_info = bytearray(b"\0" * 16)
    block_info.extend(struct.pack(">I", len(blocks)))
    for block, compressed in zip(blocks, compressed_blocks, strict=True):
        block_info.extend(struct.pack(">IIH", len(block), len(compressed), compression_flag))
    block_info.extend(struct.pack(">I", len(entries)))
    for name, offset, size in entries:
        block_info.extend(struct.pack(">qqI", offset, size, 0))
        block_info.extend(name.encode("utf-8") + b"\0")
    compressed_info = lzma.compress(bytes(block_info)) if compression == "lzma" else bytes(block_info)
    header = bytearray()
    header.extend(b"UnityFS\0")
    header.extend(struct.pack(">I", 8))
    header.extend(b"5.x.x\0")
    header.extend(b"2022.3.67f2\0")
    declared_size_offset = len(header)
    header.extend(struct.pack(">QIII", 0, len(compressed_info), len(block_info), compression_flag))
    declared_size = len(header) + len(compressed_info) + sum(len(block) for block in compressed_blocks)
    struct.pack_into(">Q", header, declared_size_offset, declared_size)
    path.write_bytes(bytes(header) + compressed_info + b"".join(compressed_blocks))


def make_unity_bundle(path: Path) -> None:
    header = bytearray()
    header.extend(b"UnityFS\0")
    header.extend(struct.pack(">I", 8))
    header.extend(b"5.x.x\0")
    header.extend(b"2022.3.67f2\0")
    header.extend(struct.pack(">QIII", 256, 64, 128, 2))
    header.extend(b"CAB-abcdef0123456789\0")
    path.write_bytes(bytes(header).ljust(256, b"\0"))


def make_fsb5(path: Path) -> None:
    path.write_bytes(b"FSB5" + struct.pack("<IIIIII", 1, 2, 36, 12, 1024, 0) + b"\0" * 64)


def make_pak(path: Path, entries: dict[str, bytes]) -> None:
    payload = bytearray()
    directory = bytearray()
    for name, data in entries.items():
        offset = 12 + len(payload)
        payload.extend(data)
        directory.extend(name.encode("utf-8")[:55].ljust(56, b"\0"))
        directory.extend(struct.pack("<II", offset, len(data)))
    header = b"PACK" + struct.pack("<II", 12 + len(payload), len(directory))
    path.write_bytes(header + payload + directory)


def make_vpk(path: Path, entries: dict[str, bytes]) -> None:
    tree = bytearray()
    data = bytearray()
    by_ext: dict[str, list[tuple[str, bytes]]] = {}
    for name, payload in entries.items():
        stem, extension = name.rsplit(".", 1)
        by_ext.setdefault(extension, []).append((stem, payload))
    for extension, items in by_ext.items():
        tree.extend(extension.encode("utf-8") + b"\0")
        tree.extend(b" \0")
        for stem, payload in items:
            tree.extend(stem.encode("utf-8") + b"\0")
            tree.extend(struct.pack("<IHHIIH", 0, 0, 0x7FFF, len(data), len(payload), 0xFFFF))
            data.extend(payload)
        tree.extend(b"\0")
        tree.extend(b"\0")
    tree.extend(b"\0")
    path.write_bytes(struct.pack("<III", 0x55AA1234, 1, len(tree)) + tree + data)


def make_open_rpf(path: Path, entries: dict[str, bytes]) -> None:
    payload = bytearray()
    directory = bytearray()
    for name, data in entries.items():
        offset = 20 + len(payload)
        payload.extend(data)
        encoded = name.encode("utf-8")
        directory.extend(struct.pack(">H", len(encoded)))
        directory.extend(encoded)
        directory.extend(struct.pack(">QQ", offset, len(data)))
    header = b"RPF0" + struct.pack(">III", len(entries), 16 + len(payload), len(directory))
    path.write_bytes(header + payload + directory)


def make_unreal_pak(path: Path, entries: dict[str, bytes], encrypted: bool = False) -> None:
    payload = bytearray()
    directory = bytearray()
    for name, data in entries.items():
        offset = 16 + len(payload)
        payload.extend(data)
        encoded = name.encode("utf-8")
        directory.extend(struct.pack("<H", len(encoded)))
        directory.extend(encoded)
        directory.extend(struct.pack("<QQ", offset, len(data)))
    flags = 1 if encrypted else 0
    header = b"UPAK" + struct.pack("<IIII", len(entries), 20 + len(payload), len(directory), flags)
    path.write_bytes(header + payload + directory)


def unreal_fstring(value: str) -> bytes:
    raw = value.encode("utf-8") + b"\0"
    return struct.pack("<i", len(raw)) + raw


def make_real_unreal_pak(path: Path, entries: dict[str, bytes]) -> None:
    payload = bytearray()
    index = bytearray()
    index.extend(unreal_fstring("../../../Game/Content/"))
    index.extend(struct.pack("<i", len(entries)))
    for name, data in entries.items():
        offset = len(payload)
        payload.extend(data)
        index.extend(unreal_fstring(name))
        index.extend(struct.pack("<QQQI", offset, len(data), len(data), 0))
        index.extend(b"\0" * 20)
        index.extend(struct.pack("<I", 0))
        index.extend(b"\0")
        index.extend(struct.pack("<I", 0))
    index_offset = len(payload)
    footer = struct.pack("<IIQQ", 0x5A6F12E1, 8, index_offset, len(index)) + b"\0" * 20
    path.write_bytes(bytes(payload) + bytes(index) + footer)


def make_utoc_ucas(utoc: Path, entries: dict[str, bytes], encrypted: bool = False) -> None:
    ucas = utoc.with_suffix(".ucas")
    payload = bytearray()
    directory = bytearray()
    for name, data in entries.items():
        offset = len(payload)
        payload.extend(data)
        encoded = name.encode("utf-8")
        directory.extend(struct.pack("<H", len(encoded)))
        directory.extend(encoded)
        directory.extend(struct.pack("<QQ", offset, len(data)))
    flags = 1 if encrypted else 0
    header = b"UTOC" + struct.pack("<IIII", len(entries), 20, len(directory), flags)
    utoc.write_bytes(header + directory)
    ucas.write_bytes(payload)


def uint40(value: int) -> bytes:
    return value.to_bytes(5, "little")


def make_iostore_utoc_ucas(utoc: Path, entries: dict[bytes, bytes]) -> None:
    ucas = utoc.with_suffix(".ucas")
    payload = bytearray()
    chunk_ids = bytearray()
    offset_lengths = bytearray()
    for chunk_id, data in entries.items():
        if len(chunk_id) != 12:
            raise ValueError("chunk_id must be 12 bytes")
        offset = len(payload)
        payload.extend(data)
        chunk_ids.extend(chunk_id)
        offset_lengths.extend(uint40(offset))
        offset_lengths.extend(uint40(len(data)))
    header_size = 64
    header = bytearray(b"-==--==--==--==-")
    header.extend(bytes([1, 0, 0, 0]))
    header.extend(struct.pack("<IIIIIIIII", header_size, len(entries), 0, 12, 0, 0, 65536, 0, 1))
    header.extend(b"\0" * (header_size - len(header)))
    utoc.write_bytes(bytes(header) + bytes(chunk_ids) + bytes(offset_lengths))
    ucas.write_bytes(payload)


def _unity_typetree_nodes(nodes: list[tuple[str, str, int, int, bool] | tuple[str, str, int, int, bool, int]]) -> tuple[bytes, bytes]:
    strings = bytearray()
    offsets: dict[str, int] = {}

    def offset(value: str) -> int:
        if value not in offsets:
            offsets[value] = len(strings)
            strings.extend(value.encode("utf-8") + b"\0")
        return offsets[value]

    raw = bytearray()
    for index, node in enumerate(nodes):
        type_name, field_name, byte_size, depth, is_array = node[:5]
        flags = node[5] if len(node) > 5 else 0
        raw.extend(struct.pack(">hBBiiiii", 1, depth, int(is_array), offset(type_name), offset(field_name), byte_size, index, flags))
        raw.extend(b"\0" * 8)
    return bytes(raw), bytes(strings)


def make_unity_assets_v22_with_typetree(
    path: Path,
    payload: bytes,
    nodes: list[tuple[str, str, int, int, bool] | tuple[str, str, int, int, bool, int]],
    class_id: int = 49,
    externals: list[tuple[int, str]] | None = None,
) -> None:
    metadata = bytearray()
    metadata.extend(b"2022.3.67f2\0")
    metadata.extend(struct.pack(">i", 19))
    metadata.extend(b"\1")
    metadata.extend(struct.pack(">i", 1))
    metadata.extend(struct.pack(">i", class_id))
    metadata.extend(b"\0")
    metadata.extend(struct.pack(">h", -1))
    if class_id == 114:
        metadata.extend(b"\0" * 16)
    metadata.extend(b"\0" * 16)
    node_data, string_data = _unity_typetree_nodes(nodes)
    metadata.extend(struct.pack(">ii", len(nodes), len(string_data)))
    metadata.extend(node_data)
    metadata.extend(string_data)
    while len(metadata) % 4:
        metadata.extend(b"\0")
    metadata.extend(struct.pack(">i", 1))
    while len(metadata) % 4:
        metadata.extend(b"\0")
    metadata.extend(struct.pack(">qQIi", 1001, 0, len(payload), 0))
    metadata.extend(struct.pack(">i", len(externals or [])))
    for file_id, external_path in externals or []:
        encoded = external_path.encode("utf-8")
        metadata.extend(struct.pack(">iH", file_id, len(encoded)))
        metadata.extend(encoded)
    data_offset = max(512, (48 + len(metadata) + 15) & ~15)
    content = bytearray(48)
    struct.pack_into(">I", content, 8, 22)
    struct.pack_into(">Q", content, 16, len(metadata))
    struct.pack_into(">Q", content, 24, data_offset + len(payload))
    struct.pack_into(">Q", content, 32, data_offset)
    content[40] = 0
    content.extend(metadata)
    content.extend(b"\0" * (data_offset - len(content)))
    content.extend(payload)
    path.write_bytes(content)


def unity_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    payload = struct.pack(">I", len(raw)) + raw
    return payload + b"\0" * ((4 - len(payload) % 4) % 4)


def make_unity_pptr_asset(
    path: Path,
    file_id: int,
    path_id: int,
    *,
    class_id: int = 21,
    externals: list[tuple[int, str]] | None = None,
) -> None:
    make_unity_assets_v22_with_typetree(
        path,
        struct.pack(">iq", file_id, path_id),
        [
            ("Material", "Material", -1, 0, False),
            ("PPtr<Texture2D>", "m_Texture", 12, 1, False),
        ],
        class_id=class_id,
        externals=externals,
    )


def make_unity_streaming_asset(
    path: Path,
    class_id: int,
    resource_path: str,
    offset: int,
    size: int,
    *,
    alias_layout: bool = False,
) -> None:
    type_name = "AudioClip" if class_id == 83 else "Texture2D"
    payload = struct.pack(">QI", offset, size) + unity_string(resource_path)
    if alias_layout:
        nodes = [
            (type_name, type_name, -1, 0, False),
            ("StreamedResource", "m_StreamingInfo", -1, 1, False),
            ("UInt64", "m_Offset", 8, 2, False),
            ("UInt32", "m_Size", 4, 2, False),
            ("string", "m_Path", -1, 2, False),
        ]
    else:
        nodes = [
            (type_name, type_name, -1, 0, False),
            ("StreamingInfo", "m_StreamData", -1, 1, False),
        ]
    make_unity_assets_v22_with_typetree(path, payload, nodes, class_id=class_id)


def make_minimal_dotnet_pe(path: Path) -> None:
    data = bytearray(2048)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into("<HHIIIHH", data, coff, 0x14C, 1, 0, 0, 0, 224, 0x210E)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    data_directory = optional + 96
    struct.pack_into("<II", data, data_directory + 14 * 8, 0x2000, 72)
    section = optional + 224
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x400, 0x2000, 0x400, 0x200)
    clr = 0x200
    struct.pack_into("<IHHII", data, clr, 72, 2, 5, 0x2100, 0x200)
    struct.pack_into("<II", data, clr + 16, 1, 0x06000001)
    metadata = 0x300
    data[metadata : metadata + 4] = b"BSJB"
    struct.pack_into("<HHI", data, metadata + 4, 1, 1, 0)
    version = b"v4.0.30319\0"
    padded_len = (len(version) + 3) & ~3
    struct.pack_into("<I", data, metadata + 12, padded_len)
    data[metadata + 16 : metadata + 16 + len(version)] = version
    streams = metadata + 16 + padded_len
    struct.pack_into("<HH", data, streams, 0, 2)
    cursor = streams + 4
    strings = b"\0MyGame\0Player\0Update\0"
    player_index = strings.index(b"Player")
    namespace_index = strings.index(b"MyGame")
    update_index = strings.index(b"Update")
    tables = bytearray()
    tables.extend(struct.pack("<I", 0))
    tables.extend(bytes([2, 0, 0, 1]))
    tables.extend(struct.pack("<QQ", (1 << 2) | (1 << 6), 0))
    tables.extend(struct.pack("<II", 1, 1))
    tables.extend(struct.pack("<IHHHHH", 0, player_index, namespace_index, 0, 1, 1))
    tables.extend(struct.pack("<IHHHHH", 0, 0, 0, update_index, 0, 1))
    data[metadata + 0x40 : metadata + 0x40 + len(tables)] = tables
    data[metadata + 0x100 : metadata + 0x100 + len(strings)] = strings
    for name, offset, size in ((b"#~\0", 0x40, len(tables)), (b"#Strings\0", 0x100, len(strings))):
        struct.pack_into("<II", data, cursor, offset, size)
        data[cursor + 8 : cursor + 8 + len(name)] = name
        cursor = (cursor + 8 + len(name) + 3) & ~3
    path.write_bytes(data)


REQUIRED_EXTENSION_CATEGORIES = {
    ".unity": ("unity", "levels"),
    ".prefab": ("prefab", "data"),
    ".uasset": ("uasset", "data"),
    ".umap": ("umap", "levels"),
    ".uexp": ("uexp", "data"),
    ".ubulk": ("ubulk", "data"),
    ".godot": ("godot", "data"),
    ".tscn": ("tscn", "levels"),
    ".fbx": ("fbx", "models"),
    ".obj": ("obj", "models"),
    ".gltf": ("gltf", "models"),
    ".glb": ("glb", "models"),
    ".dds": ("dds", "textures"),
    ".tga": ("tga", "textures"),
    ".png": ("png", "textures"),
    ".jpg": ("jpg", "textures"),
    ".jpeg": ("jpg", "textures"),
    ".wav": ("wav", "audio"),
    ".ogg": ("ogg", "audio"),
    ".fsb": ("fsb", "audio"),
    ".bank": ("bank", "audio"),
    ".cs": ("cs", "scripts"),
    ".cpp": ("cpp", "scripts"),
    ".h": ("h", "scripts"),
    ".gd": ("gd", "scripts"),
    ".lua": ("lua", "scripts"),
    ".json": ("json", "data"),
    ".xml": ("xml", "data"),
    ".yaml": ("yaml", "data"),
    ".ini": ("ini", "data"),
    ".sav": ("sav", "data"),
    ".dat": ("dat", "data"),
    ".pak": ("pak", "containers"),
    ".vpk": ("vpk", "containers"),
    ".rpf": ("rpf", "containers"),
    ".utoc": ("utoc", "containers"),
    ".ucas": ("ucas", "containers"),
    ".assets": ("assets", "containers"),
    ".resource": ("resource", "containers"),
    ".lvl": ("lvl", "levels"),
    ".hlsl": ("hlsl", "shaders"),
    ".glsl": ("glsl", "shaders"),
    ".shadergraph": ("shadergraph", "shaders"),
    ".anim": ("anim", "data"),
    ".controller": ("controller", "data"),
    ".ttf": ("ttf", "data"),
    ".otf": ("otf", "data"),
    ".asset": ("asset", "data"),
    ".po": ("po", "data"),
    ".mo": ("mo", "data"),
    ".csv": ("csv", "data"),
    ".dll": ("dll", "runtime"),
    ".so": ("so", "runtime"),
    ".wasm": ("wasm", "bytecode"),
}


class DeinserterTests(unittest.TestCase):
    def test_identifies_valid_glb_and_rejects_corrupt_length_confidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            good = root / "model.bin"
            bad = root / "bad.glb"
            good.write_bytes(make_glb(b"abcd"))
            bad.write_bytes(b"glTF" + struct.pack("<II", 2, 9999))

            self.assertEqual(identify_file(good).identified_type, "glb")
            self.assertGreaterEqual(identify_file(good).confidence, 0.9)
            self.assertEqual(identify_file(bad).identified_type, "glb")
            self.assertLess(identify_file(bad).confidence, 0.8)

    def test_finds_and_extracts_embedded_png(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            container = root / "container.dat"
            out = root / "out"
            container.write_bytes(b"junk" + PNG_BYTES + b"tail")

            probe = probe_file(container)
            pngs = [candidate for candidate in probe.embedded_candidates if candidate.detected_type == "png"]
            self.assertEqual(len(pngs), 1)
            self.assertTrue(pngs[0].extractable)

            report = extract_path(container, out)
            self.assertEqual(len(report.extracted), 1)
            self.assertEqual(Path(report.extracted[0].output_path).read_bytes(), PNG_BYTES)

    def test_validated_binary_formats_are_identified_parsed_and_extracted(self) -> None:
        cases = {
            "image.jpg": ("jpg", "jpeg", make_jpeg()),
            "texture.dds": ("dds", "dds", make_dds()),
            "sprite.tga": ("tga", "tga", make_tga()),
            "audio.fsb": ("fsb", "fsb5", make_fsb5_valid()),
            "locale.mo": ("mo", "gnu_mo", make_mo()),
            "font.ttf": ("ttf", "sfnt", make_ttf()),
            "module.wasm": ("wasm", "wasm", make_wasm()),
            "lib.so": ("so", "elf", make_elf()),
            "tool.exe": ("exe", "pe", make_pe_exact()),
            "symbols.pdb": ("pdb", "pdb_msf", make_pdb()),
            "audio.bank": ("bank", "wwise_bank", make_bank()),
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            for name, (expected_type, expected_parser, payload) in cases.items():
                path = root / name
                path.write_bytes(payload)

                probe = probe_file(path)

                self.assertEqual(probe.identified_type, expected_type, name)
                self.assertEqual(probe.parse_info["parser"], expected_parser, name)
                self.assertGreaterEqual(probe.confidence, 0.85, name)

            report = decompile_path(root, out, ExtractionOptions(mode="full", embedded_scan=False, hash_policy="never"))

            self.assertEqual(report.summary["extracted_total"], len(cases))
            for name, (_expected_type, _expected_parser, payload) in cases.items():
                self.assertEqual((out / name).read_bytes(), payload, name)

    def test_embedded_validated_binary_formats_are_extractable(self) -> None:
        payloads = [
            make_jpeg(),
            make_dds(),
            make_tga(),
            make_fsb5_valid(),
            make_mo(),
            make_ttf(),
            make_wasm(),
            make_elf(),
            make_pe_exact(),
            make_pdb(),
            make_bank(),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            container = root / "container.bin"
            out = root / "out"
            container.write_bytes(b"lead" + b"gap".join(payloads) + b"tail")

            probe = probe_file(container)
            found_types = {candidate.detected_type for candidate in probe.embedded_candidates if candidate.extractable}

            self.assertTrue({"jpg", "dds", "tga", "fsb", "mo", "ttf", "wasm", "so", "exe", "pdb", "bank"}.issubset(found_types))

            report = extract_path(container, out, ExtractionOptions(mode="full", hash_policy="never"))

            extracted_payloads = [Path(item.output_path).read_bytes() for item in report.extracted]
            for payload in payloads:
                self.assertIn(payload, extracted_payloads)

    def test_model_and_shader_text_formats_have_structural_parsers(self) -> None:
        cases = {
            "scene.gltf": (
                "gltf",
                "gltf_json",
                b'{"asset":{"version":"2.0","generator":"test"},"nodes":[{}],"meshes":[{}]}\n',
            ),
            "mesh.obj": ("obj", "wavefront_obj", b"o Cube\nv 0 0 0\nvt 0 0\nvn 0 0 1\nf 1/1/1 1/1/1 1/1/1\n"),
            "model.fbx": (
                "fbx",
                "fbx",
                b"; FBX 7.4.0 project file\nFBXHeaderExtension:  {\n  FBXVersion: 7400\n}\nModel: 1, \"Cube\", \"Mesh\" {}\n",
            ),
            "shader.glsl": ("glsl", "shader_source", b"#version 330\nuniform mat4 model;\nvoid main() {}\n"),
            "effect.hlsl": ("hlsl", "shader_source", b"#include \"lighting.hlsl\"\nTexture2D albedo;\nvoid main() {}\n"),
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            for name, (expected_type, expected_parser, payload) in cases.items():
                path = root / name
                path.write_bytes(payload)

                probe = probe_file(path)

                self.assertEqual(probe.identified_type, expected_type, name)
                self.assertEqual(probe.parse_info["parser"], expected_parser, name)

            report = decompile_path(root, out, ExtractionOptions(mode="full", embedded_scan=False, hash_policy="never"))

            self.assertEqual(report.summary["extracted_total"], len(cases))
            for name, (_expected_type, _expected_parser, payload) in cases.items():
                self.assertEqual((out / name).read_bytes(), payload, name)

    def test_unreal_rpf_level_and_generic_data_have_conservative_parsers(self) -> None:
        cases = {
            "asset.uasset": ("uasset", "unreal_package", make_unreal_package()),
            "map.umap": ("umap", "unreal_package", make_unreal_package()),
            "archive.rpf": ("rpf", "rockstar_rpf", make_rpf()),
            "level.lvl": ("lvl", "level_artifact", b"LEVEL\0room=1\n"),
            "save.sav": ("sav", "generic_game_data", b"SAVE\0slot=1\n"),
            "blob.dat": ("dat", "generic_game_data", b"DATA\0payload\n"),
            "blob.data": ("dat", "generic_game_data", b"DATA2\0payload\n"),
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            for name, (expected_type, expected_parser, payload) in cases.items():
                path = root / name
                path.write_bytes(payload)

                probe = probe_file(path)

                self.assertEqual(probe.identified_type, expected_type, name)
                self.assertEqual(probe.parse_info["parser"], expected_parser, name)
                self.assertNotEqual(probe.parse_info["status"], "extension_only", name)

            report = decompile_path(root, out, ExtractionOptions(mode="full", embedded_scan=False, hash_policy="never"))

            self.assertEqual(report.summary["extracted_total"], len(cases))
            for name, (_expected_type, _expected_parser, payload) in cases.items():
                self.assertEqual((out / name).read_bytes(), payload, name)

    def test_wav_size_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wav = root / "sound.bin"
            corrupt = root / "bad.wav"
            wav.write_bytes(make_wav())
            corrupt.write_bytes(b"RIFF\xff\xff\xff\xffWAVE")

            self.assertEqual(identify_file(wav).identified_type, "wav")
            self.assertGreaterEqual(identify_file(wav).confidence, 0.9)
            self.assertEqual(identify_file(corrupt).identified_type, "wav")
            self.assertLess(identify_file(corrupt).confidence, 0.8)

    def test_zip_with_false_extension(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            zip_path = root / "archive.fake"
            with zipfile.ZipFile(zip_path, "w") as archive:
                archive.writestr("hello.txt", "hello")

            identified = identify_file(zip_path)
            self.assertEqual(identified.identified_type, "zip")
            self.assertGreaterEqual(identified.confidence, 0.9)

    def test_high_entropy_unknown_gets_hint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            blob = root / "blob.bin"
            blob.write_bytes(bytes(range(256)) * 32)

            probe = probe_file(blob)
            self.assertEqual(probe.identified_type, "unknown")
            self.assertIn("possible_encrypted_or_compressed", probe.compression_hints)

    def test_scan_folder_summary_and_clear_text_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.png").write_bytes(PNG_BYTES)
            (root / "script.pack").write_bytes(b"\x00" + b"function update_player_state() { return true; }\n" * 4 + b"\x00")

            report = scan_path(root)
            self.assertEqual(report.summary["files_total"], 2)
            self.assertEqual(report.summary["by_type"]["png"], 1)
            text_candidates = [
                candidate
                for item in report.files
                for candidate in item.embedded_candidates
                if candidate.detected_type == "script_text"
            ]
            self.assertTrue(text_candidates)

    def test_extract_manifest_is_written(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            (root / "a.png").write_bytes(PNG_BYTES)

            report = extract_path(root / "a.png", out, ExtractionOptions(naming="type_index"))
            manifest = out / "deinserter-manifest.json"
            self.assertTrue(manifest.exists())
            self.assertTrue((out / "deinserter-summary.json").exists())
            self.assertTrue((out / "extracted.jsonl").exists())
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["extracted_total"], len(report.extracted))

    def test_gpak_index_and_streaming_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gpak = root / "resources.gpak"
            out = root / "out"
            make_gpak(
                gpak,
                {
                    "data/items.gon": b"Name Catnip\nPower 3\n",
                    "textures/cursor/default.png": PNG_BYTES,
                },
            )

            identified = identify_file(gpak)
            self.assertEqual(identified.identified_type, "gpak")
            inventory = inspect_gpak(gpak)
            self.assertEqual(inventory["entry_count"], 2)
            self.assertEqual(inventory["category_counts"]["data"], 1)
            self.assertEqual(inventory["category_counts"]["textures"], 1)

            report = extract_path(gpak, out)
            self.assertEqual(report.summary["extracted_total"], 2)
            self.assertEqual((out / "data" / "items.gon").read_bytes(), b"Name Catnip\nPower 3\n")
            self.assertEqual((out / "textures" / "cursor" / "default.png").read_bytes(), PNG_BYTES)

    def test_large_file_plan_does_not_read_entire_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            big = root / "huge.bin"
            with big.open("wb") as handle:
                handle.seek(2 * 1024 * 1024)
                handle.write(b"\0")

            with patch("pathlib.Path.read_bytes", side_effect=AssertionError("read_bytes should not be called")):
                report = plan_path(big, options=ScanOptions(max_in_memory_bytes=1024, embedded_scan=False))

            self.assertEqual(report.summary["files_total"], 1)
            self.assertEqual(report.files_sample[0]["status"], "streaming_probe")

    def test_hash_policy_extracted_skips_hash_during_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "mod.lua"
            script.write_text("return 1\n", encoding="utf-8")

            with patch("deinserter.pipeline.sha256_file", side_effect=AssertionError("sha should be lazy")):
                report = plan_path(script, options=ScanOptions(hash_policy="extracted"))

            self.assertEqual(report.files_sample[0]["sha256"], "")

    def test_plan_writes_jsonl_summary_without_extracting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "plan"
            (root / "mod.lua").write_text("return 1\n", encoding="utf-8")

            report = plan_path(root / "mod.lua", out)

            self.assertTrue((out / "deinserter-summary.json").exists())
            self.assertTrue((out / "files.jsonl").exists())
            self.assertFalse((out / "mod.lua").exists())
            self.assertEqual(report.manifest_paths.summary, str(out / "deinserter-summary.json"))

    def test_selective_decompile_extracts_high_value_categories_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            (root / "mod.lua").write_text("return 1\n", encoding="utf-8")
            (root / "icon.png").write_bytes(PNG_BYTES)
            (root / "sound.wav").write_bytes(make_wav())

            report = decompile_path(
                root,
                out,
                ExtractionOptions(mode="selective", embedded_scan=False),
            )

            self.assertTrue((out / "mod.lua").exists())
            self.assertFalse((out / "icon.png").exists())
            self.assertFalse((out / "sound.wav").exists())
            self.assertEqual(report.summary["extracted_total"], 1)

    def test_max_output_budget_blocks_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gpak = root / "resources.gpak"
            out = root / "out"
            make_gpak(gpak, {"data/items.gon": b"x" * 100})

            report = decompile_path(
                gpak,
                out,
                ExtractionOptions(mode="full", max_output_bytes=10),
            )

            self.assertEqual(report.summary["extracted_total"], 0)
            self.assertEqual(report.summary["skipped_total"], 1)
            self.assertEqual(report.skipped_sample[0]["reason"], "blocked_output_budget")
            self.assertFalse((out / "data" / "items.gon").exists())

    def test_zip_container_uses_streaming_registry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            zip_path = root / "assets.zip"
            out = root / "out"
            with zipfile.ZipFile(zip_path, "w") as archive:
                archive.writestr("data/items.json", "{}")
                archive.writestr("audio/sound.wav", make_wav())

            report = decompile_path(
                zip_path,
                out,
                ExtractionOptions(mode="selective"),
            )

            self.assertTrue((out / "data" / "items.json").exists())
            self.assertFalse((out / "audio" / "sound.wav").exists())
            self.assertEqual(report.summary["containers_total"], 1)
            self.assertEqual(report.summary["extracted_total"], 1)

    def test_pak_and_vpk_containers_extract_entries_by_range(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pak = root / "assets.pak"
            vpk = root / "assets_dir.vpk"
            pak_out = root / "pak_out"
            vpk_out = root / "vpk_out"
            make_pak(pak, {"data/items.json": b"{}", "scripts/main.lua": b"return 1\n"})
            make_vpk(vpk, {"items.json": b"{}", "main.lua": b"return 1\n"})

            pak_report = decompile_path(pak, pak_out, ExtractionOptions(mode="full", hash_policy="never"))
            vpk_report = decompile_path(vpk, vpk_out, ExtractionOptions(mode="full", hash_policy="never"))

            self.assertEqual(pak_report.summary["containers_total"], 1)
            self.assertEqual(vpk_report.summary["containers_total"], 1)
            self.assertEqual((pak_out / "data" / "items.json").read_bytes(), b"{}")
            self.assertEqual((pak_out / "scripts" / "main.lua").read_bytes(), b"return 1\n")
            self.assertEqual((vpk_out / "items.json").read_bytes(), b"{}")
            self.assertEqual((vpk_out / "main.lua").read_bytes(), b"return 1\n")

    def test_deep_versioned_containers_emit_entries_and_extract_ranges(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rpf = root / "open.rpf"
            upak = root / "content.pak"
            utoc = root / "global.utoc"
            make_open_rpf(rpf, {"data/rpf.json": b'{"rpf":true}'})
            make_unreal_pak(upak, {"Game/Data/item.json": b'{"pak":true}'})
            make_utoc_ucas(utoc, {"chunk.bin": b"ucas-payload"})

            for archive in (rpf, upak, utoc):
                out = root / f"out_{archive.stem}"
                report = decompile_path(archive, out, ExtractionOptions(mode="full", hash_policy="never"))
                entries = [json.loads(line) for line in (out / "container-entries.jsonl").read_text(encoding="utf-8").splitlines()]
                self.assertEqual(report.summary["containers_total"], 1, archive.name)
                self.assertEqual(report.summary["deep_container_entries_total"], 1, archive.name)
                self.assertEqual(len(entries), 1, archive.name)
                self.assertTrue(Path(report.extracted_sample[0]["output_path"]).exists(), archive.name)

    def test_real_unreal_pak_layout_extracts_uncompressed_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pak = root / "content.pak"
            out = root / "out"
            make_real_unreal_pak(pak, {"Data/item.json": b'{"real_pak":true}'})

            report = decompile_path(pak, out, ExtractionOptions(mode="full", hash_policy="never"))

            entries = [json.loads(line) for line in (out / "container-entries.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(report.summary["containers_total"], 1)
            self.assertEqual(report.summary["unreal_entries_total"], 1)
            self.assertEqual(entries[0]["name"], "Game/Content/Data/item.json")
            self.assertEqual((out / "Game" / "Content" / "Data" / "item.json").read_bytes(), b'{"real_pak":true}')

    def test_real_iostore_utoc_ucas_layout_extracts_uncompressed_chunks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            utoc = root / "global.utoc"
            out = root / "out"
            chunk_id = bytes.fromhex("00112233445566778899aabb")
            make_iostore_utoc_ucas(utoc, {chunk_id: b"real-iostore-payload"})

            report = decompile_path(utoc, out, ExtractionOptions(mode="full", hash_policy="never"))

            entries = [json.loads(line) for line in (out / "container-entries.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(report.summary["containers_total"], 1)
            self.assertEqual(report.summary["unreal_entries_total"], 1)
            self.assertEqual(entries[0]["name"], f"{chunk_id.hex()}.ucasbin")
            self.assertEqual(Path(report.extracted_sample[0]["output_path"]).read_bytes(), b"real-iostore-payload")

    def test_deep_container_scan_can_be_disabled_for_versioned_handlers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rpf = root / "open.rpf"
            make_open_rpf(rpf, {"data/rpf.json": b"{}"})

            report = decompile_path(
                rpf,
                root / "out",
                ExtractionOptions(mode="full", hash_policy="never", container_deep_scan=False),
            )

            self.assertEqual(report.summary["containers_total"], 0)
            self.assertEqual(report.summary["deep_container_entries_total"], 0)

    def test_plan_reusing_output_dir_truncates_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "mod.lua"
            out = root / "plan"
            script.write_text("return 1\n", encoding="utf-8")

            plan_path(script, out)
            plan_path(script, out)

            lines = (out / "files.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)

    def test_output_dir_inside_input_is_not_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "plan"
            (root / "mod.lua").write_text("return 1\n", encoding="utf-8")

            plan_path(root, out)

            files = [json.loads(line) for line in (out / "files.jsonl").read_text(encoding="utf-8").splitlines()]
            paths = [item["path"] for item in files]
            self.assertEqual(len(paths), 1)
            self.assertEqual(paths[0], str(root / "mod.lua"))
            self.assertFalse(any("files.jsonl" in path or "deinserter-summary.json" in path for path in paths))

    def test_discovery_sorting_can_be_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "z.lua").write_text("return 1\n", encoding="utf-8")
            (root / "a.lua").write_text("return 2\n", encoding="utf-8")

            from deinserter.pipeline import _discover

            sorted_files = list(_discover(root, True, sort_paths=True))
            streamed_files = list(_discover(root, True, sort_paths=False))

            self.assertEqual(sorted_files, sorted(sorted_files))
            self.assertCountEqual(streamed_files, sorted_files)

    def test_extract_path_container_legacy_warns_when_sample_is_truncated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gpak = root / "resources.gpak"
            out = root / "out"
            make_gpak(gpak, {f"data/item_{index}.json": b"{}" for index in range(55)})

            report = extract_path(gpak, out)

            self.assertEqual(report.summary["extracted_total"], 55)
            self.assertEqual(len(report.extracted), 50)
            self.assertTrue(any("legacy_extract_path_container_report_truncated" in warning for warning in report.warnings))
            self.assertTrue((out / "extracted.jsonl").exists())

    def test_container_entry_payload_validation_blocks_invalid_known_formats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gpak = root / "resources.gpak"
            out = root / "out"
            make_gpak(gpak, {"textures/bad.png": b"not a png"})

            report = decompile_path(gpak, out, ExtractionOptions(mode="full", hash_policy="never"))

            self.assertEqual(report.summary["extracted_total"], 0)
            self.assertEqual(report.summary["skipped_total"], 1)
            self.assertEqual(report.skipped_sample[0]["reason"], "failed_output_validation")
            self.assertFalse((out / "textures" / "bad.png").exists())

    def test_container_entry_payload_validation_can_be_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gpak = root / "resources.gpak"
            out = root / "out"
            make_gpak(gpak, {"textures/bad.png": b"not a png"})

            report = decompile_path(
                gpak,
                out,
                ExtractionOptions(mode="full", hash_policy="never", validate_outputs=False),
            )

            records = [json.loads(line) for line in (out / "extracted.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(report.summary["extracted_total"], 1)
            self.assertEqual(records[0]["validation_status"], "not_validated")
            self.assertEqual((out / "textures" / "bad.png").read_bytes(), b"not a png")

    def test_invalid_gpak_is_recorded_as_open_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gpak = root / "broken.gpak"
            out = root / "out"
            gpak.write_bytes(b"bad")

            report = decompile_path(gpak, out, ExtractionOptions(mode="manifest_only"))

            self.assertEqual(report.summary["failed_total"], 1)
            self.assertIn("missing GPAK entry count", report.failed_sample[0]["reason"])

    def test_gpak_index_is_parsed_once_per_decompilation_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gpak = root / "resources.gpak"
            out = root / "out"
            make_gpak(gpak, {"data/items.gon": b"Name Catnip\n"})

            from deinserter.gpak import parse_gpak_index as real_parse

            calls = 0

            def counted_parse(path: str | Path):
                nonlocal calls
                calls += 1
                return real_parse(path)

            with patch("deinserter.containers.parse_gpak_index", side_effect=counted_parse):
                decompile_path(gpak, out, ExtractionOptions(mode="manifest_only"))

            self.assertEqual(calls, 1)

    def test_manifest_reader_loads_and_filters_jsonl_streams(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            gpak = root / "resources.gpak"
            make_gpak(gpak, {"data/items.json": b"{}", "audio/sound.wav": make_wav()})

            decompile_path(gpak, out, ExtractionOptions(mode="full", hash_policy="never"))

            reader = read_manifest(out)
            summary = reader.load_summary()
            files = list(reader.iter_files(category="containers"))
            data_entries = list(reader.iter_container_entries(category="data", type="json"))
            extracted = list(reader.iter_extracted())
            helper_records = list(iter_manifest_records(out, "container_entries", type="wav"))

            self.assertEqual(load_manifest_summary(out)["summary"]["containers_total"], 1)
            self.assertEqual(summary["summary"]["containers_total"], 1)
            self.assertEqual(len(files), 1)
            self.assertEqual(data_entries[0]["name"], "data/items.json")
            self.assertEqual(len(extracted), 2)
            self.assertEqual({item["validation_status"] for item in extracted}, {"valid"})
            self.assertEqual(helper_records[0]["name"], "audio/sound.wav")

    def test_required_game_extensions_are_identified_and_classified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index, (extension, (expected_type, expected_category)) in enumerate(REQUIRED_EXTENSION_CATEGORIES.items()):
                path = root / f"sample_{index}{extension}"
                path.write_bytes(f"name: sample_{index}\n".encode("utf-8"))

                identified = identify_file(path, ScanOptions(embedded_scan=False))

                self.assertEqual(identified.identified_type, expected_type, extension)
                self.assertEqual(identified.category, expected_category, extension)
                self.assertNotEqual(identified.reason, "unclassified", extension)

    def test_full_decompile_reconstructs_all_required_extension_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_dir = root / "input"
            out = root / "out"
            input_dir.mkdir()
            expected_payloads: dict[Path, bytes] = {}
            for index, extension in enumerate(REQUIRED_EXTENSION_CATEGORIES):
                path = input_dir / f"sample_{index}{extension}"
                payload = f"payload for {extension}\n".encode("utf-8")
                path.write_bytes(payload)
                expected_payloads[path] = payload

            report = decompile_path(
                input_dir,
                out,
                ExtractionOptions(mode="full", embedded_scan=False, hash_policy="never"),
            )

            self.assertEqual(report.summary["files_total"], len(REQUIRED_EXTENSION_CATEGORIES))
            self.assertEqual(report.summary["extracted_total"], len(REQUIRED_EXTENSION_CATEGORIES))
            for source, payload in expected_payloads.items():
                self.assertEqual((out / source.name).read_bytes(), payload, source.suffix)

    def test_unity_runtime_extensions_found_in_repo_are_classified(self) -> None:
        cases = {
            "asset.bundle": "containers",
            "resources.assets.resS": "containers",
            "settings.config": "data",
            "table.tsv": "data",
            "symbols.pdb": "runtime",
            "game.exe": "runtime",
            "globalgamemanagers": "containers",
            "unity default resources": "containers",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, expected_category in cases.items():
                path = root / name
                path.write_text("name: value\n", encoding="utf-8")

                identified = identify_file(path, ScanOptions(embedded_scan=False))

                self.assertEqual(identified.category, expected_category, name)
                self.assertNotEqual(identified.reason, "unclassified", name)

    def test_unity_assets_bundle_resource_and_dotnet_are_parsed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            assets = root / "resources.assets"
            bundle = root / "localization.bundle"
            resource = root / "audio.resource"
            assembly = root / "Assembly-CSharp.dll"
            make_unity_assets_v22(assets)
            make_unity_bundle(bundle)
            make_fsb5(resource)
            make_minimal_dotnet_pe(assembly)

            assets_probe = probe_file(assets, ScanOptions(max_in_memory_bytes=0, embedded_scan=False))
            bundle_probe = probe_file(bundle, ScanOptions(max_in_memory_bytes=0, embedded_scan=False))
            resource_probe = probe_file(resource, ScanOptions(max_in_memory_bytes=0, embedded_scan=False))
            assembly_probe = probe_file(assembly, ScanOptions(max_in_memory_bytes=0, embedded_scan=False))

            self.assertEqual(assets_probe.parse_info["parser"], "unity_serialized_file")
            self.assertEqual(assets_probe.parse_info["format_version"], 22)
            self.assertEqual(assets_probe.parse_info["unity_version"], "2022.3.67f2")
            self.assertEqual(bundle_probe.parse_info["parser"], "unity_bundle")
            self.assertEqual(bundle_probe.parse_info["signature"], "UnityFS")
            self.assertEqual(bundle_probe.parse_info["compression"], "lz4")
            self.assertEqual(resource_probe.parse_info["parser"], "fsb5")
            self.assertEqual(resource_probe.parse_info["sample_count"], 2)
            self.assertEqual(assembly_probe.parse_info["parser"], "pe")
            self.assertTrue(assembly_probe.parse_info["is_dotnet"])
            self.assertEqual(assembly_probe.parse_info["dotnet_metadata"]["version"], "v4.0.30319")
            self.assertEqual(
                [stream["name"] for stream in assembly_probe.parse_info["dotnet_metadata"]["streams"]],
                ["#~", "#Strings"],
            )

    def test_plan_jsonl_includes_parse_info_for_identified_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            asset = root / "resources.assets"
            make_unity_assets_v22(asset)

            plan_path(asset, out, ScanOptions(max_in_memory_bytes=0, embedded_scan=False))

            [file_item] = [json.loads(line) for line in (out / "files.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(file_item["parse_info"]["parser"], "unity_serialized_file")
            self.assertIn(file_item["parse_info"]["status"], {"parsed_header", "parsed"})

    def test_lz4_block_decoder_handles_synthetic_match(self) -> None:
        self.assertEqual(decompress_lz4_block(bytes([0x35]) + b"abc" + b"\x03\x00", 12), b"abcabcabcabc")

    def test_unityfs_none_and_lzma_bundles_parse_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plain = root / "plain.bundle"
            compressed = root / "compressed.bundle"
            make_unityfs_bundle(plain, {"CAB-test/resources.assets": b"asset"}, "none")
            make_unityfs_bundle(compressed, {"CAB-test/resources.assets": b"asset"}, "lzma")

            plain_info = inspect_bundle(plain)
            compressed_info = inspect_bundle(compressed)

            self.assertEqual(plain_info.status, "parsed")
            self.assertEqual(plain_info.entries[0].name, "CAB-test/resources.assets")
            self.assertEqual(compressed_info.status, "parsed")
            self.assertEqual(compressed_info.compression, "lzma")

    def test_unityfs_none_range_extraction_reads_slice_without_decompressing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / "plain.bundle"
            out = root / "out"
            blocks = [b"prefix", b"0123456789", b"suffix"]
            make_unityfs_multiblock_bundle(bundle, blocks, [("slice.bin", len(blocks[0]) + 2, 4)], "none")
            info = inspect_bundle(bundle)

            with patch("deinserter.unity.bundle._decompress", wraps=unity_bundle._decompress) as decompress:
                output, digest = extract_bundle_entry(bundle, info, info.entries[0], out, hash_output=False)

            self.assertEqual(output.read_bytes(), b"2345")
            self.assertEqual(digest, "")
            self.assertEqual(decompress.call_count, 0)

    def test_unityfs_compressed_range_extraction_skips_non_overlapping_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / "compressed.bundle"
            out = root / "out"
            blocks = [b"a" * 32, b"target-payload", b"z" * 32]
            make_unityfs_multiblock_bundle(bundle, blocks, [("target.bin", len(blocks[0]), len(blocks[1]))], "lzma")
            info = inspect_bundle(bundle)

            with patch("deinserter.unity.bundle._decompress", wraps=unity_bundle._decompress) as decompress:
                output, digest = extract_bundle_entry(bundle, info, info.entries[0], out, hash_output=False)

            self.assertEqual(output.read_bytes(), b"target-payload")
            self.assertEqual(digest, "")
            self.assertEqual(decompress.call_count, 1)

    def test_plan_writes_unity_objects_jsonl_for_serialized_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            asset = root / "resources.assets"
            make_unity_assets_v22_with_object(asset, b"quest text\n")

            report = plan_path(asset, out, ScanOptions(max_in_memory_bytes=0, embedded_scan=False))

            objects = [json.loads(line) for line in (out / "objects.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(report.summary["unity_objects_total"], 1)
            self.assertEqual(objects[0]["type_name"], "TextAsset")
            self.assertEqual(objects[0]["path_id"], 1001)

    def test_unity_typetree_decodes_fields_references_and_external_resources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            asset = root / "resources.assets"
            external = root / "texture.resS"
            external.write_bytes(b"0123456789abcdef")
            path_payload = b"texture.resS"
            streaming_payload = struct.pack(">QI", 4, 6) + struct.pack(">I", len(path_payload)) + path_payload
            while len(streaming_payload) % 4:
                streaming_payload += b"\0"
            make_unity_assets_v22_with_typetree(
                asset,
                streaming_payload,
                [
                    ("Texture2D", "Texture2D", -1, 0, False),
                    ("StreamingInfo", "m_StreamData", -1, 1, False),
                ],
                class_id=28,
            )

            report = decompile_path(
                asset,
                out,
                ExtractionOptions(mode="selective", max_in_memory_bytes=0, embedded_scan=False, hash_policy="never"),
            )

            objects = [json.loads(line) for line in (out / "objects.jsonl").read_text(encoding="utf-8").splitlines()]
            resources = [
                json.loads(line) for line in (out / "unity-external-resources.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(objects[0]["decode_status"], "decoded")
            self.assertEqual(resources[0]["status"], "extracted")
            self.assertEqual(resources[0]["resource_kind"], "texture")
            self.assertEqual(resources[0]["resolution_status"], "extracted")
            self.assertEqual(objects[0]["streaming_infos"][0]["owner_type_name"], "Texture2D")
            self.assertEqual(Path(resources[0]["output_path"]).read_bytes(), b"456789")
            self.assertEqual(report.summary["unity_external_resources_total"], 1)

    def test_unity_streaming_info_uses_alias_layout_and_external_roots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            external_root = root / "external"
            external_root.mkdir()
            (external_root / "texture.resS").write_bytes(b"root-texture-payload")
            asset = root / "texture.assets"
            make_unity_streaming_asset(asset, 28, "texture.resS", 5, 7, alias_layout=True)

            report = decompile_path(
                asset,
                out,
                ExtractionOptions(
                    mode="selective",
                    max_in_memory_bytes=0,
                    embedded_scan=False,
                    hash_policy="never",
                    unity_external_resource_roots=[str(external_root)],
                ),
            )

            resources = [
                json.loads(line) for line in (out / "unity-external-resources.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            reconstructed = [
                json.loads(line) for line in (out / "reconstructed.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            sidecar = json.loads(Path(reconstructed[0]["sidecar_path"]).read_text(encoding="utf-8"))
            self.assertEqual(report.summary["unity_external_resources_total"], 1)
            self.assertEqual(resources[0]["status"], "extracted")
            self.assertEqual(resources[0]["resource_kind"], "texture")
            self.assertEqual(Path(resources[0]["output_path"]).read_bytes(), b"texture")
            self.assertEqual(sidecar["streaming_infos"][0]["resolution_status"], "extracted")
            self.assertEqual(sidecar["streaming_infos"][0]["resolved_path"], str((external_root / "texture.resS").resolve()))

    def test_unity_streaming_info_fallbacks_and_failures_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            fallback = root / "empty.assets.resS"
            fallback.write_bytes(b"fallback-data")
            make_unity_streaming_asset(root / "empty.assets", 28, "", 0, 8)
            (root / "short.resS").write_bytes(b"tiny")
            make_unity_streaming_asset(root / "invalid.assets", 28, "short.resS", 2, 20)
            make_unity_streaming_asset(root / "zero.assets", 28, "short.resS", 0, 0)
            make_unity_streaming_asset(root / "missing.assets", 28, "ghost.resS", 0, 4)

            report = plan_path(root, out, ScanOptions(max_in_memory_bytes=0, embedded_scan=False))

            resources = [
                json.loads(line) for line in (out / "unity-external-resources.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            statuses = {Path(item["source_file"]).name: item["resolution_status"] for item in resources}
            self.assertEqual(report.summary["unity_external_resources_total"], 4)
            self.assertEqual(statuses["empty.assets"], "resolved")
            self.assertEqual(statuses["invalid.assets"], "invalid_range")
            self.assertEqual(statuses["zero.assets"], "zero_size")
            self.assertEqual(statuses["missing.assets"], "missing_resource")
            self.assertFalse(any("output_path" in item for item in resources))

    def test_unity_audio_clip_streaming_info_preserves_external_audio_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            fsb = b"FSB5" + b"\0" * 32
            (root / "voice.resource").write_bytes(b"xx" + fsb + b"tail")
            (root / "music.ress").write_bytes(b"music-stream")
            make_unity_streaming_asset(root / "voice.assets", 83, "voice.resource", 2, len(fsb))
            make_unity_streaming_asset(root / "music.assets", 83, "music.ress", 0, 5)

            report = decompile_path(
                root,
                out,
                ExtractionOptions(mode="selective", max_in_memory_bytes=0, embedded_scan=False, hash_policy="never"),
            )

            resources = [
                json.loads(line) for line in (out / "unity-external-resources.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            by_asset = {Path(item["source_file"]).name: item for item in resources}
            self.assertEqual(report.summary["unity_external_resources_total"], 2)
            self.assertEqual(by_asset["voice.assets"]["resource_kind"], "audio")
            self.assertEqual(Path(by_asset["voice.assets"]["output_path"]).read_bytes(), fsb)
            self.assertEqual(Path(by_asset["music.assets"]["output_path"]).read_bytes(), b"music")

    def test_unity_streaming_info_budget_block_keeps_manifest_without_extracting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            (root / "large.resS").write_bytes(b"large-payload")
            asset = root / "large.assets"
            make_unity_streaming_asset(asset, 28, "large.resS", 0, 5)

            report = decompile_path(
                asset,
                out,
                ExtractionOptions(
                    mode="selective",
                    max_in_memory_bytes=0,
                    embedded_scan=False,
                    hash_policy="never",
                    max_output_bytes=1,
                ),
            )

            resources = [
                json.loads(line) for line in (out / "unity-external-resources.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(resources[0]["resolution_status"], "blocked_budget")
            self.assertEqual(report.summary["extracted_total"], 0)
            self.assertGreaterEqual(report.summary["skipped_total"], 1)

    def test_full_decompile_preserves_unity_resource_blob_and_extracts_streaming_range(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            resource = root / "texture.resS"
            resource.write_bytes(b"0123456789")
            asset = root / "texture.assets"
            make_unity_streaming_asset(asset, 28, "texture.resS", 3, 4)

            report = decompile_path(
                root,
                out,
                ExtractionOptions(mode="full", max_in_memory_bytes=0, embedded_scan=False, hash_policy="never"),
            )

            resources = [
                json.loads(line) for line in (out / "unity-external-resources.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual((out / "texture.resS").read_bytes(), b"0123456789")
            self.assertEqual(Path(resources[0]["output_path"]).read_bytes(), b"3456")
            self.assertGreaterEqual(report.summary["extracted_total"], 2)

    def test_unity_semantic_reconstructors_emit_class_specific_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"

            texture_stream = root / "texture.resS"
            texture_stream.write_bytes(b"texture-stream")
            texture_payload = struct.pack(">iiii", 64, 32, 12, 2)
            texture_payload += struct.pack(">QI", 0, 7) + unity_string("texture.resS")
            make_unity_assets_v22_with_typetree(
                root / "texture.assets",
                texture_payload,
                [
                    ("Texture2D", "Texture2D", -1, 0, False),
                    ("int", "m_Width", 4, 1, False),
                    ("int", "m_Height", 4, 1, False),
                    ("int", "m_TextureFormat", 4, 1, False),
                    ("int", "m_MipCount", 4, 1, False),
                    ("StreamingInfo", "m_StreamData", -1, 1, False),
                ],
                class_id=28,
            )

            audio_payload = b"FSB5" + b"\0" * 32
            (root / "voice.resource").write_bytes(audio_payload)
            clip_payload = struct.pack(">fiii", 1.5, 2, 44100, 7)
            clip_payload += struct.pack(">QI", 0, len(audio_payload)) + unity_string("voice.resource")
            make_unity_assets_v22_with_typetree(
                root / "audio.assets",
                clip_payload,
                [
                    ("AudioClip", "AudioClip", -1, 0, False),
                    ("float", "m_Length", 4, 1, False),
                    ("int", "m_Channels", 4, 1, False),
                    ("int", "m_Frequency", 4, 1, False),
                    ("int", "m_CompressionFormat", 4, 1, False),
                    ("StreamingInfo", "m_Resource", -1, 1, False),
                ],
                class_id=83,
            )

            mesh_payload = struct.pack(">i", 3)
            mesh_payload += struct.pack(">fffffffff", 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0)
            mesh_payload += struct.pack(">iiii", 3, 0, 1, 2)
            make_unity_assets_v22_with_typetree(
                root / "mesh.assets",
                mesh_payload,
                [
                    ("Mesh", "Mesh", -1, 0, False),
                    ("vector", "m_Vertices", -1, 1, False),
                    ("Array", "Array", -1, 2, True),
                    ("int", "size", 4, 3, False),
                    ("Vector3f", "data", 12, 3, False),
                    ("float", "x", 4, 4, False),
                    ("float", "y", 4, 4, False),
                    ("float", "z", 4, 4, False),
                    ("vector", "m_Indices", -1, 1, False),
                    ("Array", "Array", -1, 2, True),
                    ("int", "size", 4, 3, False),
                    ("int", "data", 4, 3, False),
                ],
                class_id=43,
            )

            make_unity_assets_v22_with_object(root / "target_texture.assets", b"target texture", class_id=28)
            make_unity_pptr_asset(root / "material.assets", 1, 1001, class_id=21, externals=[(1, "target_texture.assets")])

            behaviour_payload = struct.pack(">iiiii", 2, 2, 2, 4, 1) + struct.pack(">q", 1001)
            make_unity_assets_v22_with_typetree(
                root / "behaviour.assets",
                behaviour_payload,
                [
                    ("MonoBehaviour", "MonoBehaviour", -1, 0, False),
                    ("int", "m_Count", 4, 1, False),
                    ("vector", "m_Values", -1, 1, False),
                    ("Array", "Array", -1, 2, True),
                    ("int", "size", 4, 3, False),
                    ("int", "data", 4, 3, False),
                    ("PPtr<Texture2D>", "m_Texture", 12, 1, False),
                ],
                class_id=114,
                externals=[(1, "target_texture.assets")],
            )

            report = decompile_path(
                root,
                out,
                ExtractionOptions(mode="selective", max_in_memory_bytes=0, embedded_scan=False, hash_policy="never"),
            )

            reconstructed = [
                json.loads(line) for line in (out / "reconstructed.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            by_class = {item["class_id"]: item for item in reconstructed if item.get("semantic_type")}
            self.assertEqual({21, 28, 43, 83, 114}.issubset(by_class.keys()), True)
            self.assertEqual(by_class[28]["semantic_status"], "decoded")
            self.assertEqual(Path(by_class[28]["payload_output_path"]).read_bytes(), b"texture")
            self.assertEqual(by_class[83]["external_outputs_sample"][0]["resource_kind"], "audio")

            texture_sidecar = json.loads(Path(by_class[28]["semantic_sidecar_path"]).read_text(encoding="utf-8"))
            audio_sidecar = json.loads(Path(by_class[83]["semantic_sidecar_path"]).read_text(encoding="utf-8"))
            mesh_sidecar = json.loads(Path(by_class[43]["semantic_sidecar_path"]).read_text(encoding="utf-8"))
            material_sidecar = json.loads(Path(by_class[21]["semantic_sidecar_path"]).read_text(encoding="utf-8"))
            behaviour_sidecar = json.loads(Path(by_class[114]["semantic_sidecar_path"]).read_text(encoding="utf-8"))

            self.assertEqual(texture_sidecar["semantic"]["metadata"]["width"], 64)
            self.assertEqual(audio_sidecar["semantic"]["metadata"]["frequency"], 44100)
            self.assertEqual(mesh_sidecar["semantic"]["metadata"]["vertex_count"], 3)
            self.assertTrue(mesh_sidecar["semantic"]["exported_files"])
            self.assertIn("f 1 2 3", Path(mesh_sidecar["semantic"]["exported_files"][0]["output_path"]).read_text(encoding="utf-8"))
            self.assertEqual(material_sidecar["semantic"]["metadata"]["texture_references"][0]["target_type_name"], "Texture2D")
            self.assertEqual(behaviour_sidecar["semantic"]["fields"]["m_Values"], [2, 4])
            self.assertGreaterEqual(report.summary["unity_reconstructed_total"], 5)

    def test_unity_pptr_references_are_written_to_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            asset = root / "material.assets"
            make_unity_pptr_asset(asset, 0, 1001)

            report = plan_path(asset, out, ScanOptions(max_in_memory_bytes=0, embedded_scan=False))

            references = [
                json.loads(line) for line in (out / "unity-references.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(report.summary["unity_references_total"], 1)
            self.assertTrue(references[0]["resolved"])
            self.assertEqual(references[0]["resolution_status"], "resolved_internal")
            self.assertEqual(references[0]["target_path_id"], 1001)

    def test_unity_project_index_resolves_external_pptr_between_assets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            main = root / "a_main.assets"
            shared = root / "z_shared.assets"
            make_unity_pptr_asset(main, 1, 1001, externals=[(1, "z_shared.assets")])
            make_unity_assets_v22_with_object(shared, b"shared texture metadata", class_id=49)

            report = decompile_path(
                root,
                out,
                ExtractionOptions(mode="selective", max_in_memory_bytes=0, embedded_scan=False, hash_policy="never"),
            )

            references = [
                json.loads(line) for line in (out / "unity-references.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            objects = [json.loads(line) for line in (out / "objects.jsonl").read_text(encoding="utf-8").splitlines()]
            reconstructed = [
                json.loads(line) for line in (out / "reconstructed.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            material_record = next(item for item in reconstructed if item["class_id"] == 21)
            material_sidecar = json.loads(Path(material_record["sidecar_path"]).read_text(encoding="utf-8"))
            material_object = next(item for item in objects if item["class_id"] == 21)

            self.assertEqual(report.summary["unity_indexed_files_total"], 2)
            self.assertEqual(report.summary["unity_indexed_objects_total"], 2)
            self.assertEqual(report.summary["unity_references_total"], 1)
            self.assertEqual(report.summary["unity_references_resolved_total"], 1)
            self.assertEqual(report.summary["unity_references_unresolved_total"], 0)
            self.assertTrue(references[0]["resolved"])
            self.assertEqual(references[0]["resolution_status"], "resolved_external")
            self.assertEqual(Path(references[0]["target_file"]), shared.resolve())
            self.assertEqual(references[0]["target_path_id"], 1001)
            self.assertEqual(references[0]["target_type_name"], "TextAsset")
            self.assertEqual(references[0]["target_class_id"], 49)
            self.assertEqual(material_object["pptr_references"][0]["resolution_status"], "resolved_external")
            self.assertEqual(material_sidecar["pptr_references"][0]["target_type_name"], "TextAsset")

    def test_unity_project_index_marks_external_pptr_failures_conservatively(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            make_unity_assets_v22_with_object(root / "z_shared.assets", b"shared", class_id=49)
            make_unity_pptr_asset(root / "missing_path.assets", 1, 9999, externals=[(1, "z_shared.assets")])
            make_unity_pptr_asset(root / "missing_file.assets", 1, 1001, externals=[(1, "ghost.assets")])
            (root / "one").mkdir()
            (root / "two").mkdir()
            make_unity_assets_v22_with_object(root / "one" / "shared.assets", b"one", class_id=49)
            make_unity_assets_v22_with_object(root / "two" / "shared.assets", b"two", class_id=49)
            make_unity_pptr_asset(root / "ambiguous.assets", 1, 1001, externals=[(1, "shared.assets")])

            report = plan_path(root, out, ScanOptions(max_in_memory_bytes=0, embedded_scan=False))

            references = [
                json.loads(line) for line in (out / "unity-references.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            statuses = {item["source_file"]: item["resolution_status"] for item in references}

            self.assertEqual(report.summary["unity_references_total"], 3)
            self.assertEqual(report.summary["unity_references_resolved_total"], 0)
            self.assertEqual(report.summary["unity_references_unresolved_total"], 3)
            self.assertEqual(statuses[str(root / "missing_path.assets")], "missing_target_path_id")
            self.assertEqual(statuses[str(root / "missing_file.assets")], "missing_external_file")
            self.assertEqual(statuses[str(root / "ambiguous.assets")], "ambiguous_external_file")

    def test_unity_typetree_decodes_nested_structs_arrays_maps_and_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            asset = root / "behaviour.assets"
            stream = root / "clip.resource"
            stream.write_bytes(b"audio-stream-payload")
            payload = bytearray()
            payload.extend(struct.pack(">if?", 7, 1.25, True))
            payload.extend(b"\0" * 3)
            payload.extend(unity_string("Player"))
            payload.extend(struct.pack(">fff", 1.0, 2.0, 3.0))
            payload.extend(struct.pack(">i", 3))
            payload.extend(struct.pack(">iii", 10, 20, 30))
            payload.extend(struct.pack(">i", 2))
            payload.extend(struct.pack(">ffff", 4.0, 5.0, 6.0, 7.0))
            payload.extend(struct.pack(">i", 2))
            payload.extend(unity_string("hp"))
            payload.extend(struct.pack(">i", 100))
            payload.extend(unity_string("mp"))
            payload.extend(struct.pack(">i", 50))
            payload.extend(struct.pack(">iq", 0, 1001))
            payload.extend(struct.pack(">QI", 6, 6))
            payload.extend(unity_string("clip.resource"))
            make_unity_assets_v22_with_typetree(
                asset,
                bytes(payload),
                [
                    ("MonoBehaviour", "MonoBehaviour", -1, 0, False),
                    ("int", "m_Count", 4, 1, False),
                    ("float", "m_Speed", 4, 1, False),
                    ("bool", "m_Enabled", 1, 1, False, 0x4000),
                    ("string", "m_Name", -1, 1, False),
                    ("Vector3f", "m_Position", 12, 1, False),
                    ("float", "x", 4, 2, False),
                    ("float", "y", 4, 2, False),
                    ("float", "z", 4, 2, False),
                    ("vector", "m_Scores", -1, 1, False),
                    ("Array", "Array", -1, 2, True),
                    ("int", "size", 4, 3, False),
                    ("int", "data", 4, 3, False),
                    ("vector", "m_Points", -1, 1, False),
                    ("Array", "Array", -1, 2, True),
                    ("int", "size", 4, 3, False),
                    ("Vector2f", "data", 8, 3, False),
                    ("float", "x", 4, 4, False),
                    ("float", "y", 4, 4, False),
                    ("map", "m_Stats", -1, 1, False),
                    ("Array", "Array", -1, 2, True),
                    ("int", "size", 4, 3, False),
                    ("pair", "data", -1, 3, False),
                    ("string", "first", -1, 4, False),
                    ("int", "second", 4, 4, False),
                    ("Link", "m_Link", -1, 1, False),
                    ("PPtr<Texture2D>", "m_Texture", 12, 2, False),
                    ("StreamingInfo", "m_StreamData", -1, 1, False),
                    ("UInt64", "offset", 8, 2, False),
                    ("UInt32", "size", 4, 2, False),
                    ("string", "path", -1, 2, False),
                ],
                class_id=114,
            )

            report = decompile_path(
                asset,
                out,
                ExtractionOptions(mode="selective", max_in_memory_bytes=0, embedded_scan=False, hash_policy="never"),
            )

            objects = [json.loads(line) for line in (out / "objects.jsonl").read_text(encoding="utf-8").splitlines()]
            resources = [
                json.loads(line) for line in (out / "unity-external-resources.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            references = [
                json.loads(line) for line in (out / "unity-references.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            reconstructed = [
                json.loads(line) for line in (out / "reconstructed.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            sidecar = json.loads(Path(reconstructed[0]["sidecar_path"]).read_text(encoding="utf-8"))
            fields = objects[0]["decoded_fields"]
            self.assertEqual(report.summary["unity_references_total"], 1)
            self.assertEqual(fields["m_Count"], 7)
            self.assertEqual(fields["m_Name"], "Player")
            self.assertEqual(fields["m_Position"], {"x": 1.0, "y": 2.0, "z": 3.0})
            self.assertEqual(fields["m_Scores"], [10, 20, 30])
            self.assertEqual(fields["m_Points"][1], {"x": 6.0, "y": 7.0})
            self.assertEqual(fields["m_Stats"], [{"key": "hp", "value": 100}, {"key": "mp", "value": 50}])
            self.assertEqual(references[0]["target_path_id"], 1001)
            self.assertEqual(resources[0]["status"], "extracted")
            self.assertEqual(Path(resources[0]["output_path"]).read_bytes(), b"stream")
            self.assertEqual(sidecar["decoded_fields"]["m_Scores"], [10, 20, 30])

    def test_unity_typetree_truncated_array_keeps_partial_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            asset = root / "broken.assets"
            make_unity_assets_v22_with_typetree(
                asset,
                struct.pack(">ii", 2, 10),
                [
                    ("MonoBehaviour", "MonoBehaviour", -1, 0, False),
                    ("int", "m_Count", 4, 1, False),
                    ("vector", "m_Items", -1, 1, False),
                    ("Array", "Array", -1, 2, True),
                    ("int", "size", 4, 3, False),
                    ("int", "data", 4, 3, False),
                ],
                class_id=114,
            )

            report = plan_path(asset, out, ScanOptions(max_in_memory_bytes=0, embedded_scan=False))

            objects = [json.loads(line) for line in (out / "objects.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(report.summary["unity_objects_total"], 1)
            self.assertEqual(objects[0]["decode_status"], "partial_typetree")
            self.assertEqual(objects[0]["decoded_fields"]["m_Count"], 2)
            self.assertIn("__decode_error__", objects[0]["decoded_fields"]["m_Items"])

    def test_selective_decompile_reconstructs_textasset_with_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            asset = root / "resources.assets"
            make_unity_assets_v22_with_object(asset, b"dialogue_key=hello\n")

            report = decompile_path(
                asset,
                out,
                ExtractionOptions(mode="selective", max_in_memory_bytes=0, embedded_scan=False, hash_policy="never"),
            )

            reconstructed = [
                json.loads(line) for line in (out / "reconstructed.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(report.summary["unity_reconstructed_total"], 1)
            self.assertEqual(reconstructed[0]["reconstruction_status"], "decoded")
            self.assertEqual(Path(reconstructed[0]["output_path"]).read_bytes(), b"dialogue_key=hello\n")
            self.assertTrue(Path(reconstructed[0]["sidecar_path"]).exists())
            self.assertFalse((out / "resources.assets").exists())

    def test_full_decompile_preserves_unity_container_and_reconstructs_objects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            asset = root / "resources.assets"
            make_unity_assets_v22_with_object(asset, b"dialogue_key=hello\n")
            original = asset.read_bytes()

            report = decompile_path(
                asset,
                out,
                ExtractionOptions(mode="full", max_in_memory_bytes=0, embedded_scan=False, hash_policy="never"),
            )

            self.assertEqual((out / "resources.assets").read_bytes(), original)
            self.assertEqual(report.summary["unity_reconstructed_total"], 1)
            self.assertGreaterEqual(report.summary["extracted_total"], 2)

    def test_unity_object_budget_blocks_reconstruction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            asset = root / "resources.assets"
            make_unity_assets_v22_with_object(asset, b"payload too large")

            report = decompile_path(
                asset,
                out,
                ExtractionOptions(
                    mode="selective",
                    max_in_memory_bytes=0,
                    embedded_scan=False,
                    unity_max_object_bytes=4,
                ),
            )

            self.assertEqual(report.summary["unity_reconstructed_total"], 0)
            self.assertEqual(report.summary["skipped_total"], 1)
            self.assertEqual(report.skipped_sample[0]["reason"], "blocked_unity_object_budget")

    def test_global_output_budget_includes_unity_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            asset = root / "resources.assets"
            make_unity_assets_v22_with_object(asset, b"payload")

            report = decompile_path(
                asset,
                out,
                ExtractionOptions(
                    mode="selective",
                    max_in_memory_bytes=0,
                    embedded_scan=False,
                    max_output_bytes=1,
                    hash_policy="never",
                ),
            )

            self.assertEqual(report.summary["unity_reconstructed_total"], 0)
            self.assertEqual(report.summary["output_bytes"], 0)
            self.assertTrue(any(item.get("reason") == "blocked_output_budget" for item in report.skipped_sample))
            self.assertFalse(any((out / "unity_objects").rglob("*.json")))

    def test_assembly_types_jsonl_lists_typedef_and_methods(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            assembly = root / "Assembly-CSharp.dll"
            make_minimal_dotnet_pe(assembly)

            report = plan_path(assembly, out, ScanOptions(max_in_memory_bytes=0, embedded_scan=False))

            records = [json.loads(line) for line in (out / "assembly-types.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(report.summary["assembly_types_total"], 1)
            self.assertEqual(records[0]["namespace"], "MyGame")
            self.assertEqual(records[0]["name"], "Player")
            self.assertEqual(records[0]["methods_sample"], ["Update"])

    def test_semantic_conversions_emit_mo_po_and_dat_pseudocode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            (root / "locale.mo").write_bytes(make_mo())
            (root / "save.dat").write_bytes(b"player\x00level\x00" + bytes(range(16)))
            (root / "level.lvl").write_bytes(b"ignored")
            (root / "font.ttf").write_bytes(make_ttf())
            (root / "game.dll").write_bytes(make_pe_exact())

            report = decompile_path(root, out, ExtractionOptions(mode="full", embedded_scan=False, hash_policy="never"))

            records = [
                json.loads(line) for line in (out / "semantic-conversions.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            by_extension = {record["extension"]: record for record in records}
            self.assertIn(".mo", by_extension)
            self.assertIn(".dat", by_extension)
            self.assertNotIn(".lvl", by_extension)
            self.assertNotIn(".ttf", by_extension)
            self.assertNotIn(".dll", by_extension)
            self.assertEqual(by_extension[".mo"]["status"], "converted")
            self.assertEqual(by_extension[".dat"]["status"], "pseudocode")
            self.assertIn('msgid "hello"', Path(by_extension[".mo"]["output_path"]).read_text(encoding="utf-8"))
            dat_profile = json.loads(Path(by_extension[".dat"]["output_path"]).read_text(encoding="utf-8"))
            self.assertEqual(dat_profile["parser"], "generic_binary_pseudocode")
            self.assertEqual(report.summary["semantic_converted_total"], 1)
            self.assertEqual(report.summary["semantic_pseudocode_total"], 1)

    def test_semantic_glb_json_chunk_is_extracted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            glb = root / "model.glb"
            glb.write_bytes(make_glb_with_json())

            report = decompile_path(glb, out, ExtractionOptions(mode="full", embedded_scan=False, hash_policy="never"))

            records = [
                json.loads(line) for line in (out / "semantic-conversions.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(records[0]["extension"], ".glb")
            self.assertEqual(records[0]["status"], "converted")
            self.assertEqual(json.loads(Path(records[0]["output_path"]).read_text(encoding="utf-8"))["asset"]["version"], "2.0")
            self.assertEqual(report.summary["semantic_converted_total"], 1)

    def test_local_format_pack_registers_extension_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pack = root / "formats.toml"
            pack.write_text(
                """
[[formats]]
type_name = "dialogue"
extensions = [".dialogue"]
category = "data"
role = "game_dialogue_text"
decompile_value = "high"
text = true
""".strip(),
                encoding="utf-8",
            )
            sample = root / "intro.dialogue"
            sample.write_text("hello=world\n", encoding="utf-8")

            probe = probe_file(sample, ScanOptions(format_pack_paths=[str(pack)]))

            self.assertEqual(probe.identified_type, "dialogue")
            self.assertEqual(probe.category, "data")
            self.assertEqual(probe.decompile_value, "high")
            self.assertEqual(probe.parse_info["parser"], "extension_descriptor")
            self.assertEqual(probe.parse_info["type"], "dialogue")

    def test_local_format_pack_participates_in_registry_and_decompile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            pack_dir = root / "pack"
            pack_dir.mkdir()
            (pack_dir / "formats.toml").write_text(
                """
[[formats]]
type_name = "quest"
extensions = [".quest"]
category = "data"
role = "quest_definition_text"
decompile_value = "high"
text = true
""".strip(),
                encoding="utf-8",
            )
            sample = root / "main.quest"
            sample.write_text("quest=bring_the_key\n", encoding="utf-8")
            registry = build_capability_registry([str(pack_dir)], load_plugins=False)

            report = decompile_path(root, out, ExtractionOptions(mode="selective", embedded_scan=False, format_pack_paths=[str(pack_dir)]))

            self.assertIn(".quest", registry.format_by_extension)
            self.assertEqual(report.summary["by_type"]["quest"], 1)
            self.assertTrue((out / "main.quest").exists())

    def test_overwrite_never_truncates_the_source_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "source.png"
            sample.write_bytes(PNG_BYTES)

            report = decompile_path(
                sample,
                root,
                ExtractionOptions(mode="full", overwrite=True, embedded_scan=False, unity_object_scan=False),
            )

            self.assertEqual(sample.read_bytes(), PNG_BYTES)
            self.assertEqual(report.summary["failed_total"], 1)
            failures = list(read_manifest(root).iter_failures())
            self.assertIn("same", failures[0]["reason"])

    def test_directory_decompile_rejects_identical_output_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "asset.png").write_bytes(PNG_BYTES)

            with self.assertRaisesRegex(ValueError, "same directory"):
                decompile_path(root, root, ExtractionOptions(mode="full", overwrite=True))

    def test_hash_naming_uses_embedded_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "payload.bin"
            source.write_bytes(b"prefix" + PNG_BYTES + b"suffix")
            out = root / "out"

            decompile_path(
                source,
                out,
                ExtractionOptions(
                    mode="full",
                    naming="hash",
                    preserve_paths=False,
                    unity_object_scan=False,
                ),
            )

            expected = hashlib.sha256(PNG_BYTES).hexdigest()[:16]
            self.assertTrue((out / f"png_{expected}.png").exists())

    def test_invalid_numeric_options_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "stream_chunk_size"):
            ScanOptions(stream_chunk_size=0)
        with self.assertRaisesRegex(ValueError, "max_output_bytes"):
            ExtractionOptions(max_output_bytes=-1)
        with self.assertRaisesRegex(ValueError, "max_processing_seconds"):
            ScanOptions(max_processing_seconds=0)

    def test_processing_deadline_stops_run_cooperatively(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(10):
                (root / f"asset_{index}.png").write_bytes(PNG_BYTES)

            with patch("deinserter.pipeline.monotonic", side_effect=[0.0] + [1.0] * 100):
                report = decompile_path(
                    root,
                    root / "out",
                    ExtractionOptions(
                        mode="manifest_only",
                        unity_object_scan=False,
                        max_processing_seconds=0.5,
                    ),
                )

            self.assertIn("processing_deadline_reached", report.warnings)
            self.assertTrue(report.summary["deadline_reached"])
            self.assertLess(report.summary["files_total"], 10)

    def test_unsafe_archive_paths_never_escape_output_root(self) -> None:
        from deinserter.containers import _safe_output_path

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive_path = root / "unsafe.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../escaped.txt", "unsafe")
            out = root / "out"

            report = decompile_path(
                archive_path,
                out,
                ExtractionOptions(mode="full", unity_object_scan=False),
            )

            self.assertFalse((root / "escaped.txt").exists())
            self.assertEqual(report.summary["failed_total"], 1)
            with self.assertRaisesRegex(ValueError, "unsafe absolute archive path"):
                _safe_output_path(out, "//server/share/escaped.txt", overwrite=False)
            with self.assertRaisesRegex(ValueError, "unsafe archive path"):
                _safe_output_path(out, "CON", overwrite=False)

    def test_container_overwrite_never_replaces_its_source_archive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive_path = root / "self.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("self.zip", b"replacement")
            original = archive_path.read_bytes()

            report = decompile_path(
                archive_path,
                root,
                ExtractionOptions(mode="full", overwrite=True, unity_object_scan=False),
            )

            self.assertEqual(archive_path.read_bytes(), original)
            self.assertGreaterEqual(report.summary["failed_total"], 1)

    def test_semantic_outputs_respect_global_output_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "profile.dat"
            source.write_bytes(b"binary-profile")
            out = root / "out"

            report = decompile_path(
                source,
                out,
                ExtractionOptions(
                    mode="full",
                    max_output_bytes=1,
                    embedded_scan=False,
                    unity_object_scan=False,
                ),
            )

            self.assertEqual(report.summary["output_bytes"], 0)
            self.assertEqual(report.summary["semantic_blocked_total"], 1)
            self.assertFalse((out / "semantic" / "profile.dat.semantic.json").exists())

    def test_all_failures_are_persisted_beyond_report_sample(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "input"
            source.mkdir()
            for index in range(55):
                (source / f"invalid_{index}.gpak").write_bytes(b"bad")
            out = root / "out"

            report = decompile_path(
                source,
                out,
                ExtractionOptions(mode="manifest_only", unity_object_scan=False),
            )

            self.assertEqual(report.summary["failed_total"], 55)
            self.assertEqual(len(report.failed_sample), 50)
            self.assertEqual(len(list(read_manifest(out).iter_failures())), 55)

    def test_scan_continues_after_malformed_container(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "broken.gpak").write_bytes(b"bad")
            valid = root / "valid.png"
            valid.write_bytes(PNG_BYTES)

            report = scan_path(root, ScanOptions(unity_object_scan=False))

            self.assertEqual([Path(item.path).name for item in report.files], ["valid.png"])
            self.assertTrue(any("broken.gpak" in warning for warning in report.warnings))

    def test_file_size_limit_applies_before_container_or_unity_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            oversized = root / "oversized.gpak"
            with oversized.open("wb") as handle:
                handle.seek(2 * 1024 * 1024)
                handle.write(b"bad")
            valid = root / "valid.png"
            valid.write_bytes(PNG_BYTES)

            scanned = scan_path(root, ScanOptions(max_file_size_mb=1, unity_object_scan=False))
            by_name = {Path(item.path).name: item for item in scanned.files}
            out = root / "out"
            decompiled = decompile_path(
                root,
                out,
                ExtractionOptions(mode="full", max_file_size_mb=1, unity_object_scan=False),
            )

            self.assertEqual(by_name["oversized.gpak"].status, "skipped_size_limit")
            self.assertEqual(by_name["valid.png"].identified_type, "png")
            self.assertTrue(any(item.get("reason") == "blocked_file_size_limit" for item in decompiled.skipped_sample))

    def test_directory_classification_works_for_absolute_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audio_dir = Path(tmp) / "audio"
            audio_dir.mkdir()
            sample = audio_dir / "bank_without_extension"
            sample.write_bytes(b"unknown")

            report = probe_file(sample, ScanOptions(embedded_scan=False))

            self.assertEqual(report.category, "audio")

    def test_unused_container_keyring_is_reported_instead_of_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "asset.png"
            sample.write_bytes(PNG_BYTES)

            report = scan_path(
                sample,
                ScanOptions(container_keyring_path=str(Path(tmp) / "keys.json"), unity_object_scan=False),
            )

            self.assertTrue(any("no registered container handler accepts" in warning for warning in report.warnings))

    def test_plugin_container_can_accept_keyring_configuration(self) -> None:
        class ConfigurableContainer:
            type_name = "configured"

            def __init__(self):
                self.keyring = ""

            def configure(self, options):
                self.keyring = options.container_keyring_path or ""
                return True

            def sniff(self, _path):
                return False

            def open(self, _path):
                raise AssertionError("not opened")

            def extract_entry(self, *_args, **_kwargs):
                raise AssertionError("not extracted")

        registry = build_capability_registry(load_plugins=False)
        handler = ConfigurableContainer()
        registry.add_container_handler(handler, capability_id="test:container:configured", priority=100)

        registry.configure(ScanOptions(container_keyring_path="keys.json"))

        self.assertEqual(handler.keyring, "keys.json")
        self.assertFalse(any("no registered container handler accepts" in error for error in registry.load_errors))

    def test_detector_priority_and_conflicts_are_explicit(self) -> None:
        class MarkerDetector:
            extension = ".mark"

            def __init__(self, type_name: str):
                self.type_name = type_name

            def identify(self, data: bytes, path: Path):
                return FileIdentification(str(path), self.type_name, 1.0, path.suffix, data[:4].hex())

            def find_embedded(self, data: bytes, source_file: str):
                return []

            def validate(self, data: bytes):
                return True

        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.mark"
            sample.write_bytes(b"MARK")
            registry = build_capability_registry(load_plugins=False)
            low = MarkerDetector("low_priority")
            high = MarkerDetector("high_priority")
            registry.add_detector(low, capability_id="test:marker:low", priority=10)
            registry.add_detector(high, capability_id="test:marker:high", priority=20)

            self.assertEqual(probe_file(sample, registry=registry).identified_type, "high_priority")
            with self.assertRaisesRegex(ValueError, "duplicate detector capability"):
                registry.add_detector(MarkerDetector("duplicate"), capability_id="test:marker:high")
            registry.add_detector(
                MarkerDetector("replacement"),
                capability_id="test:marker:high",
                priority=30,
                replace=True,
            )
            self.assertEqual(probe_file(sample, registry=registry).identified_type, "replacement")

    def test_plugin_streaming_detector_handles_large_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "large.bin"
            sample.write_bytes(b"x" * 64 + b"CSTMdata" + b"x" * 64)
            registry = build_capability_registry(load_plugins=False)

            def broken_length(_source, _offset, _signature):
                raise RuntimeError("broken stream")

            registry.add_streaming_detector(
                type_name="broken_stream",
                signatures=(b"CSTM",),
                length_reader=broken_length,
                extension=".broken",
                capability_id="test:streaming:broken",
                priority=200,
            )
            registry.add_streaming_detector(
                type_name="custom_stream",
                signatures=(b"CSTM",),
                length_reader=lambda _source, _offset, _signature: 8,
                extension=".cstm",
                capability_id="test:streaming:custom",
                priority=100,
            )

            report = probe_file(
                sample,
                ScanOptions(max_in_memory_bytes=16, stream_chunk_size=17),
                registry,
            )

            custom = [item for item in report.embedded_candidates if item.detected_type == "custom_stream"]
            self.assertEqual(len(custom), 1)
            self.assertEqual((custom[0].offset, custom[0].length), (64, 8))
            self.assertTrue(any("broken stream" in error for error in registry.runtime_errors))
            out = Path(tmp) / "out"
            with patch("deinserter.pipeline.build_capability_registry", return_value=registry):
                decompile_path(
                    sample,
                    out,
                    ExtractionOptions(
                        mode="full",
                        max_in_memory_bytes=16,
                        stream_chunk_size=17,
                        preserve_paths=False,
                        unity_object_scan=False,
                    ),
                )
            self.assertTrue((out / "custom_stream_00000040.cstm").exists())

    def test_large_probe_skips_non_stream_safe_path_parsers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "large.slow"
            sample.write_bytes(b"slow" * 64)
            registry = build_capability_registry(load_plugins=False)
            spec = FormatSpec("slow", (".slow",), "data", "slow_data", "medium", False)
            registry.add_format(spec)
            registry.add_detector(ExtensionDetector(spec), capability_id="test:detector:slow", priority=100)

            def unsafe_parser(_path):
                raise AssertionError("must not materialize")

            registry.add_parser(
                unsafe_parser,
                name="slow_path_parser",
                capability_id="test:parser:slow",
                extensions={".slow"},
                priority=100,
                stream_safe=False,
            )

            report = probe_file(sample, ScanOptions(max_in_memory_bytes=16), registry)

            self.assertEqual(report.parse_info["parser"], "extension_descriptor")

    def test_source_parser_and_converter_process_container_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive_path = root / "dialogue.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("story.dialogue", b"hello from archive")
            out = root / "out"
            registry = build_capability_registry(load_plugins=False)
            spec = FormatSpec("dialogue", (".dialogue",), "data", "dialogue_text", "high", True)
            registry.add_format(spec)
            registry.add_detector(
                ExtensionDetector(spec),
                capability_id="test:detector:dialogue",
                priority=100,
            )
            registry.add_source_parser(
                lambda source, _path: {
                    "parser": "dialogue_source",
                    "status": "parsed",
                    "text": source.read_all().decode("utf-8"),
                },
                name="dialogue_source",
                capability_id="test:parser:dialogue",
                extensions={".dialogue"},
                priority=100,
            )
            registry.add_converter(
                lambda context: {
                    "status": "plugin_converted",
                    "preview": context.source.read_at(0, 5).decode("ascii"),
                },
                name="dialogue_converter",
                capability_id="test:converter:dialogue",
                extensions={".dialogue"},
                priority=100,
            )

            with patch("deinserter.pipeline.build_capability_registry", return_value=registry):
                decompile_path(
                    archive_path,
                    out,
                    ExtractionOptions(mode="manifest_only", unity_object_scan=False),
                )

            events = list(read_manifest(out).iter_capability_events())
            artifact = next(item for item in events if item.get("stream") == "container_artifact")
            converted = next(item for item in events if item.get("capability_id") == "test:converter:dialogue")
            self.assertEqual(artifact["parse_info"]["parser"], "dialogue_source")
            self.assertEqual(artifact["parse_info"]["text"], "hello from archive")
            self.assertEqual(converted["preview"], "hello")

    def test_nested_containers_are_processed_with_depth_limits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inner_bytes = io.BytesIO()
            with zipfile.ZipFile(inner_bytes, "w") as inner:
                inner.writestr("notes.txt", "nested")
            outer_path = root / "outer.zip"
            with zipfile.ZipFile(outer_path, "w") as outer:
                outer.writestr("inner.zip", inner_bytes.getvalue())

            recursive_out = root / "recursive"
            recursive = decompile_path(
                outer_path,
                recursive_out,
                ExtractionOptions(mode="manifest_only", unity_object_scan=False, max_container_depth=4),
            )
            shallow_out = root / "shallow"
            shallow = decompile_path(
                outer_path,
                shallow_out,
                ExtractionOptions(mode="manifest_only", unity_object_scan=False, max_container_depth=0),
            )

            self.assertEqual(recursive.summary["containers_total"], 2)
            self.assertEqual(recursive.summary["container_entries_total"], 2)
            self.assertEqual(shallow.summary["containers_total"], 1)
            nested_events = [
                item
                for item in read_manifest(recursive_out).iter_capability_events()
                if item.get("stream") == "nested_container"
            ]
            self.assertEqual(len(nested_events), 1)

    def test_container_entry_limit_is_global_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive_path = root / "many.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                for index in range(3):
                    archive.writestr(f"item_{index}.txt", "value")

            report = decompile_path(
                archive_path,
                root / "out",
                ExtractionOptions(
                    mode="manifest_only",
                    unity_object_scan=False,
                    max_container_entries=1,
                ),
            )

            self.assertEqual(report.summary["container_entries_total"], 1)
            self.assertTrue(any("container_entry_limit_reached" in warning for warning in report.warnings))

    def test_plugin_api_version_is_enforced(self) -> None:
        registry = build_capability_registry(load_plugins=False)

        def incompatible(_registry):
            return None

        incompatible.DEINSERTER_API_VERSION = CAPABILITY_API_VERSION + 1
        with self.assertRaisesRegex(ValueError, "unsupported plugin API version"):
            register_plugin_callable(registry, "incompatible", incompatible)

    def test_entry_point_plugins_can_be_loaded_or_disabled(self) -> None:
        class FakeEntryPoint:
            name = "fake_plugin"

            @staticmethod
            def load():
                def register(registry):
                    registry.add_converter(
                        lambda _context: {"status": "fake"},
                        name="fake",
                        capability_id="fake:converter",
                        extensions={".fake"},
                    )

                register.DEINSERTER_API_VERSION = CAPABILITY_API_VERSION
                return register

        with patch("deinserter.registry.entry_points", return_value=[FakeEntryPoint()]):
            loaded = build_capability_registry()
            disabled = build_capability_registry(disabled_plugins={"fake_plugin"})

        self.assertIn("fake", [item.name for item in loaded.converters])
        self.assertNotIn("fake", [item.name for item in disabled.converters])
        self.assertEqual(disabled.plugins[0]["status"], "disabled")

    def test_entry_point_descriptor_gets_generated_extension_detector(self) -> None:
        class DescriptorEntryPoint:
            name = "descriptor_plugin"

            @staticmethod
            def load():
                def register(registry):
                    registry.add_format(FormatSpec("plugdata", (".plug",), "data", "plugin_data", "high", True))

                return register

        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.plug"
            sample.write_text("plugin", encoding="utf-8")
            with patch("deinserter.registry.entry_points", return_value=[DescriptorEntryPoint()]):
                registry = build_capability_registry()

            self.assertEqual(probe_file(sample, registry=registry).identified_type, "plugdata")

    def test_failed_plugin_registration_is_transactional(self) -> None:
        registry = build_capability_registry(load_plugins=False)

        def broken(registry):
            registry.add_converter(
                lambda _context: None,
                name="partial",
                capability_id="broken:partial",
                extensions={".broken"},
            )
            raise RuntimeError("registration failed")

        with self.assertRaisesRegex(RuntimeError, "registration failed"):
            register_plugin_callable(registry, "broken", broken)
        self.assertNotIn("broken:partial", [item.capability_id for item in registry.converters])

    def test_plugin_can_explicitly_replace_builtin_capability(self) -> None:
        registry = build_capability_registry(load_plugins=False)

        def replacement(registry):
            registry.add_converter(
                lambda _context: {"status": "replacement"},
                name="semantic_replacement",
                capability_id="builtin:converter:semantic",
                predicate=lambda _path, _type, _category: True,
                priority=500,
                replace=True,
            )

        register_plugin_callable(registry, "replacement", replacement)

        capabilities = [item for item in registry.converters if item.capability_id == "builtin:converter:semantic"]
        self.assertEqual(len(capabilities), 1)
        self.assertEqual(capabilities[0].source, "plugin:replacement")

    def test_plugin_run_hook_can_prepare_shared_services(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.txt"
            sample.write_text("hello", encoding="utf-8")
            out = root / "out"
            registry = build_capability_registry(load_plugins=False)

            def prepare(context):
                context.services["prepared_value"] = 7
                context.summary["plugin_prepared"] = True

            def consume(context):
                return {"status": "consumed", "value": context.services["prepared_value"]}

            registry.add_run_hook(prepare, capability_id="test:run_hook:prepare", priority=100)
            registry.add_converter(
                consume,
                capability_id="test:converter:consume",
                extensions={".txt"},
                priority=100,
            )

            with patch("deinserter.pipeline.build_capability_registry", return_value=registry):
                report = decompile_path(
                    sample,
                    out,
                    ExtractionOptions(mode="manifest_only", unity_object_scan=False),
                )

            events = list(read_manifest(out).iter_capability_events())
            self.assertTrue(report.summary["plugin_prepared"])
            self.assertTrue(any(item.get("value") == 7 for item in events))

    def test_malformed_processor_result_is_isolated_from_later_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.txt"
            sample.write_text("hello", encoding="utf-8")
            out = root / "out"
            registry = build_capability_registry(load_plugins=False)
            registry.add_converter(
                lambda _context: "invalid result",
                name="malformed",
                capability_id="test:converter:malformed",
                extensions={".txt"},
                priority=200,
            )
            registry.add_converter(
                lambda _context: {"status": "later_capability_ran"},
                name="later",
                capability_id="test:converter:later",
                extensions={".txt"},
                priority=100,
            )

            with patch("deinserter.pipeline.build_capability_registry", return_value=registry):
                report = decompile_path(
                    sample,
                    out,
                    ExtractionOptions(mode="manifest_only", unity_object_scan=False),
                )

            events = list(read_manifest(out).iter_capability_events())
            self.assertTrue(any(item.get("status") == "later_capability_ran" for item in events))
            self.assertEqual(report.summary["failed_total"], 1)

    def test_manifest_paths_are_absolute_and_portable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "asset.png"
            source.write_bytes(PNG_BYTES)
            out = root / "relative-out"

            report = decompile_path(
                source,
                out,
                ExtractionOptions(mode="manifest_only", unity_object_scan=False),
            )

            self.assertTrue(Path(report.manifest_paths.summary).is_absolute())
            self.assertEqual(len(list(read_manifest(out).iter_files())), 1)

    def test_plugin_scaffold_validate_and_sample_test_cover_code_capabilities(self) -> None:
        from deinserter.cli import _init_plugin, _test_plugin, _validate_plugin

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plugin_dir = root / "deinserter-example"
            created = _init_plugin(plugin_dir, template="full")
            sample = root / "sample.dialogue"
            sample.write_bytes(b"DIALOGUE\0hello")

            validation = _validate_plugin(plugin_dir)
            tested = _test_plugin(plugin_dir, sample, "example_dialogue")

            self.assertEqual(created["template"], "full")
            self.assertTrue(validation["valid"], validation)
            self.assertGreaterEqual(validation["capabilities_added"]["detectors"], 1)
            self.assertGreaterEqual(validation["capabilities_added"]["converters"], 1)
            self.assertTrue(tested["matched"], tested)

    def test_plugin_validation_returns_structured_format_errors(self) -> None:
        from deinserter.cli import _validate_plugin

        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = Path(tmp)
            (plugin_dir / "formats.toml").write_text(
                '''[[formats]]
type_name = "Bad Type"
extensions = [42]
category = "data"
role = "bad"
decompile_value = "unlimited"
''',
                encoding="utf-8",
            )

            validation = _validate_plugin(plugin_dir)

            self.assertFalse(validation["valid"])
            self.assertTrue(validation["load_errors"])


if __name__ == "__main__":
    unittest.main()
