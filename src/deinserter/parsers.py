from __future__ import annotations

import json
import re
import struct
from pathlib import Path
from typing import Any

from .assembly import inspect_assembly
from .unity.bundle import inspect_bundle
from .unity.serialized import inspect_serialized_file
from .utils import shannon_entropy, strings_preview


def _read_at(path: Path, offset: int, length: int) -> bytes:
    if offset < 0 or length < 0:
        return b""
    with path.open("rb") as handle:
        handle.seek(offset)
        return handle.read(length)


def _c_string(data: bytes, offset: int = 0) -> tuple[str, int]:
    end = data.find(b"\0", offset)
    if end == -1:
        end = len(data)
    raw = data[offset:end]
    try:
        value = raw.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        value = ""
    return value, end + 1


def _u32_be(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def _u64_be(data: bytes, offset: int) -> int:
    return struct.unpack_from(">Q", data, offset)[0]


def _u16_le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32_le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def parse_unity_serialized_file(path: Path) -> dict[str, Any]:
    return inspect_serialized_file(path).to_dict()


def parse_unity_bundle(path: Path) -> dict[str, Any]:
    return inspect_bundle(path).to_dict()


def parse_unity_resource(path: Path) -> dict[str, Any]:
    header = _read_at(path, 0, 16)
    if header.startswith(b"FSB5"):
        return parse_fsb(path)
    return {
        "parser": "unity_resource_blob",
        "status": "raw_resource_blob",
        "file_size": path.stat().st_size,
        "magic": header.hex(),
        "header_entropy": shannon_entropy(_read_at(path, 0, min(path.stat().st_size, 4096))),
    }


def parse_fsb(path: Path) -> dict[str, Any]:
    size = path.stat().st_size
    header = _read_at(path, 0, min(128, size))
    info: dict[str, Any] = {"parser": "fsb5", "status": "partial", "file_size": size}
    if not header.startswith(b"FSB5") or len(header) < 28:
        info["status"] = "not_fsb5"
        return info
    try:
        info.update(
            {
                "version": _u32_le(header, 4),
                "sample_count": _u32_le(header, 8),
                "sample_headers_size": _u32_le(header, 12),
                "name_table_size": _u32_le(header, 16),
                "data_size": _u32_le(header, 20),
                "mode": _u32_le(header, 24),
                "status": "parsed_header",
            }
        )
    except (struct.error, OSError, ValueError) as exc:
        info["status"] = "parse_error"
        info["error"] = str(exc)
    return info


def parse_jpeg(path: Path) -> dict[str, Any]:
    data = _read_at(path, 0, min(path.stat().st_size, 1024 * 1024))
    info: dict[str, Any] = {"parser": "jpeg", "status": "partial", "file_size": path.stat().st_size}
    if not data.startswith(b"\xff\xd8"):
        info["status"] = "not_jpeg"
        return info
    cursor = 2
    segments: list[str] = []
    try:
        while cursor < len(data):
            if data[cursor] != 0xFF:
                info["status"] = "scan_data_or_invalid_marker"
                break
            while cursor < len(data) and data[cursor] == 0xFF:
                cursor += 1
            marker = data[cursor]
            cursor += 1
            segments.append(hex(marker))
            if marker == 0xD9:
                info["status"] = "parsed"
                break
            if marker == 0xDA:
                info["status"] = "parsed_to_scan"
                break
            if marker == 0x00 or 0xD0 <= marker <= 0xD8:
                continue
            segment_len = int.from_bytes(data[cursor : cursor + 2], "big")
            cursor += segment_len
        info["segments_sample"] = segments[:32]
    except (IndexError, ValueError) as exc:
        info["status"] = "parse_error"
        info["error"] = str(exc)
    return info


def parse_dds(path: Path) -> dict[str, Any]:
    header = _read_at(path, 0, 148)
    info: dict[str, Any] = {"parser": "dds", "status": "partial", "file_size": path.stat().st_size}
    if len(header) < 128 or not header.startswith(b"DDS "):
        info["status"] = "not_dds"
        return info
    try:
        flags = _u32_le(header, 80)
        fourcc = header[84:88]
        info.update(
            {
                "status": "parsed_header",
                "height": _u32_le(header, 12),
                "width": _u32_le(header, 16),
                "depth": _u32_le(header, 24),
                "mipmap_count": _u32_le(header, 28),
                "pixel_format_flags": hex(flags),
                "fourcc": fourcc.decode("ascii", errors="replace").rstrip("\0"),
                "rgb_bit_count": _u32_le(header, 88),
                "caps2": hex(_u32_le(header, 112)),
            }
        )
        if fourcc == b"DX10" and len(header) >= 148:
            info["dxgi_format"] = _u32_le(header, 128)
    except (struct.error, OSError, ValueError) as exc:
        info["status"] = "parse_error"
        info["error"] = str(exc)
    return info


def parse_tga(path: Path) -> dict[str, Any]:
    header = _read_at(path, 0, 18)
    info: dict[str, Any] = {"parser": "tga", "status": "partial", "file_size": path.stat().st_size}
    if len(header) != 18:
        info["status"] = "too_short"
        return info
    image_type = header[2]
    width = int.from_bytes(header[12:14], "little")
    height = int.from_bytes(header[14:16], "little")
    pixel_depth = header[16]
    if image_type not in {1, 2, 3, 9, 10, 11} or width == 0 or height == 0:
        info["status"] = "not_tga"
        return info
    info.update(
        {
            "status": "parsed_header",
            "image_type": image_type,
            "color_map_type": header[1],
            "width": width,
            "height": height,
            "pixel_depth": pixel_depth,
            "rle": image_type in {9, 10, 11},
        }
    )
    return info


def parse_mo(path: Path) -> dict[str, Any]:
    size = path.stat().st_size
    header = _read_at(path, 0, min(size, 28))
    info: dict[str, Any] = {"parser": "gnu_mo", "status": "partial", "file_size": size}
    if len(header) != 28:
        info["status"] = "too_short"
        return info
    magic = header[:4]
    endian = "<" if magic == b"\xde\x12\x04\x95" else ">" if magic == b"\x95\x04\x12\xde" else ""
    if not endian:
        info["status"] = "not_mo"
        return info
    try:
        revision, count, original_offset, translated_offset, hash_size, hash_offset = struct.unpack_from(f"{endian}6I", header, 4)
        originals = _read_at(path, original_offset, min(count * 8, 80))
        translations = _read_at(path, translated_offset, min(count * 8, 80))
        samples: list[dict[str, int]] = []
        for index in range(min(count, 10)):
            if (index + 1) * 8 > len(originals) or (index + 1) * 8 > len(translations):
                break
            original_len, original_pos = struct.unpack_from(f"{endian}2I", originals, index * 8)
            translated_len, translated_pos = struct.unpack_from(f"{endian}2I", translations, index * 8)
            samples.append(
                {
                    "original_offset": original_pos,
                    "original_length": original_len,
                    "translated_offset": translated_pos,
                    "translated_length": translated_len,
                }
            )
        info.update(
            {
                "status": "parsed_header",
                "revision": revision,
                "string_count": count,
                "hash_size": hash_size,
                "hash_offset": hash_offset,
                "entries_sample": samples,
            }
        )
    except (struct.error, OSError, ValueError) as exc:
        info["status"] = "parse_error"
        info["error"] = str(exc)
    return info


def parse_sfnt(path: Path) -> dict[str, Any]:
    header = _read_at(path, 0, min(path.stat().st_size, 12))
    info: dict[str, Any] = {"parser": "sfnt", "status": "partial", "file_size": path.stat().st_size}
    if len(header) != 12 or header[:4] not in {b"\x00\x01\x00\x00", b"OTTO", b"true", b"typ1"}:
        info["status"] = "not_sfnt"
        return info
    try:
        table_count = struct.unpack_from(">H", header, 4)[0]
        directory = _read_at(path, 12, min(table_count * 16, 16 * 64))
        tables: list[dict[str, Any]] = []
        for index in range(min(table_count, len(directory) // 16)):
            cursor = index * 16
            tag = directory[cursor : cursor + 4].decode("ascii", errors="replace")
            tables.append(
                {
                    "tag": tag,
                    "checksum": hex(struct.unpack_from(">I", directory, cursor + 4)[0]),
                    "offset": struct.unpack_from(">I", directory, cursor + 8)[0],
                    "length": struct.unpack_from(">I", directory, cursor + 12)[0],
                }
            )
        info.update({"status": "parsed_directory", "flavor": header[:4].hex(), "table_count": table_count, "tables_sample": tables})
    except (struct.error, OSError, ValueError) as exc:
        info["status"] = "parse_error"
        info["error"] = str(exc)
    return info


def _read_uleb128(data: bytes, offset: int) -> tuple[int, int] | None:
    value = 0
    shift = 0
    cursor = offset
    for _ in range(5):
        if cursor >= len(data):
            return None
        byte = data[cursor]
        cursor += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, cursor
        shift += 7
    return None


def parse_wasm(path: Path) -> dict[str, Any]:
    data = _read_at(path, 0, min(path.stat().st_size, 1024 * 1024))
    info: dict[str, Any] = {"parser": "wasm", "status": "partial", "file_size": path.stat().st_size}
    if len(data) < 8 or data[:4] != b"\0asm":
        info["status"] = "not_wasm"
        return info
    if data[4:8] != b"\x01\0\0\0":
        info["status"] = "unsupported_version"
        info["version"] = int.from_bytes(data[4:8], "little")
        return info
    cursor = 8
    sections: list[dict[str, int]] = []
    while cursor < len(data) and len(sections) < 64:
        section_id = data[cursor]
        cursor += 1
        parsed = _read_uleb128(data, cursor)
        if parsed is None:
            break
        payload_size, payload_offset = parsed
        sections.append({"id": section_id, "offset": payload_offset, "size": payload_size})
        cursor = payload_offset + payload_size
    info.update({"status": "parsed_sections", "version": 1, "sections_sample": sections})
    return info


def parse_elf(path: Path) -> dict[str, Any]:
    header = _read_at(path, 0, 64)
    info: dict[str, Any] = {"parser": "elf", "status": "partial", "file_size": path.stat().st_size}
    if len(header) < 16 or not header.startswith(b"\x7fELF"):
        info["status"] = "not_elf"
        return info
    elf_class = header[4]
    endian_marker = header[5]
    endian = "<" if endian_marker == 1 else ">" if endian_marker == 2 else ""
    if elf_class not in {1, 2} or not endian:
        info["status"] = "unsupported_ident"
        return info
    try:
        if elf_class == 1:
            e_type, e_machine = struct.unpack_from(f"{endian}HH", header, 16)
            e_phoff, e_shoff = struct.unpack_from(f"{endian}II", header, 28)
            e_phentsize, e_phnum, e_shentsize, e_shnum = struct.unpack_from(f"{endian}HHHH", header, 42)
        else:
            e_type, e_machine = struct.unpack_from(f"{endian}HH", header, 16)
            e_phoff, e_shoff = struct.unpack_from(f"{endian}QQ", header, 32)
            e_phentsize, e_phnum, e_shentsize, e_shnum = struct.unpack_from(f"{endian}HHHH", header, 54)
        info.update(
            {
                "status": "parsed_header",
                "class": "elf64" if elf_class == 2 else "elf32",
                "endianness": "little" if endian == "<" else "big",
                "type": e_type,
                "machine": e_machine,
                "program_header_offset": e_phoff,
                "program_header_count": e_phnum,
                "section_header_offset": e_shoff,
                "section_header_count": e_shnum,
                "program_header_entry_size": e_phentsize,
                "section_header_entry_size": e_shentsize,
            }
        )
    except (struct.error, OSError, ValueError) as exc:
        info["status"] = "parse_error"
        info["error"] = str(exc)
    return info


def parse_pdb(path: Path) -> dict[str, Any]:
    header = _read_at(path, 0, 56)
    info: dict[str, Any] = {"parser": "pdb_msf", "status": "partial", "file_size": path.stat().st_size}
    signature = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"
    if len(header) != 56 or not header.startswith(signature):
        info["status"] = "not_pdb_msf"
        return info
    try:
        block_size = _u32_le(header, 32)
        free_block_map = _u32_le(header, 36)
        block_count = _u32_le(header, 40)
        directory_size = _u32_le(header, 44)
        directory_root = _u32_le(header, 52)
        info.update(
            {
                "status": "parsed_superblock",
                "block_size": block_size,
                "free_block_map": free_block_map,
                "block_count": block_count,
                "directory_size": directory_size,
                "directory_root": directory_root,
            }
        )
    except (struct.error, OSError, ValueError) as exc:
        info["status"] = "parse_error"
        info["error"] = str(exc)
    return info


def parse_bank(path: Path) -> dict[str, Any]:
    data = _read_at(path, 0, min(path.stat().st_size, 1024 * 1024))
    info: dict[str, Any] = {"parser": "wwise_bank", "status": "partial", "file_size": path.stat().st_size}
    if not data.startswith(b"BKHD"):
        info["status"] = "not_wwise_bank"
        return info
    cursor = 0
    chunks: list[dict[str, Any]] = []
    try:
        while cursor + 8 <= len(data) and len(chunks) < 64:
            chunk_id = data[cursor : cursor + 4]
            if not chunk_id.isalpha():
                break
            chunk_size = _u32_le(data, cursor + 4)
            chunks.append({"id": chunk_id.decode("ascii", errors="replace"), "offset": cursor + 8, "size": chunk_size})
            cursor += 8 + chunk_size
        info.update({"status": "parsed_chunks", "chunks_sample": chunks})
    except (struct.error, OSError, ValueError) as exc:
        info["status"] = "parse_error"
        info["error"] = str(exc)
    return info


def parse_gltf(path: Path) -> dict[str, Any]:
    info: dict[str, Any] = {"parser": "gltf_json", "status": "partial", "file_size": path.stat().st_size}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        info["status"] = "parse_error"
        info["error"] = str(exc)
        return info
    if not isinstance(payload, dict):
        info["status"] = "not_gltf_object"
        return info
    asset = payload.get("asset") if isinstance(payload.get("asset"), dict) else {}
    info.update(
        {
            "status": "parsed",
            "asset_version": str(asset.get("version", "")),
            "generator": str(asset.get("generator", "")),
            "scene_count": len(payload.get("scenes", [])) if isinstance(payload.get("scenes"), list) else 0,
            "node_count": len(payload.get("nodes", [])) if isinstance(payload.get("nodes"), list) else 0,
            "mesh_count": len(payload.get("meshes", [])) if isinstance(payload.get("meshes"), list) else 0,
            "material_count": len(payload.get("materials", [])) if isinstance(payload.get("materials"), list) else 0,
            "animation_count": len(payload.get("animations", [])) if isinstance(payload.get("animations"), list) else 0,
            "image_count": len(payload.get("images", [])) if isinstance(payload.get("images"), list) else 0,
        }
    )
    return info


def parse_obj(path: Path) -> dict[str, Any]:
    info: dict[str, Any] = {"parser": "wavefront_obj", "status": "partial", "file_size": path.stat().st_size}
    counts = {"v": 0, "vt": 0, "vn": 0, "f": 0, "o": 0, "g": 0, "usemtl": 0, "mtllib": 0}
    objects: list[str] = []
    materials: list[str] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                keyword, _, rest = stripped.partition(" ")
                if keyword in counts:
                    counts[keyword] += 1
                if keyword in {"o", "g"} and rest and len(objects) < 32:
                    objects.append(rest)
                if keyword in {"usemtl", "mtllib"} and rest and len(materials) < 32:
                    materials.append(rest)
    except OSError as exc:
        info["status"] = "parse_error"
        info["error"] = str(exc)
        return info
    info.update({"status": "parsed", "counts": counts, "objects_sample": objects, "materials_sample": materials})
    return info


def parse_fbx(path: Path) -> dict[str, Any]:
    size = path.stat().st_size
    header = _read_at(path, 0, min(size, 4096))
    info: dict[str, Any] = {"parser": "fbx", "status": "partial", "file_size": size}
    signature = b"Kaydara FBX Binary  \x00\x1a\x00"
    if header.startswith(signature):
        version = _u32_le(header, len(signature)) if len(header) >= len(signature) + 4 else 0
        info.update({"status": "parsed_binary_header", "encoding": "binary", "version": version})
        return info
    try:
        text = header.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        info["status"] = "not_fbx"
        return info
    version_match = re.search(r"FBXVersion:\s*(\d+)", text)
    object_model_count = len(re.findall(r"\b(Model|Geometry|Material|Texture):", text))
    info.update(
        {
            "status": "parsed_text_header" if "FBXHeaderExtension" in text or version_match else "text_fbx_unverified",
            "encoding": "text",
            "version": int(version_match.group(1)) if version_match else 0,
            "objects_in_header_sample": object_model_count,
        }
    )
    return info


def parse_shader(path: Path) -> dict[str, Any]:
    info: dict[str, Any] = {"parser": "shader_source", "status": "partial", "file_size": path.stat().st_size}
    includes: list[str] = []
    uniforms: list[str] = []
    samplers: list[str] = []
    entry_points: list[str] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                stripped = line.strip()
                include = re.match(r'#\s*include\s+[<"]([^>"]+)[>"]', stripped)
                if include and len(includes) < 32:
                    includes.append(include.group(1))
                uniform = re.match(r"\buniform\s+\w+\s+(\w+)", stripped)
                if uniform and len(uniforms) < 64:
                    uniforms.append(uniform.group(1))
                sampler = re.search(r"\b(SamplerState|sampler\w*|Texture\w*)\s+(\w+)", stripped)
                if sampler and len(samplers) < 64:
                    samplers.append(sampler.group(2))
                if re.search(r"\bvoid\s+main\s*\(", stripped) and "main" not in entry_points:
                    entry_points.append("main")
    except OSError as exc:
        info["status"] = "parse_error"
        info["error"] = str(exc)
        return info
    info.update(
        {
            "status": "parsed_source",
            "includes_sample": includes,
            "uniforms_sample": uniforms,
            "samplers_sample": samplers,
            "entry_points_sample": entry_points,
        }
    )
    return info


def parse_unreal_package(path: Path) -> dict[str, Any]:
    size = path.stat().st_size
    header = _read_at(path, 0, min(size, 256))
    info: dict[str, Any] = {"parser": "unreal_package", "status": "partial", "file_size": size}
    if len(header) < 4 or header[:4] != b"\xc1\x83\x2a\x9e":
        info["status"] = "extension_only"
        info["magic"] = header[:8].hex()
        return info
    try:
        fields: dict[str, int] = {
            "legacy_file_version": struct.unpack_from("<i", header, 4)[0] if len(header) >= 8 else 0,
            "legacy_ue3_version": struct.unpack_from("<i", header, 8)[0] if len(header) >= 12 else 0,
            "file_version_ue4": struct.unpack_from("<i", header, 12)[0] if len(header) >= 16 else 0,
            "file_version_licensee_ue4": struct.unpack_from("<i", header, 16)[0] if len(header) >= 20 else 0,
            "custom_version_count": struct.unpack_from("<i", header, 20)[0] if len(header) >= 24 else 0,
        }
        info.update({"status": "parsed_summary_header", "magic": header[:4].hex(), **fields})
    except (struct.error, ValueError) as exc:
        info["status"] = "parse_error"
        info["error"] = str(exc)
    return info


def parse_rpf(path: Path) -> dict[str, Any]:
    size = path.stat().st_size
    header = _read_at(path, 0, min(size, 64))
    info: dict[str, Any] = {"parser": "rockstar_rpf", "status": "partial", "file_size": size}
    if len(header) < 4 or not header.startswith(b"RPF"):
        info["status"] = "extension_only"
        info["magic"] = header[:8].hex()
        return info
    try:
        signature = header[:4].decode("ascii", errors="replace")
        big_values = struct.unpack_from(">III", header, 4) if len(header) >= 16 else (0, 0, 0)
        little_values = struct.unpack_from("<III", header, 4) if len(header) >= 16 else (0, 0, 0)
        info.update(
            {
                "status": "parsed_header",
                "signature": signature,
                "header_values_be": list(big_values),
                "header_values_le": list(little_values),
                "encrypted_or_versioned_index": signature in {"RPF6", "RPF7"},
            }
        )
    except (struct.error, ValueError) as exc:
        info["status"] = "parse_error"
        info["error"] = str(exc)
    return info


def parse_generic_artifact(path: Path, parser_name: str) -> dict[str, Any]:
    size = path.stat().st_size
    sample = _read_at(path, 0, min(size, 4096))
    text_decodable = False
    try:
        sample.decode("utf-8")
        text_decodable = True
    except UnicodeDecodeError:
        text_decodable = False
    return {
        "parser": parser_name,
        "status": "described",
        "file_size": size,
        "magic": sample[:16].hex(),
        "header_entropy": shannon_entropy(sample) if sample else None,
        "text_decodable_sample": text_decodable,
        "strings_sample": strings_preview(sample, 4)[:16],
    }


def _rva_to_offset(rva: int, sections: list[dict[str, Any]]) -> int | None:
    for section in sections:
        virtual_address = int(section["virtual_address"])
        virtual_size = max(int(section["virtual_size"]), int(section["raw_size"]))
        if virtual_address <= rva < virtual_address + virtual_size:
            return int(section["raw_pointer"]) + (rva - virtual_address)
    return None


def _parse_metadata_root(path: Path, offset: int, size: int) -> dict[str, Any]:
    root = _read_at(path, offset, min(size, 8192))
    info: dict[str, Any] = {"offset": offset, "size": size}
    if len(root) < 20 or root[:4] != b"BSJB":
        info["status"] = "metadata_root_not_found"
        return info
    version_length = _u32_le(root, 12)
    version_start = 16
    version_end = version_start + version_length
    version = root[version_start:version_end].rstrip(b"\0").decode("utf-8", errors="replace")
    aligned = (version_end + 3) & ~3
    streams_offset = aligned + 2
    streams: list[dict[str, Any]] = []
    if streams_offset + 2 <= len(root):
        stream_count = _u16_le(root, streams_offset)
        cursor = streams_offset + 2
        for _ in range(min(stream_count, 64)):
            if cursor + 8 > len(root):
                break
            stream_offset = _u32_le(root, cursor)
            stream_size = _u32_le(root, cursor + 4)
            name, name_end = _c_string(root, cursor + 8)
            streams.append({"name": name, "offset": stream_offset, "size": stream_size})
            cursor = (name_end + 3) & ~3
    info.update({"status": "parsed", "version": version, "streams": streams})
    return info


def parse_pe(path: Path) -> dict[str, Any]:
    size = path.stat().st_size
    data = _read_at(path, 0, min(size, 4096))
    info: dict[str, Any] = {"parser": "pe", "status": "partial", "file_size": size}
    if len(data) < 0x40 or data[:2] != b"MZ":
        info["status"] = "not_pe"
        return info
    try:
        pe_offset = _u32_le(data, 0x3C)
        pe_header = _read_at(path, pe_offset, 4096)
        if len(pe_header) < 24 or pe_header[:4] != b"PE\0\0":
            info["status"] = "pe_header_not_found"
            return info
        machine = _u16_le(pe_header, 4)
        section_count = _u16_le(pe_header, 6)
        timestamp = _u32_le(pe_header, 8)
        optional_size = _u16_le(pe_header, 20)
        optional_offset = 24
        optional = pe_header[optional_offset : optional_offset + optional_size]
        magic = _u16_le(optional, 0) if len(optional) >= 2 else 0
        is_pe32_plus = magic == 0x20B
        data_directory_offset = 112 if is_pe32_plus else 96
        clr_rva = clr_size = 0
        if len(optional) >= data_directory_offset + (15 * 8):
            clr_dir = data_directory_offset + (14 * 8)
            clr_rva = _u32_le(optional, clr_dir)
            clr_size = _u32_le(optional, clr_dir + 4)
        sections: list[dict[str, Any]] = []
        section_offset = pe_offset + 24 + optional_size
        section_data = _read_at(path, section_offset, min(section_count * 40, 4096))
        for index in range(section_count):
            cursor = index * 40
            if cursor + 40 > len(section_data):
                break
            raw_name = section_data[cursor : cursor + 8].split(b"\0", 1)[0]
            sections.append(
                {
                    "name": raw_name.decode("ascii", errors="replace"),
                    "virtual_size": _u32_le(section_data, cursor + 8),
                    "virtual_address": _u32_le(section_data, cursor + 12),
                    "raw_size": _u32_le(section_data, cursor + 16),
                    "raw_pointer": _u32_le(section_data, cursor + 20),
                }
            )
        info.update(
            {
                "status": "parsed_header",
                "pe_offset": pe_offset,
                "machine": hex(machine),
                "timestamp": timestamp,
                "section_count": section_count,
                "optional_magic": hex(magic),
                "architecture": "pe32_plus" if is_pe32_plus else "pe32",
                "sections": sections[:16],
                "is_dotnet": bool(clr_rva),
            }
        )
        metadata_offset: int | None = None
        metadata_size = 0
        if clr_rva:
            clr_offset = _rva_to_offset(clr_rva, sections)
            info["clr_header"] = {"rva": clr_rva, "size": clr_size, "offset": clr_offset}
            if clr_offset is not None:
                clr = _read_at(path, clr_offset, min(clr_size or 72, 256))
                if len(clr) >= 24:
                    metadata_rva = _u32_le(clr, 8)
                    metadata_size = _u32_le(clr, 12)
                    flags = _u32_le(clr, 16)
                    entry_point = _u32_le(clr, 20)
                    metadata_offset = _rva_to_offset(metadata_rva, sections)
                    info["clr_header"].update(
                        {
                            "runtime_version": f"{_u16_le(clr, 4)}.{_u16_le(clr, 6)}",
                            "metadata_rva": metadata_rva,
                            "metadata_size": metadata_size,
                            "metadata_offset": metadata_offset,
                            "flags": flags,
                            "entry_point_token_or_rva": entry_point,
                        }
                    )
        if metadata_offset is not None:
            info["dotnet_metadata"] = _parse_metadata_root(path, metadata_offset, metadata_size)
            info["dotnet_tables"] = inspect_assembly(path, info)
    except (struct.error, OSError, ValueError) as exc:
        info["status"] = "parse_error"
        info["error"] = str(exc)
    return info


def register_builtin_parsers(registry: object) -> None:
    registry.add_parser(
        parse_unity_serialized_file,
        name="unity_serialized_file",
        type_names={"assets"},
        extensions={".assets"},
        file_names={"globalgamemanagers", "unity default resources"},
        stream_safe=True,
    )
    registry.add_parser(parse_unity_bundle, name="unity_bundle", type_names={"bundle"}, extensions={".bundle"}, stream_safe=True)
    registry.add_parser(parse_unity_resource, name="unity_resource", type_names={"resource"}, extensions={".resource", ".ress"}, stream_safe=True)
    registry.add_parser(parse_jpeg, name="jpeg", type_names={"jpg"}, extensions={".jpg", ".jpeg"}, stream_safe=True)
    registry.add_parser(parse_dds, name="dds", type_names={"dds"}, extensions={".dds"}, stream_safe=True)
    registry.add_parser(parse_tga, name="tga", type_names={"tga"}, extensions={".tga"}, stream_safe=True)
    registry.add_parser(parse_fsb, name="fsb5", type_names={"fsb"}, extensions={".fsb"}, stream_safe=True)
    registry.add_parser(parse_mo, name="gnu_mo", type_names={"mo"}, extensions={".mo"}, stream_safe=True)
    registry.add_parser(parse_sfnt, name="sfnt", type_names={"ttf", "otf"}, extensions={".ttf", ".otf"}, stream_safe=True)
    registry.add_parser(parse_wasm, name="wasm", type_names={"wasm"}, extensions={".wasm"}, stream_safe=True)
    registry.add_parser(parse_elf, name="elf", type_names={"so"}, extensions={".so"}, stream_safe=True)
    registry.add_parser(parse_pdb, name="pdb_msf", type_names={"pdb"}, extensions={".pdb"}, stream_safe=True)
    registry.add_parser(parse_bank, name="wwise_bank", type_names={"bank"}, extensions={".bank"}, stream_safe=True)
    registry.add_parser(parse_gltf, name="gltf_json", type_names={"gltf"}, extensions={".gltf"})
    registry.add_parser(parse_obj, name="wavefront_obj", type_names={"obj"}, extensions={".obj"})
    registry.add_parser(parse_fbx, name="fbx", type_names={"fbx"}, extensions={".fbx"}, stream_safe=True)
    registry.add_parser(parse_shader, name="shader_source", type_names={"hlsl", "glsl"}, extensions={".hlsl", ".glsl", ".frag", ".vert"})
    registry.add_parser(parse_unreal_package, name="unreal_package", type_names={"uasset", "umap"}, extensions={".uasset", ".umap"}, stream_safe=True)
    registry.add_parser(parse_rpf, name="rockstar_rpf", type_names={"rpf"}, extensions={".rpf"}, stream_safe=True)
    registry.add_parser(lambda path: parse_generic_artifact(path, "level_artifact"), name="level_artifact", type_names={"lvl"}, extensions={".lvl"}, stream_safe=True)
    registry.add_parser(
        lambda path: parse_generic_artifact(path, "generic_game_data"),
        name="generic_game_data",
        type_names={"sav", "dat"},
        extensions={".sav", ".dat", ".data"},
        stream_safe=True,
    )
    registry.add_parser(parse_pe, name="pe", type_names={"dll", "exe"}, extensions={".dll", ".exe"}, stream_safe=True)


def parse_file(path: str | Path, identified_type: str, category: str = "") -> dict[str, Any]:
    from .registry import get_active_registry

    return get_active_registry().parse_file(path, identified_type, category)
