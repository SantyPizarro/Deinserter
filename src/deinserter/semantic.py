from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .resources import write_bytes_atomic
from .utils import ensure_unique, safe_relative_path, shannon_entropy, strings_preview


IGNORED_SEMANTIC_EXTENSIONS = {
    ".lvl",
    ".ttf",
    ".otf",
    ".dll",
    ".exe",
    ".so",
    ".wasm",
    ".pdb",
}


@dataclass(frozen=True, slots=True)
class SemanticSpec:
    semantic_classification: str
    backend: str
    strategy: str
    note: str


NO_CONVERSION = "no_hace_falta"
REAL_RECOMPILE = "recompilacion_real"
PSEUDOCODE = "pseudocodigo"


SEMANTIC_SPECS: dict[str, SemanticSpec] = {
    ".png": SemanticSpec(NO_CONVERSION, "nativo", "preserve_final_asset", "Formato final usable."),
    ".jpg": SemanticSpec(NO_CONVERSION, "nativo", "preserve_final_asset", "Formato final usable."),
    ".jpeg": SemanticSpec(NO_CONVERSION, "nativo", "preserve_final_asset", "Formato final usable."),
    ".dds": SemanticSpec(NO_CONVERSION, "nativo", "preserve_final_asset", "Textura final; decodificar seria transcodificacion."),
    ".tga": SemanticSpec(NO_CONVERSION, "nativo", "preserve_final_asset", "Textura final usable."),
    ".ktx": SemanticSpec(NO_CONVERSION, "nativo", "preserve_final_asset", "Textura final usable."),
    ".wav": SemanticSpec(NO_CONVERSION, "nativo", "preserve_final_asset", "Audio final usable."),
    ".ogg": SemanticSpec(NO_CONVERSION, "nativo", "preserve_final_asset", "Audio final usable."),
    ".fsb": SemanticSpec(NO_CONVERSION, "nativo", "preserve_container", "Container FMOD conservado fielmente."),
    ".bank": SemanticSpec(NO_CONVERSION, "mixto", "preserve_container", "Bank conservado; metadata profunda puede requerir backend externo."),
    ".fbx": SemanticSpec(NO_CONVERSION, "mixto", "preserve_model", "Modelo final; binario a ASCII seria transcodificacion."),
    ".obj": SemanticSpec(NO_CONVERSION, "n/a", "preserve_text", "Modelo de texto ya legible."),
    ".gltf": SemanticSpec(NO_CONVERSION, "n/a", "preserve_text", "glTF JSON ya legible."),
    ".glb": SemanticSpec(NO_CONVERSION, "nativo", "extract_glb_json_chunk", "Se puede separar el chunk JSON sin decompilar."),
    ".hlsl": SemanticSpec(NO_CONVERSION, "n/a", "preserve_text", "Shader fuente ya legible."),
    ".glsl": SemanticSpec(NO_CONVERSION, "n/a", "preserve_text", "Shader fuente ya legible."),
    ".frag": SemanticSpec(NO_CONVERSION, "n/a", "preserve_text", "Shader fuente ya legible."),
    ".vert": SemanticSpec(NO_CONVERSION, "n/a", "preserve_text", "Shader fuente ya legible."),
    ".po": SemanticSpec(NO_CONVERSION, "n/a", "preserve_text", "Localizacion fuente ya legible."),
    ".mo": SemanticSpec(REAL_RECOMPILE, "nativo", "mo_to_po", "Transcodificacion determinista validable con msgfmt."),
    ".json": SemanticSpec(NO_CONVERSION, "n/a", "preserve_text", "Datos texto ya legibles."),
    ".xml": SemanticSpec(NO_CONVERSION, "n/a", "preserve_text", "Datos texto ya legibles."),
    ".yaml": SemanticSpec(NO_CONVERSION, "n/a", "preserve_text", "Datos texto ya legibles."),
    ".yml": SemanticSpec(NO_CONVERSION, "n/a", "preserve_text", "Datos texto ya legibles."),
    ".csv": SemanticSpec(NO_CONVERSION, "n/a", "preserve_text", "Datos tabulares ya legibles."),
    ".ini": SemanticSpec(NO_CONVERSION, "n/a", "preserve_text", "Config texto ya legible."),
    ".cfg": SemanticSpec(NO_CONVERSION, "n/a", "preserve_text", "Config texto ya legible."),
    ".sav": SemanticSpec(PSEUDOCODE, "nativo", "generic_binary_pseudocode", "Heuristica conservadora para datos genericos."),
    ".dat": SemanticSpec(PSEUDOCODE, "nativo", "generic_binary_pseudocode", "Heuristica conservadora para datos genericos."),
    ".data": SemanticSpec(PSEUDOCODE, "nativo", "generic_binary_pseudocode", "Heuristica conservadora para datos genericos."),
    ".zip": SemanticSpec(NO_CONVERSION, "nativo", "preserve_container", "Container; entradas se clasifican por separado."),
    ".gpak": SemanticSpec(NO_CONVERSION, "nativo", "preserve_container", "Container; entradas se clasifican por separado."),
    ".pak": SemanticSpec(NO_CONVERSION, "nativo", "preserve_container", "Container; entradas se clasifican por separado."),
    ".vpk": SemanticSpec(NO_CONVERSION, "nativo", "preserve_container", "Container; entradas se clasifican por separado."),
    ".rpf": SemanticSpec(NO_CONVERSION, "nativo", "preserve_container", "Container Rockstar conservado fielmente."),
    ".assets": SemanticSpec(REAL_RECOMPILE, "nativo", "unity_reconstruction_pipeline", "SerializedFile Unity cubierto por el pipeline Unity."),
    ".bundle": SemanticSpec(REAL_RECOMPILE, "nativo", "unity_reconstruction_pipeline", "UnityFS cubierto por el pipeline Unity."),
    ".resource": SemanticSpec(NO_CONVERSION, "nativo", "preserve_resource_blob", "Blob de recurso externo Unity."),
    ".ress": SemanticSpec(NO_CONVERSION, "nativo", "preserve_resource_blob", "Blob de recurso externo Unity."),
    ".uasset": SemanticSpec(PSEUDOCODE, "externo", "unreal_header_pseudocode", "Resumen conservador; expansion profunda requiere backend Unreal."),
    ".umap": SemanticSpec(PSEUDOCODE, "externo", "unreal_header_pseudocode", "Resumen conservador; expansion profunda requiere backend Unreal."),
}


def semantic_spec_for_extension(extension: str) -> SemanticSpec | None:
    ext = extension.lower()
    if ext in IGNORED_SEMANTIC_EXTENSIONS:
        return None
    return SEMANTIC_SPECS.get(ext)


def semantic_output_base(root: Path, file_path: Path, output_dir: Path, suffix: str, overwrite: bool) -> Path:
    relative = safe_relative_path(file_path, root if root.is_dir() else file_path.parent)
    destination = output_dir / "semantic" / relative
    destination = destination.with_name(destination.name + suffix)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not overwrite:
        destination = ensure_unique(destination)
    return destination


def _po_escape(value: bytes) -> str:
    text = value.decode("utf-8", errors="replace")
    return text.replace("\\", "\\\\").replace("\t", "\\t").replace("\r", "\\r").replace("\n", "\\n").replace('"', '\\"')


def _read_mo_entries(path: Path) -> list[tuple[bytes, bytes]]:
    data = path.read_bytes()
    if len(data) < 28:
        raise ValueError("mo_too_short")
    magic = data[:4]
    endian = "<" if magic == b"\xde\x12\x04\x95" else ">" if magic == b"\x95\x04\x12\xde" else ""
    if not endian:
        raise ValueError("not_mo")
    _revision, count, originals_offset, translations_offset, _hash_size, _hash_offset = struct.unpack_from(
        f"{endian}6I", data, 4
    )
    entries: list[tuple[bytes, bytes]] = []
    for index in range(count):
        original_table_offset = originals_offset + index * 8
        translation_table_offset = translations_offset + index * 8
        if original_table_offset + 8 > len(data) or translation_table_offset + 8 > len(data):
            raise ValueError("mo_table_out_of_bounds")
        original_length, original_offset = struct.unpack_from(f"{endian}2I", data, original_table_offset)
        translation_length, translation_offset = struct.unpack_from(f"{endian}2I", data, translation_table_offset)
        if original_offset + original_length > len(data) or translation_offset + translation_length > len(data):
            raise ValueError("mo_string_out_of_bounds")
        entries.append(
            (
                data[original_offset : original_offset + original_length],
                data[translation_offset : translation_offset + translation_length],
            )
        )
    return entries


def _po_from_mo(path: Path) -> bytes:
    entries = _read_mo_entries(path)
    lines = ["# Generated by Deinserter from GNU MO", ""]
    for original, translated in entries:
        context = b""
        msgid = original
        if b"\x04" in original:
            context, msgid = original.split(b"\x04", 1)
            lines.append(f'msgctxt "{_po_escape(context)}"')
        if b"\0" in msgid:
            singular, plural = msgid.split(b"\0", 1)
            translations = translated.split(b"\0")
            lines.append(f'msgid "{_po_escape(singular)}"')
            lines.append(f'msgid_plural "{_po_escape(plural)}"')
            for index, item in enumerate(translations):
                lines.append(f'msgstr[{index}] "{_po_escape(item)}"')
        else:
            lines.append(f'msgid "{_po_escape(msgid)}"')
            lines.append(f'msgstr "{_po_escape(translated)}"')
        lines.append("")
    return "\n".join(lines).encode("utf-8")


def _glb_json(path: Path) -> bytes:
    data = path.read_bytes()
    if len(data) < 20 or data[:4] != b"glTF":
        raise ValueError("not_glb")
    version, total_length = struct.unpack_from("<II", data, 4)
    if version != 2 or total_length > len(data):
        raise ValueError("unsupported_glb")
    cursor = 12
    while cursor + 8 <= total_length:
        chunk_length, chunk_type = struct.unpack_from("<II", data, cursor)
        cursor += 8
        end = cursor + chunk_length
        if end > total_length:
            raise ValueError("glb_chunk_out_of_bounds")
        if chunk_type == 0x4E4F534A:
            return data[cursor:end].rstrip(b" \0")
        cursor = (end + 3) & ~3
    raise ValueError("glb_json_chunk_missing")


def _generic_pseudocode(path: Path) -> bytes:
    size = path.stat().st_size
    with path.open("rb") as handle:
        sample = handle.read(min(size, 64 * 1024))
    ascii_bytes = sum(1 for byte in sample if byte in b"\t\r\n" or 32 <= byte <= 126)
    nul_bytes = sample.count(0)
    profile = {
        "parser": "generic_binary_pseudocode",
        "status": "heuristic",
        "file_size": size,
        "sample_size": len(sample),
        "sample_entropy": shannon_entropy(sample) if sample else 0.0,
        "ascii_ratio": ascii_bytes / len(sample) if sample else 0.0,
        "nul_ratio": nul_bytes / len(sample) if sample else 0.0,
        "strings_preview": strings_preview(sample, 6),
        "limits": "Schema is game-specific; this is a conservative heuristic profile, not a reversible source format.",
    }
    return json.dumps(profile, indent=2, ensure_ascii=False).encode("utf-8")


def _unreal_pseudocode(path: Path, parse_info: dict[str, Any]) -> bytes:
    payload = {
        "parser": "unreal_header_pseudocode",
        "status": "metadata_only",
        "source_path": str(path),
        "parse_info": parse_info,
        "limits": "Exports, imports, name maps and bulk data need an Unreal-version-aware backend.",
    }
    return json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")


def build_semantic_conversion(
    root: Path,
    file_path: Path,
    output_dir: Path | None,
    extension: str,
    identified_type: str,
    category: str,
    parse_info: dict[str, Any],
    mode: str,
    overwrite: bool,
    can_write: Callable[[int], bool] | None = None,
    input_path: Path | None = None,
) -> dict[str, object] | None:
    read_path = input_path or file_path
    spec = semantic_spec_for_extension(extension)
    if spec is None:
        return None
    item: dict[str, object] = {
        "source_path": str(file_path),
        "extension": extension.lower(),
        "identified_type": identified_type,
        "category": category,
        "semantic_classification": spec.semantic_classification,
        "backend": spec.backend,
        "strategy": spec.strategy,
        "status": "no_conversion_required" if spec.semantic_classification == NO_CONVERSION else "planned",
        "output_path": "",
        "note": spec.note,
    }
    if output_dir is None or mode == "manifest_only":
        return item

    try:
        destination: Path | None = None
        payload: bytes | None = None
        if spec.strategy == "mo_to_po":
            destination = semantic_output_base(root, file_path, output_dir, ".po", overwrite)
            payload = _po_from_mo(read_path)
        elif spec.strategy == "extract_glb_json_chunk":
            destination = semantic_output_base(root, file_path, output_dir, ".gltf.json", overwrite)
            payload = _glb_json(read_path)
        elif spec.strategy == "generic_binary_pseudocode":
            destination = semantic_output_base(root, file_path, output_dir, ".semantic.json", overwrite)
            payload = _generic_pseudocode(read_path)
        elif spec.strategy == "unreal_header_pseudocode":
            destination = semantic_output_base(root, file_path, output_dir, ".semantic.json", overwrite)
            payload = _unreal_pseudocode(file_path, parse_info)
        elif spec.strategy == "unity_reconstruction_pipeline":
            item["status"] = "handled_by_unity_pipeline"
        if destination is not None and payload is not None:
            if can_write is not None and not can_write(len(payload)):
                item.update({"status": "blocked_output_budget", "output_path": "", "output_length": 0})
                return item
            write_bytes_atomic(destination, payload)
            conversion_status = "pseudocode" if spec.semantic_classification == PSEUDOCODE else "converted"
            item.update(
                {
                    "status": conversion_status,
                    "output_path": str(destination),
                    "output_length": len(payload),
                }
            )
    except (OSError, ValueError, struct.error) as exc:
        item.update({"status": "semantic_conversion_failed", "error": str(exc)})
    return item
