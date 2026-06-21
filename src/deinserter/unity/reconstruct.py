from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..resources import copy_range_streaming
from ..utils import ensure_unique
from .serialized import UnityObject


SELECTIVE_CLASS_IDS = {21, 28, 43, 48, 49, 83, 114, 213}
SEMANTIC_CLASS_IDS = {21, 28, 43, 83, 114}
METADATA_ONLY_CLASS_IDS = {21, 43, 48, 114}


def should_reconstruct_unity_object(obj: UnityObject, mode: str, include_categories: list[str] | None = None) -> bool:
    if mode == "manifest_only":
        return False
    if include_categories and "unity_objects" not in include_categories:
        return False
    if mode == "full":
        return True
    return obj.class_id in SELECTIVE_CLASS_IDS


def _safe_stem(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value)
    return cleaned.strip("._") or "object"


def _norm(value: str) -> str:
    return value.lower().replace("_", "").replace(" ", "")


def _field(fields: dict[str, Any], *aliases: str) -> Any:
    wanted = {_norm(alias) for alias in aliases}
    for key, value in fields.items():
        if _norm(str(key)) in wanted:
            return value
    for value in fields.values():
        if isinstance(value, dict):
            found = _field(value, *aliases)
            if found is not None:
                return found
    return None


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _external_outputs(obj: UnityObject) -> list[dict[str, Any]]:
    outputs: list[dict[str, Any]] = []
    for item in obj.streaming_infos:
        if item.get("output_path"):
            outputs.append(
                {
                    "output_path": str(item.get("output_path") or ""),
                    "resource_kind": str(item.get("resource_kind") or ""),
                    "resolved_path": str(item.get("resolved_path") or ""),
                    "source_offset": int(item.get("offset") or 0),
                    "length": int(item.get("size") or 0),
                    "sha256": str(item.get("sha256") or ""),
                }
            )
    return outputs


def _semantic_status(obj: UnityObject, fields: dict[str, Any]) -> str:
    if obj.decode_status == "raw_payload":
        return "raw_payload"
    if obj.decode_status == "partial_typetree" or "__decode_error__" in fields:
        return "partial"
    return "decoded" if fields else "metadata_only"


def _semantic_base(obj: UnityObject) -> dict[str, Any]:
    fields = obj.decoded_fields
    return {
        "class_name": obj.type_name,
        "path_id": obj.path_id,
        "source_file": obj.source_path,
        "semantic_status": _semantic_status(obj, fields),
        "decode_status": obj.decode_status,
        "fields": fields,
        "references": [item.to_dict() for item in obj.pptr_references],
        "external_resources": obj.streaming_infos,
        "raw_payload": {},
        "exported_files": [],
    }


def _payload_kind(data: bytes, obj: UnityObject) -> tuple[str, str]:
    if obj.class_id == 49:
        try:
            text = data.decode("utf-8")
            printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
            if text and printable / max(1, len(text)) > 0.85:
                return ".txt", "decoded"
        except UnicodeDecodeError:
            pass
        return ".bin", "raw_payload"
    if obj.class_id in {28, 213}:
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            return ".png", "decoded"
        if data.startswith(b"\xff\xd8\xff"):
            return ".jpg", "decoded"
        return ".texture.bin", "raw_payload"
    if obj.class_id == 83:
        if data.startswith(b"RIFF") and data[8:12] == b"WAVE":
            return ".wav", "decoded"
        if data.startswith(b"OggS"):
            return ".ogg", "decoded"
        if data.startswith(b"FSB5"):
            return ".fsb", "raw_payload"
        return ".audio.bin", "raw_payload"
    if obj.class_id in METADATA_ONLY_CLASS_IDS:
        return ".object.bin", "metadata_only"
    return ".object.bin", "raw_payload"


def _copy_raw_payload(
    obj: UnityObject,
    target_dir: Path,
    stem: str,
    extension: str,
    overwrite: bool,
    hash_output: bool,
    chunk_size: int,
) -> tuple[Path, str]:
    source = Path(obj.source_path)
    output_path = target_dir / f"{stem}{extension}"
    if output_path.exists() and not overwrite:
        output_path = ensure_unique(output_path)
    sha256 = copy_range_streaming(source, output_path, obj.offset, obj.size, chunk_size, hash_output)
    return output_path, sha256


def _write_json_sidecar(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _texture_semantic(obj: UnityObject) -> dict[str, Any]:
    semantic = _semantic_base(obj)
    fields = obj.decoded_fields
    semantic["metadata"] = {
        "name": _field(fields, "m_Name", "name"),
        "width": _field(fields, "m_Width", "width"),
        "height": _field(fields, "m_Height", "height"),
        "texture_format": _field(fields, "m_TextureFormat", "textureFormat"),
        "mip_count": _field(fields, "m_MipCount", "mipCount"),
    }
    return semantic


def _audio_semantic(obj: UnityObject) -> dict[str, Any]:
    semantic = _semantic_base(obj)
    fields = obj.decoded_fields
    semantic["metadata"] = {
        "name": _field(fields, "m_Name", "name"),
        "length": _field(fields, "m_Length", "length"),
        "channels": _field(fields, "m_Channels", "channels"),
        "frequency": _field(fields, "m_Frequency", "frequency"),
        "bits_per_sample": _field(fields, "m_BitsPerSample", "bitsPerSample"),
        "load_type": _field(fields, "m_LoadType", "loadType"),
        "compression_format": _field(fields, "m_CompressionFormat", "compressionFormat"),
    }
    return semantic


def _mesh_values(obj: UnityObject) -> tuple[list[Any], list[Any]]:
    fields = obj.decoded_fields
    vertices = _as_list(_field(fields, "m_Vertices", "vertices", "m_VertexData"))
    indices = _as_list(_field(fields, "m_Indices", "indices", "m_IndexBuffer"))
    return vertices, indices


def _vertex_triplet(value: Any) -> tuple[float, float, float] | None:
    if isinstance(value, dict):
        try:
            return float(value.get("x", 0)), float(value.get("y", 0)), float(value.get("z", 0))
        except (TypeError, ValueError):
            return None
    if isinstance(value, list) and len(value) >= 3:
        try:
            return float(value[0]), float(value[1]), float(value[2])
        except (TypeError, ValueError):
            return None
    return None


def _export_obj(vertices: list[Any], indices: list[Any], target_dir: Path, stem: str, overwrite: bool) -> Path | None:
    parsed_vertices = [_vertex_triplet(item) for item in vertices]
    if not parsed_vertices or any(item is None for item in parsed_vertices):
        return None
    try:
        parsed_indices = [int(item) for item in indices]
    except (TypeError, ValueError):
        return None
    if len(parsed_indices) < 3:
        return None
    output_path = target_dir / f"{stem}.obj"
    if output_path.exists() and not overwrite:
        output_path = ensure_unique(output_path)
    lines: list[str] = []
    for vertex in parsed_vertices:
        assert vertex is not None
        lines.append(f"v {vertex[0]:.9g} {vertex[1]:.9g} {vertex[2]:.9g}")
    for index in range(0, len(parsed_indices) - 2, 3):
        a, b, c = parsed_indices[index : index + 3]
        if min(a, b, c) < 0 or max(a, b, c) >= len(parsed_vertices):
            return None
        lines.append(f"f {a + 1} {b + 1} {c + 1}")
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output_path


def _mesh_semantic(obj: UnityObject, target_dir: Path, stem: str, overwrite: bool) -> dict[str, Any]:
    semantic = _semantic_base(obj)
    fields = obj.decoded_fields
    vertices, indices = _mesh_values(obj)
    semantic["metadata"] = {
        "vertex_count": len(vertices),
        "index_count": len(indices),
        "submeshes": _field(fields, "m_SubMeshes", "subMeshes"),
        "bounds": _field(fields, "m_Bounds", "bounds"),
        "normals": _field(fields, "m_Normals", "normals"),
        "uvs": _field(fields, "m_UV", "uv", "uvs"),
    }
    obj_path = _export_obj(vertices, indices, target_dir, stem, overwrite)
    if obj_path is not None:
        semantic["exported_files"].append({"kind": "obj", "output_path": str(obj_path)})
    elif vertices:
        semantic["semantic_status"] = "partial"
    return semantic


def _material_semantic(obj: UnityObject) -> dict[str, Any]:
    semantic = _semantic_base(obj)
    fields = obj.decoded_fields
    semantic["metadata"] = {
        "name": _field(fields, "m_Name", "name"),
        "shader": _field(fields, "m_Shader", "shader"),
        "saved_properties": _field(fields, "m_SavedProperties", "savedProperties"),
        "texture_references": [
            item.to_dict()
            for item in obj.pptr_references
            if item.target_type_name in {"Texture", "Texture2D"} or item.target_class_id in {28, 213}
        ],
    }
    return semantic


def _mono_behaviour_semantic(obj: UnityObject) -> dict[str, Any]:
    semantic = _semantic_base(obj)
    semantic["metadata"] = {
        "script": _field(obj.decoded_fields, "m_Script", "script"),
        "game_object": _field(obj.decoded_fields, "m_GameObject", "gameObject"),
    }
    return semantic


def _semantic_for_object(obj: UnityObject, target_dir: Path, stem: str, overwrite: bool) -> dict[str, Any]:
    if obj.class_id == 28:
        return _texture_semantic(obj)
    if obj.class_id == 83:
        return _audio_semantic(obj)
    if obj.class_id == 43:
        return _mesh_semantic(obj, target_dir, stem, overwrite)
    if obj.class_id == 21:
        return _material_semantic(obj)
    if obj.class_id == 114:
        return _mono_behaviour_semantic(obj)
    return _semantic_base(obj)


def reconstruct_unity_object(
    obj: UnityObject,
    output_root: str | Path,
    *,
    overwrite: bool = False,
    hash_output: bool = True,
    chunk_size: int = 8 * 1024 * 1024,
    max_object_bytes: int | None = None,
    extract_raw_objects: bool = False,
    decode_media: bool = False,
) -> dict[str, Any]:
    if max_object_bytes is not None and obj.size > max_object_bytes:
        return {
            "source_path": obj.source_path,
            "path_id": obj.path_id,
            "class_id": obj.class_id,
            "type_name": obj.type_name,
            "source_offset": obj.offset,
            "length": obj.size,
            "reconstruction_status": "blocked_budget",
            "semantic_status": "blocked_budget",
            "reason": "blocked_unity_object_budget",
        }

    source = Path(obj.source_path)
    target_dir = Path(output_root) / "unity_objects" / _safe_stem(source.stem)
    target_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{_safe_stem(obj.type_name)}_{obj.path_id}"

    with source.open("rb") as handle:
        handle.seek(obj.offset)
        preview = handle.read(min(obj.size, 4096))
    extension, payload_status = _payload_kind(preview, obj)
    semantic = _semantic_for_object(obj, target_dir, stem, overwrite)
    external_outputs = _external_outputs(obj)
    semantic["external_outputs"] = external_outputs
    semantic["raw_payload"] = {
        "source_offset": obj.offset,
        "source_size": obj.size,
        "copied": False,
        "output_path": "",
        "sha256": "",
    }

    should_copy_raw = (
        obj.class_id not in SEMANTIC_CLASS_IDS
        or extract_raw_objects
        or not external_outputs and obj.class_id in {28, 83}
    )
    output_path: Path | None = None
    sha256 = ""
    payload_length = 0
    if should_copy_raw and (payload_status != "metadata_only" or extract_raw_objects):
        output_path, sha256 = _copy_raw_payload(obj, target_dir, stem, extension, overwrite, hash_output, chunk_size)
        payload_length = obj.size
        semantic["raw_payload"].update({"copied": True, "output_path": str(output_path), "sha256": sha256})

    if output_path is None and external_outputs:
        output_path = Path(str(external_outputs[0]["output_path"]))

    sidecar_path = target_dir / f"{stem}.json"
    if sidecar_path.exists() and not overwrite:
        sidecar_path = ensure_unique(sidecar_path)

    reconstruction_status = semantic.get("semantic_status") if obj.class_id in SEMANTIC_CLASS_IDS else payload_status
    sidecar = {
        "source_file": obj.source_path,
        "path_id": obj.path_id,
        "class_id": obj.class_id,
        "type": obj.type_name,
        "source_offset": obj.offset,
        "source_size": obj.size,
        "external_resource": obj.external_resource,
        "decode_status": obj.decode_status,
        "decoded_fields": obj.decoded_fields,
        "pptr_references": [item.to_dict() for item in obj.pptr_references],
        "streaming_infos": obj.streaming_infos,
        "decoder_status": "decoder_unavailable" if decode_media and obj.class_id in {28, 83} and payload_status == "raw_payload" else "",
        "reconstruction_status": reconstruction_status,
        "semantic_status": semantic.get("semantic_status", ""),
        "semantic": semantic,
        "output_path": str(output_path) if output_path is not None else "",
    }
    _write_json_sidecar(sidecar_path, sidecar)
    return {
        "output_path": str(output_path or sidecar_path),
        "sidecar_path": str(sidecar_path),
        "semantic_sidecar_path": str(sidecar_path),
        "payload_output_path": str(output_path) if output_path is not None else "",
        "semantic_type": obj.type_name if obj.class_id in SEMANTIC_CLASS_IDS else "",
        "semantic_status": str(semantic.get("semantic_status", "")),
        "external_outputs_sample": external_outputs[:5],
        "type": obj.type_name,
        "class_id": obj.class_id,
        "path_id": obj.path_id,
        "source_path": obj.source_path,
        "source_offset": obj.offset,
        "length": payload_length,
        "sha256": sha256,
        "validation_status": "unity_object_range",
        "reconstruction_status": reconstruction_status,
        "category": "unity_objects",
        "decompile_value": "high" if obj.class_id in {49, 114, 48, 21} else "medium",
    }
