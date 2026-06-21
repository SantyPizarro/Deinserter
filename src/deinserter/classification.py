from __future__ import annotations

from pathlib import Path

SELECTIVE_CATEGORIES = {"scripts", "data", "levels", "shaders", "containers"}


def classify_asset(name: str, detected_type: str = "", registry: object | None = None) -> dict[str, str]:
    normalized = name.replace("\\", "/").lower()
    ext = Path(normalized).suffix
    filename = Path(normalized).name
    top = normalized.split("/", 1)[0] if normalized else ""
    detected = detected_type.lower()

    if registry is None:
        from .registry import get_active_registry

        registry = get_active_registry()

    spec = registry.find_format_by_type(detected) or registry.find_format_by_extension(ext)
    if spec is not None:
        category = spec.category
        role = spec.role
        value = spec.decompile_value
    elif filename in {"globalgamemanagers", "unity default resources"}:
        category = "containers"
        role = "unity_engine_resource_container"
        value = "high"
    elif detected in {"gpak", "zip"} or ext in {".gpak", ".zip", ".bundle"}:
        category = "containers"
        role = "archive_or_asset_container"
        value = "high"
    elif ext in {".js", ".lua", ".py", ".cs", ".as", ".rpy", ".bat", ".cmd", ".ps1"}:
        category = "scripts"
        role = "source_or_script_text"
        value = "high"
    elif top == "levels" or ext == ".lvl":
        category = "levels"
        role = "map_or_level_data"
        value = "high"
    elif top == "shaders" or ext in {".shader", ".frag", ".vert", ".glsl", ".hlsl"}:
        category = "shaders"
        role = "rendering_program_text"
        value = "high"
    elif top == "data" or ext in {".gon", ".json", ".xml", ".ini", ".cfg", ".txt", ".csv", ".data"}:
        category = "data"
        role = "game_data_or_config"
        value = "high"
    elif top == "audio" or ext in {".wav", ".ogg", ".mid", ".mp3", ".flac", ".aac"}:
        category = "audio"
        role = "soundtrack_or_sfx"
        value = "low"
    elif top == "textures" or ext in {".png", ".dds", ".ktx", ".jpg", ".jpeg", ".tga", ".bmp", ".webp"}:
        category = "textures"
        role = "image_asset"
        value = "low"
    elif ext in {".mp4", ".webm", ".avi", ".mov", ".mkv"}:
        category = "video"
        role = "video_asset"
        value = "low"
    elif ext in {".swf", ".abc", ".pyo", ".pyc", ".dll", ".exe"}:
        category = "bytecode" if ext in {".swf", ".abc", ".pyo", ".pyc"} else "runtime"
        role = "compiled_code_or_runtime_binary"
        value = "medium" if ext == ".swf" else "none"
    else:
        category = "unknown"
        role = "unclassified"
        value = "none"

    return {"category": category, "role": role, "decompile_value": value}


def should_extract_category(
    category: str,
    mode: str,
    include_categories: list[str] | None = None,
    exclude_categories: list[str] | None = None,
) -> bool:
    if mode == "manifest_only":
        return False
    include = set(include_categories or [])
    exclude = set(exclude_categories or [])
    if category in exclude:
        return False
    if include:
        return category in include
    if mode == "selective":
        return category in SELECTIVE_CATEGORIES
    return mode == "full"
