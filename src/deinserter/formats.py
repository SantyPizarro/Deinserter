from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10
    import tomli as tomllib


@dataclass(frozen=True, slots=True)
class FormatSpec:
    type_name: str
    extensions: tuple[str, ...]
    category: str
    role: str
    decompile_value: str
    text: bool = False

    @property
    def primary_extension(self) -> str:
        return self.extensions[0]


BUILTIN_FORMATS_PATH = Path(__file__).with_name("builtin_formats.toml")


def normalize_extension(extension: str) -> str:
    value = extension.strip().lower()
    if not value:
        raise ValueError("extension cannot be empty")
    return value if value.startswith(".") else f".{value}"


def format_spec_from_mapping(item: dict[str, Any], source: str = "") -> FormatSpec:
    if not isinstance(item, dict):
        raise ValueError(f"{source}: each format must be a table")
    required = ("type_name", "extensions", "category", "role", "decompile_value")
    missing = [key for key in required if key not in item]
    if missing:
        prefix = f"{source}: " if source else ""
        raise ValueError(f"{prefix}format is missing required field(s): {', '.join(missing)}")

    type_name = str(item["type_name"]).strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", type_name):
        raise ValueError(f"{source}: type_name must be a stable lowercase identifier")

    raw_extensions = item["extensions"]
    if not isinstance(raw_extensions, list) or not raw_extensions or not all(isinstance(item, str) for item in raw_extensions):
        raise ValueError(f"{source}: extensions must be a non-empty list")

    extensions = tuple(dict.fromkeys(normalize_extension(extension) for extension in raw_extensions))
    category = str(item["category"]).strip().lower() or "unknown"
    role = str(item["role"]).strip().lower() or "unclassified"
    decompile_value = str(item["decompile_value"]).strip().lower() or "none"
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", category):
        raise ValueError(f"{source}: category must be a lowercase identifier")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", role):
        raise ValueError(f"{source}: role must be a lowercase identifier")
    if decompile_value not in {"none", "low", "medium", "high"}:
        raise ValueError(f"{source}: decompile_value must be one of none, low, medium, high")
    raw_text = item.get("text", False)
    if not isinstance(raw_text, bool):
        raise ValueError(f"{source}: text must be a boolean")
    return FormatSpec(
        type_name=type_name,
        extensions=extensions,
        category=category,
        role=role,
        decompile_value=decompile_value,
        text=raw_text,
    )


def load_format_specs_from_mapping(data: dict[str, Any], source: str = "") -> tuple[FormatSpec, ...]:
    raw_formats = data.get("formats", [])
    if not isinstance(raw_formats, list):
        raise ValueError(f"{source}: formats must be a list")
    specs = tuple(
        format_spec_from_mapping(item, f"{source}#formats[{index}]" if source else f"formats[{index}]")
        for index, item in enumerate(raw_formats)
    )
    seen_types: set[str] = set()
    seen_extensions: dict[str, str] = {}
    for spec in specs:
        if spec.type_name in seen_types:
            raise ValueError(f"{source}: duplicate format type_name: {spec.type_name}")
        seen_types.add(spec.type_name)
        for extension in spec.extensions:
            previous = seen_extensions.get(extension)
            if previous is not None and previous != spec.type_name:
                raise ValueError(f"{source}: extension {extension} is assigned to both {previous} and {spec.type_name}")
            seen_extensions[extension] = spec.type_name
    return specs


def load_format_specs(path: str | Path) -> tuple[FormatSpec, ...]:
    file_path = Path(path)
    with file_path.open("rb") as handle:
        data = tomllib.load(handle)
    return load_format_specs_from_mapping(data, str(file_path))


def index_formats_by_extension(specs: tuple[FormatSpec, ...]) -> dict[str, FormatSpec]:
    return {extension: spec for spec in specs for extension in spec.extensions}


def index_formats_by_type(specs: tuple[FormatSpec, ...]) -> dict[str, FormatSpec]:
    return {spec.type_name: spec for spec in specs}


def text_extensions(specs: tuple[FormatSpec, ...]) -> frozenset[str]:
    return frozenset(extension for spec in specs if spec.text for extension in spec.extensions)


SUPPORTED_FORMATS: tuple[FormatSpec, ...] = load_format_specs(BUILTIN_FORMATS_PATH)
FORMAT_BY_EXTENSION: dict[str, FormatSpec] = index_formats_by_extension(SUPPORTED_FORMATS)
FORMAT_BY_TYPE: dict[str, FormatSpec] = index_formats_by_type(SUPPORTED_FORMATS)
TEXT_EXTENSIONS: frozenset[str] = text_extensions(SUPPORTED_FORMATS)
