from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
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
    required = ("type_name", "extensions", "category", "role", "decompile_value")
    missing = [key for key in required if key not in item]
    if missing:
        prefix = f"{source}: " if source else ""
        raise ValueError(f"{prefix}format is missing required field(s): {', '.join(missing)}")

    type_name = str(item["type_name"]).strip().lower()
    if not type_name:
        raise ValueError(f"{source}: type_name cannot be empty")

    raw_extensions = item["extensions"]
    if not isinstance(raw_extensions, list) or not raw_extensions:
        raise ValueError(f"{source}: extensions must be a non-empty list")

    extensions = tuple(dict.fromkeys(normalize_extension(str(extension)) for extension in raw_extensions))
    return FormatSpec(
        type_name=type_name,
        extensions=extensions,
        category=str(item["category"]).strip() or "unknown",
        role=str(item["role"]).strip() or "unclassified",
        decompile_value=str(item["decompile_value"]).strip() or "none",
        text=bool(item.get("text", False)),
    )


def load_format_specs_from_mapping(data: dict[str, Any], source: str = "") -> tuple[FormatSpec, ...]:
    raw_formats = data.get("formats", [])
    if not isinstance(raw_formats, list):
        raise ValueError(f"{source}: formats must be a list")
    return tuple(
        format_spec_from_mapping(item, f"{source}#formats[{index}]" if source else f"formats[{index}]")
        for index, item in enumerate(raw_formats)
    )


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
