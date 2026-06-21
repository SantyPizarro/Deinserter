from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

NamingStrategy = Literal["hash", "offset", "type_index"]
HashPolicy = Literal["extracted", "always", "never"]
DecompilationMode = Literal["manifest_only", "selective", "full"]


def _json_value(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    return value


@dataclass(slots=True)
class JsonModel:
    def to_dict(self) -> dict[str, Any]:
        return _json_value(asdict(self))


@dataclass(slots=True)
class ScanOptions(JsonModel):
    recursive: bool = True
    sort_paths: bool = True
    max_file_size_mb: int | None = None
    string_min_length: int = 6
    entropy_block_size: int = 4096
    embedded_scan: bool = True
    max_in_memory_bytes: int = 64 * 1024 * 1024
    stream_chunk_size: int = 8 * 1024 * 1024
    hash_policy: HashPolicy = "extracted"
    max_output_bytes: int | None = None
    mode: DecompilationMode = "manifest_only"
    include_categories: list[str] | None = None
    exclude_categories: list[str] | None = None
    unity_object_scan: bool = True
    unity_reconstruct: bool = True
    unity_extract_raw_objects: bool = False
    unity_max_object_bytes: int | None = None
    unity_external_resource_roots: list[str] | None = None
    unity_decode_media: bool = False
    container_deep_scan: bool = True
    container_keyring_path: str | None = None
    format_pack_paths: list[str] | None = None


@dataclass(slots=True)
class ExtractionOptions(ScanOptions):
    overwrite: bool = False
    preserve_paths: bool = True
    naming: NamingStrategy = "offset"
    validate_outputs: bool = True


@dataclass(slots=True)
class FileIdentification(JsonModel):
    path: str
    identified_type: str
    confidence: float
    extension: str
    magic: str
    status: str = "identified"
    category: str = "unknown"
    decompile_value: str = "none"
    reason: str = ""


@dataclass(slots=True)
class EmbeddedCandidate(JsonModel):
    source_file: str
    offset: int
    length: int | None
    confidence: float
    detected_type: str
    extractable: bool
    reason: str = ""
    category: str = "unknown"
    decompile_value: str = "none"


@dataclass(slots=True)
class ProbeReport(JsonModel):
    path: str
    size: int
    sha256: str
    extension: str
    identified_type: str
    confidence: float
    magic: str
    entropy: float | None
    strings_preview: list[str] = field(default_factory=list)
    embedded_candidates: list[EmbeddedCandidate] = field(default_factory=list)
    compression_hints: list[str] = field(default_factory=list)
    status: str = "ok"
    warnings: list[str] = field(default_factory=list)
    category: str = "unknown"
    decompile_value: str = "none"
    reason: str = ""
    parse_info: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class FileReport(ProbeReport):
    pass


@dataclass(slots=True)
class ScanReport(JsonModel):
    version: str
    input_path: str
    started_at: str
    finished_at: str
    files: list[FileReport] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ExtractedAsset(JsonModel):
    output_path: str
    type: str
    source_path: str
    source_offset: int
    length: int
    sha256: str
    validation_status: str


@dataclass(slots=True)
class ExtractionReport(ScanReport):
    output_dir: str = ""
    extracted: list[ExtractedAsset] = field(default_factory=list)
    failed: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class ManifestPaths(JsonModel):
    summary: str = ""
    files: str = ""
    candidates: str = ""
    extracted: str = ""
    skipped: str = ""
    objects: str = ""
    reconstructed: str = ""
    assembly_types: str = ""
    semantic_conversions: str = ""
    unity_references: str = ""
    unity_external_resources: str = ""
    unreal_entries: str = ""
    container_entries: str = ""


@dataclass(slots=True)
class DecompilationPlan(JsonModel):
    version: str
    input_path: str
    started_at: str
    finished_at: str
    mode: DecompilationMode
    summary: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    manifest_paths: ManifestPaths = field(default_factory=ManifestPaths)
    files_sample: list[dict[str, Any]] = field(default_factory=list)
    candidates_sample: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class DecompilationReport(DecompilationPlan):
    output_dir: str = ""
    extracted_sample: list[dict[str, Any]] = field(default_factory=list)
    skipped_sample: list[dict[str, Any]] = field(default_factory=list)
    failed_sample: list[dict[str, Any]] = field(default_factory=list)
