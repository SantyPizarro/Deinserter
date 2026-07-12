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
    disabled_plugins: list[str] | None = None
    max_container_depth: int = 4
    max_container_entries: int | None = 100_000
    max_embedded_candidates: int | None = 100_000
    max_processing_seconds: float | None = None

    def __post_init__(self) -> None:
        if self.max_file_size_mb is not None and self.max_file_size_mb < 0:
            raise ValueError("max_file_size_mb must be non-negative")
        if self.string_min_length <= 0:
            raise ValueError("string_min_length must be greater than zero")
        if self.entropy_block_size <= 0:
            raise ValueError("entropy_block_size must be greater than zero")
        if self.max_in_memory_bytes < 0:
            raise ValueError("max_in_memory_bytes must be non-negative")
        if self.stream_chunk_size <= 0:
            raise ValueError("stream_chunk_size must be greater than zero")
        if self.max_output_bytes is not None and self.max_output_bytes < 0:
            raise ValueError("max_output_bytes must be non-negative")
        if self.unity_max_object_bytes is not None and self.unity_max_object_bytes < 0:
            raise ValueError("unity_max_object_bytes must be non-negative")
        if self.max_container_depth < 0:
            raise ValueError("max_container_depth must be non-negative")
        if self.max_container_entries is not None and self.max_container_entries < 0:
            raise ValueError("max_container_entries must be non-negative")
        if self.max_embedded_candidates is not None and self.max_embedded_candidates < 0:
            raise ValueError("max_embedded_candidates must be non-negative")
        if self.max_processing_seconds is not None and self.max_processing_seconds <= 0:
            raise ValueError("max_processing_seconds must be greater than zero")
        if self.hash_policy not in {"extracted", "always", "never"}:
            raise ValueError(f"unsupported hash_policy: {self.hash_policy}")
        if self.mode not in {"manifest_only", "selective", "full"}:
            raise ValueError(f"unsupported decompilation mode: {self.mode}")
        if self.include_categories is not None:
            self.include_categories = [item.strip().lower() for item in self.include_categories if item.strip()]
        if self.exclude_categories is not None:
            self.exclude_categories = [item.strip().lower() for item in self.exclude_categories if item.strip()]
        if self.disabled_plugins is not None:
            self.disabled_plugins = [item.strip() for item in self.disabled_plugins if item.strip()]


@dataclass(slots=True)
class ExtractionOptions(ScanOptions):
    overwrite: bool = False
    preserve_paths: bool = True
    naming: NamingStrategy = "offset"
    validate_outputs: bool = True

    def __post_init__(self) -> None:
        ScanOptions.__post_init__(self)
        if self.naming not in {"hash", "offset", "type_index"}:
            raise ValueError(f"unsupported naming strategy: {self.naming}")


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
    failures: str = ""
    objects: str = ""
    reconstructed: str = ""
    assembly_types: str = ""
    semantic_conversions: str = ""
    unity_references: str = ""
    unity_external_resources: str = ""
    unreal_entries: str = ""
    container_entries: str = ""
    capability_events: str = ""


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
