"""Public API for Deinserter."""

from .models import (
    DecompilationPlan,
    DecompilationReport,
    EmbeddedCandidate,
    ExtractedAsset,
    ExtractionOptions,
    ExtractionReport,
    FileIdentification,
    FileReport,
    ProbeReport,
    ScanOptions,
    ScanReport,
)
from .classification import classify_asset
from .formats import FormatSpec, load_format_specs
from .gpak import extract_gpak, inspect_gpak, parse_gpak_index
from .manifests import ManifestReader, iter_manifest_records, load_manifest_summary, read_manifest
from .parsers import parse_file
from .pipeline import decompile_path, extract_path, identify_file, plan_path, probe_file, scan_path
from .registry import CapabilityRegistry, build_capability_registry, get_active_registry, get_default_registry

__all__ = [
    "DecompilationPlan",
    "DecompilationReport",
    "EmbeddedCandidate",
    "ExtractedAsset",
    "ExtractionOptions",
    "ExtractionReport",
    "CapabilityRegistry",
    "FileIdentification",
    "FileReport",
    "FormatSpec",
    "ManifestReader",
    "ProbeReport",
    "ScanOptions",
    "ScanReport",
    "classify_asset",
    "build_capability_registry",
    "decompile_path",
    "extract_gpak",
    "extract_path",
    "identify_file",
    "inspect_gpak",
    "iter_manifest_records",
    "load_manifest_summary",
    "load_format_specs",
    "plan_path",
    "parse_gpak_index",
    "parse_file",
    "probe_file",
    "read_manifest",
    "scan_path",
    "get_active_registry",
    "get_default_registry",
]
