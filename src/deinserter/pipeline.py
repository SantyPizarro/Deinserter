from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field
from time import monotonic
from typing import Iterable

from .assembly import iter_assembly_types
from .classification import classify_asset, should_extract_category
from .containers import source_for_container_entry
from .detectors import Detector
from .manifests import JsonlManifestWriter
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
from .registry import CapabilityContext, CapabilityRegistry, ProcessorCapability, RunContext, build_capability_registry, use_registry
from .resources import (
    ArtifactSource,
    ByteSource,
    copy_artifact_range,
    copy_file_streaming,
    copy_range_streaming,
    sha256_artifact_range,
    sha256_range,
    write_text_atomic,
)
from .stream_scanner import scan_embedded_streaming
from .unity.bundle import extract_bundle_entry, inspect_bundle
from .unity.reconstruct import reconstruct_unity_object, should_reconstruct_unity_object
from .unity.serialized import inspect_serialized_file
from .utils import (
    compression_hints,
    ensure_unique,
    magic_hex,
    safe_relative_path,
    sha256_file,
    shannon_entropy,
    strings_preview,
)
from ._version import VERSION


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _coerce_scan_options(options: ScanOptions | None) -> ScanOptions:
    return options if options is not None else ScanOptions()


def _coerce_extraction_options(options: ExtractionOptions | None) -> ExtractionOptions:
    return options if options is not None else ExtractionOptions()


def _registry_for_options(options: ScanOptions) -> CapabilityRegistry:
    registry = build_capability_registry(options.format_pack_paths, disabled_plugins=options.disabled_plugins or ())
    registry.configure(options)
    return registry


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _discover(
    input_path: Path,
    recursive: bool,
    exclude_roots: list[Path] | None = None,
    sort_paths: bool = True,
) -> Iterable[Path]:
    excludes = [root.resolve() for root in (exclude_roots or [])]
    if input_path.is_file():
        if not any(_is_within(input_path, root) for root in excludes):
            yield input_path
        return
    if not input_path.exists():
        raise FileNotFoundError(input_path)
    iterator = input_path.rglob("*") if recursive else input_path.glob("*")
    files = (path for path in iterator if path.is_file() and not any(_is_within(path, root) for root in excludes))
    yield from sorted(files) if sort_paths else files


def _read_for_probe(path: Path, options: ScanOptions) -> tuple[bytes | None, list[str], str]:
    warnings: list[str] = []
    size = path.stat().st_size
    if options.max_file_size_mb is not None:
        max_bytes = options.max_file_size_mb * 1024 * 1024
        if size > max_bytes:
            warnings.append(f"file_exceeds_max_file_size_mb:{options.max_file_size_mb}")
            return None, warnings, "skipped_size_limit"
    if size > options.max_in_memory_bytes:
        warnings.append(f"streaming_probe:size_exceeds_max_in_memory_bytes:{options.max_in_memory_bytes}")
        return None, warnings, "streaming_probe"
    return path.read_bytes(), warnings, "ok"


def _apply_classification(identified: FileIdentification, name: str, registry: CapabilityRegistry) -> FileIdentification:
    classification = classify_asset(name, identified.identified_type, registry)
    identified.category = classification["category"]
    identified.decompile_value = classification["decompile_value"]
    identified.reason = classification["role"]
    return identified


def _identify_from_bytes(path: Path, data: bytes, registry: CapabilityRegistry) -> FileIdentification:
    for record in registry.detector_capabilities:
        detector = record.value
        try:
            identified = detector.identify(data, path)
        except Exception as exc:  # third-party capability boundary
            registry.record_runtime_error(record, path, exc)
            continue
        if identified is not None:
            return _apply_classification(identified, str(path), registry)
    return _apply_classification(
        FileIdentification(str(path), "unknown", 0.0, path.suffix.lower(), magic_hex(data), "unknown"),
        str(path),
        registry,
    )


def _detector_for_type(type_name: str, registry: CapabilityRegistry) -> Detector | None:
    for detector in registry.detectors:
        if detector.type_name == type_name:
            return detector
    return None


def _extension_for_type(type_name: str, registry: CapabilityRegistry) -> str:
    detector = _detector_for_type(type_name, registry)
    if detector is not None:
        return getattr(detector, "extension", f".{type_name}")
    streaming = registry.find_streaming_detector(type_name)
    return streaming.extension if streaming is not None else f".{type_name}"


def _classify_candidate(candidate: EmbeddedCandidate, registry: CapabilityRegistry) -> EmbeddedCandidate:
    classification = classify_asset(f"asset.{candidate.detected_type}", candidate.detected_type, registry)
    candidate.category = classification["category"]
    candidate.decompile_value = classification["decompile_value"]
    if not candidate.reason:
        candidate.reason = classification["role"]
    return candidate


def identify_file(path: str | Path, options: ScanOptions | None = None) -> FileIdentification:
    scan_options = _coerce_scan_options(options)
    registry = _registry_for_options(scan_options)
    file_path = Path(path)
    with use_registry(registry):
        if (
            scan_options.max_file_size_mb is not None
            and file_path.stat().st_size > scan_options.max_file_size_mb * 1024 * 1024
        ):
            identified = _identify_from_bytes(file_path, b"", registry)
            identified.status = "skipped_size_limit"
            return identified
        handler = registry.find_container_handler(file_path, scan_options.container_deep_scan)
        if handler is not None:
            with file_path.open("rb") as handle:
                magic = handle.read(4).hex()
            return _apply_classification(
                FileIdentification(str(file_path), handler.type_name, 1.0, file_path.suffix.lower(), magic, "archive_index_valid"),
                str(file_path),
                registry,
            )
        if file_path.stat().st_size > scan_options.max_in_memory_bytes:
            source = ByteSource(file_path, scan_options.stream_chunk_size)
            data = source.read_at(0, min(4096, source.size))
        else:
            data = file_path.read_bytes()
        return _identify_from_bytes(file_path, data, registry)


def probe_file(path: str | Path, options: ScanOptions | None = None, registry: CapabilityRegistry | None = None) -> ProbeReport:
    scan_options = _coerce_scan_options(options)
    registry = registry or _registry_for_options(scan_options)
    file_path = Path(path)
    with use_registry(registry):
        size = file_path.stat().st_size
        digest = sha256_file(file_path) if scan_options.hash_policy == "always" else ""
        if scan_options.max_file_size_mb is not None and size > scan_options.max_file_size_mb * 1024 * 1024:
            identified = _identify_from_bytes(file_path, b"", registry)
            warning = f"file_exceeds_max_file_size_mb:{scan_options.max_file_size_mb}"
            return ProbeReport(
                path=str(file_path),
                size=size,
                sha256=digest,
                extension=file_path.suffix.lower(),
                identified_type=identified.identified_type,
                confidence=identified.confidence,
                magic="",
                entropy=None,
                status="skipped_size_limit",
                warnings=[warning],
                category=identified.category,
                decompile_value=identified.decompile_value,
                reason=identified.reason,
                parse_info=registry.describe_file(file_path, identified.identified_type, identified.category),
            )
        handler = registry.find_container_handler(file_path, scan_options.container_deep_scan)
        if handler is not None:
            info = handler.inspect(file_path)
            with file_path.open("rb") as handle:
                magic = handle.read(4).hex()
            classification = classify_asset(str(file_path), handler.type_name, registry)
            return ProbeReport(
                path=str(file_path),
                size=size,
                sha256=digest,
                extension=file_path.suffix.lower(),
                identified_type=handler.type_name,
                confidence=1.0,
                magic=magic,
                entropy=None,
                strings_preview=[
                    f"entries={info.entry_count}",
                    f"payload_bytes={info.payload_bytes}",
                ],
                embedded_candidates=[],
                compression_hints=[],
                status="archive_index_valid",
                warnings=[],
                category=classification["category"],
                decompile_value=classification["decompile_value"],
                reason=classification["role"],
                parse_info={"parser": "container_handler", "status": "parsed_index", "container": info.to_dict()},
            )
        data, warnings, status = _read_for_probe(file_path, scan_options)
        if data is None:
            source = ByteSource(file_path, scan_options.stream_chunk_size)
            header = (
                source.read_at(0, min(max(4096, scan_options.entropy_block_size), source.size))
                if status == "streaming_probe"
                else b""
            )
            identified = _identify_from_bytes(file_path, header, registry) if header else _apply_classification(
                FileIdentification(str(file_path), "unknown", 0.0, file_path.suffix.lower(), "", "unknown"),
                str(file_path),
                registry,
            )
            entropy = shannon_entropy(header) if header else None
            candidates: list[EmbeddedCandidate] = []
            if status == "streaming_probe" and scan_options.embedded_scan:
                candidates = scan_embedded_streaming(
                    ArtifactSource.from_path(file_path, chunk_size=scan_options.stream_chunk_size),
                    scan_options,
                    registry.streaming_detectors,
                    lambda detector, exc: registry.record_runtime_error(detector, file_path, exc),
                )
            return ProbeReport(
                path=str(file_path),
                size=size,
                sha256=digest,
                extension=file_path.suffix.lower(),
                identified_type=identified.identified_type,
                confidence=identified.confidence,
                magic=identified.magic,
                entropy=entropy,
                embedded_candidates=candidates,
                compression_hints=compression_hints(header, entropy) if header else [],
                status=status,
                warnings=warnings,
                category=identified.category,
                decompile_value=identified.decompile_value,
                reason=identified.reason,
                parse_info=registry.parse_source(
                    ArtifactSource.from_path(file_path, chunk_size=scan_options.stream_chunk_size),
                    file_path,
                    identified.identified_type,
                    identified.category,
                    materialize_limit=scan_options.max_in_memory_bytes,
                ),
            )

        identified = _identify_from_bytes(file_path, data, registry)
        entropy = shannon_entropy(data[: scan_options.entropy_block_size])
        candidates: list[EmbeddedCandidate] = []
        if scan_options.embedded_scan:
            for record in registry.detector_capabilities:
                detector = record.value
                try:
                    found = detector.find_embedded(data, str(file_path))
                except Exception as exc:  # third-party capability boundary
                    registry.record_runtime_error(record, file_path, exc)
                    continue
                candidates.extend(_classify_candidate(candidate, registry) for candidate in found)
                if scan_options.max_embedded_candidates is not None and len(candidates) >= scan_options.max_embedded_candidates:
                    candidates = candidates[: scan_options.max_embedded_candidates]
                    warnings.append(f"embedded_candidate_limit_reached:{scan_options.max_embedded_candidates}")
                    break
        return ProbeReport(
            path=str(file_path),
            size=size,
            sha256=digest,
            extension=file_path.suffix.lower(),
            identified_type=identified.identified_type,
            confidence=identified.confidence,
            magic=identified.magic,
            entropy=entropy,
            strings_preview=strings_preview(data, scan_options.string_min_length),
            embedded_candidates=candidates,
            compression_hints=compression_hints(data, entropy),
            status=identified.status if identified.status != "unknown" else "unknown",
            warnings=warnings,
            category=identified.category,
            decompile_value=identified.decompile_value,
            reason=identified.reason,
            parse_info=registry.parse_source(
                ArtifactSource.from_path(file_path, chunk_size=scan_options.stream_chunk_size),
                file_path,
                identified.identified_type,
                identified.category,
                materialize_limit=scan_options.max_in_memory_bytes,
            ),
        )


def probe_artifact_source(
    source: ArtifactSource,
    logical_path: Path,
    options: ScanOptions,
    registry: CapabilityRegistry,
) -> ProbeReport:
    warnings: list[str] = []
    if source.size <= options.max_in_memory_bytes:
        data = source.read_all(options.max_in_memory_bytes)
        identified = _identify_from_bytes(logical_path, data, registry)
        entropy = shannon_entropy(data[: options.entropy_block_size])
        candidates: list[EmbeddedCandidate] = []
        if options.embedded_scan:
            for record in registry.detector_capabilities:
                detector = record.value
                try:
                    found = detector.find_embedded(data, str(logical_path))
                except Exception as exc:
                    registry.record_runtime_error(record, logical_path, exc)
                    continue
                candidates.extend(_classify_candidate(candidate, registry) for candidate in found)
                if options.max_embedded_candidates is not None and len(candidates) >= options.max_embedded_candidates:
                    candidates = candidates[: options.max_embedded_candidates]
                    warnings.append(f"embedded_candidate_limit_reached:{options.max_embedded_candidates}")
                    break
        candidates = [
            candidate
            for candidate in candidates
            if not (
                candidate.offset == 0
                and candidate.length == source.size
                and candidate.detected_type == identified.identified_type
            )
        ]
        status = identified.status if identified.status != "unknown" else "unknown"
        preview = strings_preview(data, options.string_min_length)
        hints = compression_hints(data, entropy)
    else:
        header = source.read_at(0, min(max(4096, options.entropy_block_size), source.size))
        identified = _identify_from_bytes(logical_path, header, registry)
        entropy = shannon_entropy(header)
        candidates = (
            scan_embedded_streaming(
                source,
                options,
                registry.streaming_detectors,
                lambda detector, exc: registry.record_runtime_error(detector, logical_path, exc),
            )
            if options.embedded_scan
            else []
        )
        status = "streaming_probe"
        preview = strings_preview(header, options.string_min_length)
        hints = compression_hints(header, entropy)
        warnings.append(f"streaming_probe:size_exceeds_max_in_memory_bytes:{options.max_in_memory_bytes}")
    return ProbeReport(
        path=str(logical_path),
        size=source.size,
        sha256="",
        extension=logical_path.suffix.lower(),
        identified_type=identified.identified_type,
        confidence=identified.confidence,
        magic=identified.magic,
        entropy=entropy,
        strings_preview=preview,
        embedded_candidates=candidates,
        compression_hints=hints,
        status=status,
        warnings=warnings,
        category=identified.category,
        decompile_value=identified.decompile_value,
        reason=identified.reason,
        parse_info=registry.parse_source(
            source,
            logical_path,
            identified.identified_type,
            identified.category,
            materialize_limit=options.max_in_memory_bytes,
        ),
    )


def _summary(files: list[FileReport]) -> dict[str, object]:
    by_type: dict[str, int] = {}
    by_category: dict[str, int] = {}
    by_decompile_value: dict[str, int] = {}
    candidates = 0
    extractable = 0
    for item in files:
        by_type[item.identified_type] = by_type.get(item.identified_type, 0) + 1
        by_category[item.category] = by_category.get(item.category, 0) + 1
        by_decompile_value[item.decompile_value] = by_decompile_value.get(item.decompile_value, 0) + 1
        candidates += len(item.embedded_candidates)
        extractable += sum(1 for candidate in item.embedded_candidates if candidate.extractable)
    return {
        "files_total": len(files),
        "by_type": by_type,
        "by_category": by_category,
        "by_decompile_value": by_decompile_value,
        "embedded_candidates_total": candidates,
        "embedded_extractable_total": extractable,
    }


def _file_report_from_probe(probe: ProbeReport) -> FileReport:
    return FileReport(
        path=probe.path,
        size=probe.size,
        sha256=probe.sha256,
        extension=probe.extension,
        identified_type=probe.identified_type,
        confidence=probe.confidence,
        magic=probe.magic,
        entropy=probe.entropy,
        strings_preview=probe.strings_preview,
        embedded_candidates=probe.embedded_candidates,
        compression_hints=probe.compression_hints,
        status=probe.status,
        warnings=probe.warnings,
        category=probe.category,
        decompile_value=probe.decompile_value,
        reason=probe.reason,
        parse_info=probe.parse_info,
    )


def scan_path(input_path: str | Path, options: ScanOptions | None = None) -> ScanReport:
    scan_options = _coerce_scan_options(options)
    registry = _registry_for_options(scan_options)
    root = Path(input_path)
    started_at = _now()
    warnings: list[str] = []
    files: list[FileReport] = []
    with use_registry(registry):
        warnings.extend(f"capability_registry: {warning}" for warning in registry.load_errors)
        for file_path in _discover(root, scan_options.recursive, sort_paths=scan_options.sort_paths):
            try:
                probe = probe_file(file_path, scan_options, registry)
                files.append(_file_report_from_probe(probe))
                warnings.extend(f"{file_path}: {warning}" for warning in probe.warnings)
            except Exception as exc:
                warnings.append(f"{file_path}: {exc}")
            warnings.extend(f"capability_runtime: {warning}" for warning in registry.drain_runtime_errors())
    finished_at = _now()
    return ScanReport(
        version=VERSION,
        input_path=str(root),
        started_at=started_at,
        finished_at=finished_at,
        files=files,
        summary=_summary(files),
        warnings=warnings,
    )


def _empty_summary() -> dict[str, object]:
    return {
        "files_total": 0,
        "by_type": {},
        "by_category": {},
        "by_decompile_value": {},
        "embedded_candidates_total": 0,
        "embedded_extractable_total": 0,
        "containers_total": 0,
        "container_entries_total": 0,
        "planned_output_bytes": 0,
        "extracted_total": 0,
        "extracted_bytes": 0,
        "output_bytes": 0,
        "failed_total": 0,
        "skipped_total": 0,
        "unity_objects_total": 0,
        "unity_reconstructed_total": 0,
        "unity_metadata_only_total": 0,
        "unity_unsupported_total": 0,
        "unity_resource_blobs_total": 0,
        "unity_bundle_entries_total": 0,
        "unity_references_total": 0,
        "unity_references_resolved_total": 0,
        "unity_references_unresolved_total": 0,
        "unity_indexed_files_total": 0,
        "unity_indexed_objects_total": 0,
        "unity_external_files_total": 0,
        "unity_external_resources_total": 0,
        "assembly_types_total": 0,
        "deep_container_entries_total": 0,
        "unreal_entries_total": 0,
        "semantic_conversions_total": 0,
        "semantic_converted_total": 0,
        "semantic_noop_total": 0,
        "semantic_pseudocode_total": 0,
        "semantic_failed_total": 0,
        "semantic_blocked_total": 0,
        "capability_events_total": 0,
        "deadline_reached": False,
        "by_unity_class": {},
        "by_semantic_classification": {},
    }


@dataclass(slots=True)
class RunState:
    writer: JsonlManifestWriter
    services: dict[str, object] = field(default_factory=dict)
    deadline: float | None = None
    summary: dict[str, object] = field(default_factory=_empty_summary)
    warnings: list[str] = field(default_factory=list)
    files_sample: list[dict[str, object]] = field(default_factory=list)
    candidates_sample: list[dict[str, object]] = field(default_factory=list)
    extracted_sample: list[dict[str, object]] = field(default_factory=list)
    skipped_sample: list[dict[str, object]] = field(default_factory=list)
    failed_sample: list[dict[str, object]] = field(default_factory=list)


def _bump(mapping: dict[str, int], key: str, amount: int = 1) -> None:
    mapping[key] = mapping.get(key, 0) + amount


def _sample_append(sample: list[dict[str, object]], item: dict[str, object], limit: int = 50) -> None:
    if len(sample) < limit:
        sample.append(item)


def _deadline_exceeded(state: RunState) -> bool:
    if state.deadline is None or monotonic() < state.deadline:
        return False
    warning = "processing_deadline_reached"
    state.summary["deadline_reached"] = True
    if warning not in state.warnings:
        state.warnings.append(warning)
    return True


def _safe_stem(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value)
    return cleaned.strip("._") or "item"


def _probe_file_item(probe: ProbeReport) -> dict[str, object]:
    return {
        "path": probe.path,
        "size": probe.size,
        "sha256": probe.sha256,
        "extension": probe.extension,
        "identified_type": probe.identified_type,
        "confidence": probe.confidence,
        "magic": probe.magic,
        "entropy": probe.entropy,
        "compression_hints": probe.compression_hints,
        "status": probe.status,
        "warnings": probe.warnings,
        "category": probe.category,
        "decompile_value": probe.decompile_value,
        "reason": probe.reason,
        "parse_info": probe.parse_info,
        "embedded_candidates_count": len(probe.embedded_candidates),
        "embedded_extractable_count": sum(1 for candidate in probe.embedded_candidates if candidate.extractable),
    }


def _candidate_item(candidate: EmbeddedCandidate) -> dict[str, object]:
    return candidate.to_dict()


def _output_base_for_container(root: Path, file_path: Path, output_dir: Path) -> Path:
    if root.is_file():
        return output_dir
    relative_parent = safe_relative_path(file_path, root).parent
    return output_dir / relative_parent / file_path.stem


def _output_path_for_direct_file(root: Path, file_path: Path, output_dir: Path, overwrite: bool) -> Path:
    relative = safe_relative_path(file_path, root if root.is_dir() else file_path.parent)
    destination = output_dir / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not overwrite:
        destination = ensure_unique(destination)
    return destination


def _can_write_bytes(summary: dict[str, object], options: ScanOptions, size: int) -> bool:
    if options.max_output_bytes is None:
        return True
    return int(summary["output_bytes"]) + size <= options.max_output_bytes


def _record_skipped(
    writer: JsonlManifestWriter,
    summary: dict[str, object],
    sample: list[dict[str, object]],
    item: dict[str, object],
) -> None:
    summary["skipped_total"] = int(summary["skipped_total"]) + 1
    writer.skipped(item)
    _sample_append(sample, item)


def _record_extracted(
    writer: JsonlManifestWriter,
    summary: dict[str, object],
    sample: list[dict[str, object]],
    item: dict[str, object],
) -> None:
    summary["extracted_total"] = int(summary["extracted_total"]) + 1
    summary["extracted_bytes"] = int(summary["extracted_bytes"]) + int(item.get("length", 0))
    summary["output_bytes"] = int(summary["output_bytes"]) + int(item.get("length", 0))
    writer.extracted(item)
    _sample_append(sample, item)


def _record_failure(state: RunState, file_path: Path, reason: str, entry: str | None = None) -> None:
    failure: dict[str, object] = {"source_path": str(file_path), "reason": reason}
    if entry is not None:
        failure["entry"] = entry
    state.summary["failed_total"] = int(state.summary["failed_total"]) + 1
    state.writer.failure(failure)
    _sample_append(state.failed_sample, failure)


def _record_semantic_conversion(state: RunState, item: dict[str, object] | None) -> None:
    if item is None:
        return
    state.writer.semantic_conversion(item)
    state.summary["semantic_conversions_total"] = int(state.summary["semantic_conversions_total"]) + 1
    classification = str(item.get("semantic_classification") or "unknown")
    _bump(state.summary["by_semantic_classification"], classification)
    status = str(item.get("status") or "")
    if status == "converted":
        state.summary["semantic_converted_total"] = int(state.summary["semantic_converted_total"]) + 1
        state.summary["output_bytes"] = int(state.summary["output_bytes"]) + int(item.get("output_length", 0))
    elif status == "no_conversion_required":
        state.summary["semantic_noop_total"] = int(state.summary["semantic_noop_total"]) + 1
    elif status == "pseudocode":
        state.summary["semantic_pseudocode_total"] = int(state.summary["semantic_pseudocode_total"]) + 1
        state.summary["output_bytes"] = int(state.summary["output_bytes"]) + int(item.get("output_length", 0))
    elif status == "semantic_conversion_failed":
        state.summary["semantic_failed_total"] = int(state.summary["semantic_failed_total"]) + 1
    elif status in {"blocked_output_budget", "blocked_materialization_limit"}:
        state.summary["semantic_blocked_total"] = int(state.summary["semantic_blocked_total"]) + 1
        _record_skipped(state.writer, state.summary, state.skipped_sample, item | {"reason": status})


def _record_capability_event(state: RunState, item: dict[str, object]) -> None:
    state.writer.capability_event(item)
    state.summary["capability_events_total"] = int(state.summary["capability_events_total"]) + 1


def _processor_emitter(state: RunState, stream: str, item: dict[str, object]) -> None:
    if stream == "semantic_conversion":
        _record_semantic_conversion(state, item)
        return
    if stream == "output":
        state.summary["output_bytes"] = int(state.summary["output_bytes"]) + int(item.get("output_length", 0))
    _record_capability_event(state, {"stream": stream, **item})


def _run_registered_processors(
    kind: str,
    capabilities: list[ProcessorCapability],
    context: CapabilityContext,
    state: RunState,
) -> None:
    for capability in capabilities:
        if _deadline_exceeded(state):
            break
        try:
            result = capability.processor(context)
        except Exception as exc:
            context.registry.record_runtime_error(capability, context.logical_path, exc)
            _record_failure(state, context.logical_path, f"{capability.capability_id}: {exc}")
            continue
        if result is None:
            continue
        records = result if isinstance(result, list) else [result]
        for record in records:
            if not isinstance(record, dict):
                error = TypeError(f"processor result must be a dict or list of dicts, got {type(record).__name__}")
                context.registry.record_runtime_error(capability, context.logical_path, error)
                _record_failure(state, context.logical_path, f"{capability.capability_id}: {error}")
                continue
            _record_capability_event(
                state,
                {
                    "kind": kind,
                    "capability_id": capability.capability_id,
                    "capability_source": capability.source,
                    "logical_path": str(context.logical_path),
                    **record,
                }
            )


def _capability_context(
    *,
    root: Path,
    file_path: Path,
    output_dir: Path | None,
    identified_type: str,
    category: str,
    decompile_value: str,
    parse_info: dict[str, object],
    state: RunState,
    options: ExtractionOptions,
    registry: CapabilityRegistry,
    probe: ProbeReport | None = None,
    depth: int = 0,
    source: ArtifactSource | None = None,
) -> CapabilityContext:
    return CapabilityContext(
        root=root,
        logical_path=file_path,
        source=source or ArtifactSource.from_path(file_path, chunk_size=options.stream_chunk_size),
        identified_type=identified_type,
        category=category,
        decompile_value=decompile_value,
        parse_info=dict(parse_info),
        output_dir=output_dir,
        options=options,
        registry=registry,
        depth=depth,
        services={
            **state.services,
            "state": state,
            "probe": probe,
            "emit": lambda stream, item: _processor_emitter(state, stream, item),
            "can_write": lambda size: _can_write_bytes(state.summary, options, size),
            "deadline_exceeded": lambda: _deadline_exceeded(state),
        },
    )


def _container_output_validation_status(
    out_path: Path,
    type_name: str,
    options: ExtractionOptions,
    registry: CapabilityRegistry,
) -> str:
    if not options.validate_outputs:
        return "not_validated"
    detector = _detector_for_type(type_name, registry)
    if detector is None or type_name == "unknown":
        return "archive_index_valid"
    if out_path.stat().st_size > options.max_in_memory_bytes:
        return "archive_index_valid"
    return "valid" if detector.validate(out_path.read_bytes()) else "invalid"


def maybe_extract_container_entry(
    file_path: Path,
    entry: object,
    handler: object,
    container_output: Path | None,
    state: RunState,
    options: ExtractionOptions,
    registry: CapabilityRegistry,
    source_display_path: Path | None = None,
) -> None:
    candidate = entry.to_dict()
    candidate["extractable"] = True
    state.writer.candidate(candidate)
    _sample_append(state.candidates_sample, candidate)
    if not should_extract_category(entry.category, options.mode, options.include_categories, options.exclude_categories):
        return
    state.summary["planned_output_bytes"] = int(state.summary["planned_output_bytes"]) + entry.size
    if container_output is None:
        return
    if not _can_write_bytes(state.summary, options, entry.size):
        _record_skipped(state.writer, state.summary, state.skipped_sample, candidate | {"reason": "blocked_output_budget"})
        return
    try:
        out_path, digest = handler.extract_entry(
            file_path,
            entry,
            container_output,
            options.overwrite,
            options.stream_chunk_size,
            options.hash_policy != "never",
        )
        validation_status = _container_output_validation_status(out_path, entry.type, options, registry)
        if validation_status == "invalid":
            try:
                out_path.unlink()
            except OSError:
                pass
            _record_skipped(
                state.writer,
                state.summary,
                state.skipped_sample,
                candidate
                | {
                    "reason": "failed_output_validation",
                    "output_path": str(out_path),
                    "validation_status": validation_status,
                },
            )
            return
        _record_extracted(
            state.writer,
            state.summary,
            state.extracted_sample,
            {
                "output_path": str(out_path),
                "type": entry.type,
                "source_path": str(source_display_path or file_path),
                "source_offset": entry.offset,
                "length": entry.size,
                "sha256": digest,
                "validation_status": validation_status,
                "category": entry.category,
                "decompile_value": entry.decompile_value,
            },
        )
    except Exception as exc:
        _record_failure(state, source_display_path or file_path, str(exc), entry.name)


def maybe_extract_direct_file(
    input_path: Path,
    file_path: Path,
    output_dir: Path | None,
    probe: ProbeReport,
    file_item: dict[str, object],
    state: RunState,
    options: ExtractionOptions,
    registry: CapabilityRegistry,
    direct_extract_known_only: bool = False,
) -> None:
    if _should_skip_direct_unity_file(file_path, probe, options):
        return
    if direct_extract_known_only:
        detector = _detector_for_type(probe.identified_type, registry)
        if detector is None:
            return
        if options.validate_outputs:
            if probe.size > options.max_in_memory_bytes or not detector.validate(file_path.read_bytes()):
                return
    if not should_extract_category(probe.category, options.mode, options.include_categories, options.exclude_categories):
        return
    state.summary["planned_output_bytes"] = int(state.summary["planned_output_bytes"]) + probe.size
    if output_dir is None:
        return
    if not _can_write_bytes(state.summary, options, probe.size):
        _record_skipped(state.writer, state.summary, state.skipped_sample, file_item | {"reason": "blocked_output_budget"})
        return
    destination = _output_path_for_direct_file(input_path, file_path, output_dir, options.overwrite)
    digest = copy_file_streaming(file_path, destination, options.stream_chunk_size, options.hash_policy != "never")
    _record_extracted(
        state.writer,
        state.summary,
        state.extracted_sample,
        {
            "output_path": str(destination),
            "type": probe.identified_type,
            "source_path": str(file_path),
            "source_offset": 0,
            "length": probe.size,
            "sha256": digest,
            "validation_status": probe.status,
            "category": probe.category,
            "decompile_value": probe.decompile_value,
        },
    )


def _should_skip_direct_unity_file(file_path: Path, probe: ProbeReport, options: ExtractionOptions) -> bool:
    if not options.unity_object_scan:
        return False
    if options.mode == "full":
        return False
    parser = str((probe.parse_info or {}).get("parser", ""))
    status = str((probe.parse_info or {}).get("status", ""))
    if parser in {"unity_serialized_file", "unity_bundle"}:
        return status.startswith("parsed")
    if parser in {"unity_resource_blob", "fsb5"}:
        name = file_path.name.lower()
        return file_path.suffix.lower() == ".ress" or any(token in name for token in ("sharedassets", "resources.assets"))
    return False


def _record_unity_object(state: RunState, item: dict[str, object]) -> None:
    state.writer.object(item)
    state.summary["unity_objects_total"] = int(state.summary["unity_objects_total"]) + 1
    type_name = str(item.get("type_name") or item.get("type") or "unknown")
    _bump(state.summary["by_unity_class"], type_name)


def _record_reconstructed_unity(state: RunState, item: dict[str, object]) -> None:
    state.writer.reconstructed(item)
    state.summary["unity_reconstructed_total"] = int(state.summary["unity_reconstructed_total"]) + 1
    if item.get("reconstruction_status") == "metadata_only":
        state.summary["unity_metadata_only_total"] = int(state.summary["unity_metadata_only_total"]) + 1
    if item.get("reconstruction_status") == "unsupported":
        state.summary["unity_unsupported_total"] = int(state.summary["unity_unsupported_total"]) + 1


@dataclass(slots=True)
class _UnityResourceResolution:
    path: Path | None
    status: str
    resolution_status: str


def _unity_resource_kind(class_id: int) -> str:
    if class_id == 28:
        return "texture"
    if class_id == 83:
        return "audio"
    return "external_blob"


def _unique_paths(paths: list[Path]) -> list[Path]:
    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in paths:
        key = str(candidate.resolve()) if candidate.exists() else str(candidate)
        if key not in seen:
            unique.append(candidate)
            seen.add(key)
    return unique


def _unity_resource_candidate_groups(
    file_path: Path,
    resource_path: str,
    options: ExtractionOptions,
    indexed_resources: list[Path],
) -> list[list[Path]]:
    groups: list[list[Path]] = []
    raw = Path(resource_path.replace("\\", "/")) if resource_path else None
    if raw is not None and raw.is_absolute():
        groups.append([raw])
    elif raw is not None:
        groups.append([file_path.parent / raw])
        groups.append([Path(root) / raw for root in options.unity_external_resource_roots or []])
    sibling_candidates: list[Path] = []
    for suffix in (".resS", ".resource", ".ress"):
        sibling_candidates.append(file_path.with_suffix(suffix))
        sibling_candidates.append(file_path.parent / f"{file_path.name}{suffix}")
    groups.append(sibling_candidates)
    if resource_path:
        resource_name = Path(resource_path).name.lower()
        resource_tail = Path(resource_path.replace("\\", "/")).as_posix().lower()
        groups.append(
            [
                candidate
                for candidate in indexed_resources
                if candidate.name.lower() == resource_name or candidate.as_posix().lower().endswith(resource_tail)
            ]
        )
    return [_unique_paths(group) for group in groups if group]


def _resolve_unity_resource(
    file_path: Path,
    streaming_info: dict[str, object],
    options: ExtractionOptions,
    indexed_resources: list[Path],
) -> _UnityResourceResolution:
    size = int(streaming_info.get("size") or 0)
    offset = int(streaming_info.get("offset") or 0)
    resource_path = str(streaming_info.get("path") or "")
    if size == 0:
        return _UnityResourceResolution(None, "zero_size", "zero_size")
    if offset < 0 or size < 0:
        return _UnityResourceResolution(None, "invalid_range", "invalid_range")
    saw_existing = False
    for group in _unity_resource_candidate_groups(file_path, resource_path, options, indexed_resources):
        valid: list[Path] = []
        for candidate in group:
            try:
                if not candidate.exists():
                    continue
                saw_existing = True
                if offset + size <= candidate.stat().st_size:
                    valid.append(candidate)
            except OSError:
                continue
        if len(valid) == 1:
            return _UnityResourceResolution(valid[0], "resolved", "resolved")
        if len(valid) > 1:
            return _UnityResourceResolution(None, "ambiguous_resource", "ambiguous_resource")
        if saw_existing:
            return _UnityResourceResolution(None, "invalid_range", "invalid_range")
    return _UnityResourceResolution(None, "empty_path" if not resource_path else "missing_resource", "empty_path" if not resource_path else "missing_resource")


def _record_unity_reference(state: RunState, item: dict[str, object]) -> None:
    state.writer.unity_reference(item)
    state.summary["unity_references_total"] = int(state.summary["unity_references_total"]) + 1
    if item.get("resolved"):
        state.summary["unity_references_resolved_total"] = int(state.summary["unity_references_resolved_total"]) + 1
    else:
        state.summary["unity_references_unresolved_total"] = int(state.summary["unity_references_unresolved_total"]) + 1


def _record_unity_external_resource(state: RunState, item: dict[str, object]) -> None:
    state.writer.unity_external_resource(item)
    state.summary["unity_external_resources_total"] = int(state.summary["unity_external_resources_total"]) + 1


def _process_unity_serialized_file(
    file_path: Path,
    output_dir: Path | None,
    state: RunState,
    options: ExtractionOptions,
) -> None:
    unity_index = state.services.get("unity_index")
    if unity_index is None:
        from .unity.index import UnityProjectIndex

        unity_index = UnityProjectIndex()
        state.services["unity_index"] = unity_index
    info = unity_index.ensure_file(file_path)
    objects = info.objects
    state.summary["unity_external_files_total"] = int(state.summary["unity_external_files_total"]) + len(info.externals)
    for obj in objects:
        unity_index.resolve_object_references(obj)
        for streaming_info in obj.streaming_infos:
            length = int(streaming_info.get("size") or 0)
            offset = int(streaming_info.get("offset") or 0)
            resource_kind = _unity_resource_kind(obj.class_id)
            resolution = _resolve_unity_resource(
                file_path,
                streaming_info,
                options,
                list(state.services.get("unity_resource_files", [])),
            )
            resource = resolution.path
            streaming_info.update(
                {
                    "owner_class_id": obj.class_id,
                    "owner_type_name": obj.type_name,
                    "owner_path_id": obj.path_id,
                    "resource_kind": resource_kind,
                    "resolved_path": str(resource) if resource is not None else "",
                    "resolution_status": resolution.resolution_status,
                    "status": resolution.status,
                }
            )
            resource_item: dict[str, object] = {
                "source_file": str(file_path),
                "path_id": obj.path_id,
                "class_id": obj.class_id,
                "type_name": obj.type_name,
                "resource_path": str(streaming_info.get("path") or ""),
                "resolved_path": str(resource) if resource is not None else "",
                "source_offset": offset,
                "length": length,
                "resource_kind": resource_kind,
                "resolution_status": resolution.resolution_status,
                "status": resolution.status,
            }
            if (
                resource is not None
                and output_dir is not None
                and options.mode != "manifest_only"
                and _can_write_bytes(state.summary, options, length)
            ):
                state.summary["planned_output_bytes"] = int(state.summary["planned_output_bytes"]) + length
                relative = Path("unity_external_resources") / _safe_stem(file_path.stem) / _safe_stem(str(obj.path_id))
                suffix = Path(str(streaming_info.get("path") or "")).suffix or ".resource"
                destination = output_dir / relative.with_suffix(suffix)
                if destination.exists() and not options.overwrite:
                    destination = ensure_unique(destination)
                digest = copy_range_streaming(resource, destination, offset, length, options.stream_chunk_size, options.hash_policy != "never")
                resource_item.update({"status": "extracted", "resolution_status": "extracted", "output_path": str(destination), "sha256": digest})
                streaming_info.update({"status": "extracted", "resolution_status": "extracted", "output_path": str(destination), "sha256": digest})
                _record_extracted(
                    state.writer,
                    state.summary,
                    state.extracted_sample,
                    {
                        "output_path": str(destination),
                        "type": obj.type_name,
                        "source_path": str(resource),
                        "source_offset": offset,
                        "length": length,
                        "sha256": digest,
                        "validation_status": "unity_streaming_info_range",
                        "category": "unity_objects",
                        "decompile_value": "medium",
                    },
                )
            elif resource is not None and output_dir is not None and options.mode != "manifest_only":
                resource_item.update({"status": "blocked_budget", "resolution_status": "blocked_budget"})
                streaming_info.update({"status": "blocked_budget", "resolution_status": "blocked_budget"})
                _record_skipped(state.writer, state.summary, state.skipped_sample, resource_item | {"reason": "blocked_output_budget"})
            _record_unity_external_resource(state, resource_item)
        obj.external_resource = obj.streaming_infos[0] if obj.streaming_infos else None
        obj_item = obj.to_dict()
        _record_unity_object(state, obj_item)
        for reference in obj.pptr_references:
            _record_unity_reference(state, reference.to_dict())
        if not options.unity_reconstruct or not should_reconstruct_unity_object(
            obj,
            options.mode,
            options.include_categories,
        ):
            continue
        if options.unity_max_object_bytes is not None and obj.size > options.unity_max_object_bytes:
            skipped = obj_item | {"reason": "blocked_unity_object_budget"}
            _record_skipped(state.writer, state.summary, state.skipped_sample, skipped)
            continue
        state.summary["planned_output_bytes"] = int(state.summary["planned_output_bytes"]) + obj.size
        if output_dir is None:
            continue
        record = reconstruct_unity_object(
            obj,
            output_dir,
            overwrite=options.overwrite,
            hash_output=options.hash_policy != "never",
            chunk_size=options.stream_chunk_size,
            max_object_bytes=options.unity_max_object_bytes,
            max_output_bytes=(
                None
                if options.max_output_bytes is None
                else max(0, options.max_output_bytes - int(state.summary["output_bytes"]))
            ),
            extract_raw_objects=options.unity_extract_raw_objects or options.mode == "full",
            decode_media=options.unity_decode_media,
        )
        actual_planned = int(record.get("planned_output_bytes", record.get("output_bytes", record.get("length", obj.size))))
        state.summary["planned_output_bytes"] = int(state.summary["planned_output_bytes"]) + actual_planned - obj.size
        if record.get("reconstruction_status") == "blocked_budget":
            _record_skipped(state.writer, state.summary, state.skipped_sample, record)
            continue
        _record_reconstructed_unity(state, record)
        if int(record.get("length", 0)) > 0:
            _record_extracted(state.writer, state.summary, state.extracted_sample, record)


def _process_unity_bundle_file(
    file_path: Path,
    output_dir: Path | None,
    state: RunState,
    options: ExtractionOptions,
    registry: CapabilityRegistry,
) -> None:
    info = inspect_bundle(file_path)
    state.summary["unity_bundle_entries_total"] = int(state.summary["unity_bundle_entries_total"]) + len(info.entries)
    for entry in info.entries:
        classification = classify_asset(entry.name, Path(entry.name).suffix.lstrip("."), registry)
        item = {
            "kind": "unity_bundle_entry",
            "source_path": str(file_path),
            "name": entry.name,
            "source_offset": entry.offset,
            "size": entry.size,
            "type_name": Path(entry.name).suffix.lstrip(".") or "unknown",
            "category": classification["category"],
            "decompile_value": classification["decompile_value"],
            "reason": classification["role"],
        }
        _record_unity_object(state, item)
        if not options.unity_reconstruct or not should_extract_category(
            classification["category"],
            options.mode,
            options.include_categories,
            options.exclude_categories,
        ):
            continue
        if not _can_write_bytes(state.summary, options, entry.size):
            _record_skipped(state.writer, state.summary, state.skipped_sample, item | {"reason": "blocked_output_budget"})
            continue
        state.summary["planned_output_bytes"] = int(state.summary["planned_output_bytes"]) + entry.size
        if output_dir is None:
            continue
        try:
            out_path, digest = extract_bundle_entry(
                file_path,
                info,
                entry,
                output_dir / "unity_bundle_entries" / file_path.stem,
                overwrite=options.overwrite,
                hash_output=options.hash_policy != "never",
            )
            record = {
                "output_path": str(out_path),
                "sidecar_path": "",
                "type": item["type_name"],
                "class_id": None,
                "path_id": None,
                "source_path": str(file_path),
                "source_offset": entry.offset,
                "length": entry.size,
                "sha256": digest,
                "validation_status": "unity_bundle_entry_range",
                "reconstruction_status": "raw_payload",
                "category": classification["category"],
                "decompile_value": classification["decompile_value"],
            }
            _record_reconstructed_unity(state, record)
            _record_extracted(state.writer, state.summary, state.extracted_sample, record)
        except (OSError, ValueError, EOFError) as exc:
            _record_failure(state, file_path, str(exc), entry.name)


def _process_unity_resource_blob(file_path: Path, state: RunState) -> None:
    item = {
        "kind": "unity_resource_blob",
        "source_path": str(file_path),
        "name": file_path.name,
        "source_offset": 0,
        "size": file_path.stat().st_size,
        "type_name": "UnityResourceBlob",
        "category": "containers",
        "decompile_value": "medium",
        "reason": "external_unity_resource_storage",
    }
    state.writer.object(item)
    state.summary["unity_resource_blobs_total"] = int(state.summary["unity_resource_blobs_total"]) + 1


def process_unity_artifacts(
    file_path: Path,
    output_dir: Path | None,
    probe: ProbeReport,
    state: RunState,
    options: ExtractionOptions,
    registry: CapabilityRegistry,
) -> None:
    if not options.unity_object_scan:
        return
    parser = str((probe.parse_info or {}).get("parser", ""))
    status = str((probe.parse_info or {}).get("status", ""))
    if parser == "unity_serialized_file" and status.startswith("parsed"):
        _process_unity_serialized_file(file_path, output_dir, state, options)
    elif parser == "unity_bundle" and status.startswith("parsed"):
        _process_unity_bundle_file(file_path, output_dir, state, options, registry)
    elif parser in {"unity_resource_blob", "fsb5"}:
        _process_unity_resource_blob(file_path, state)


def process_assembly_artifacts(file_path: Path, probe: ProbeReport, state: RunState) -> None:
    parse_info = probe.parse_info or {}
    if parse_info.get("parser") != "pe" or not parse_info.get("is_dotnet"):
        return
    for record in iter_assembly_types(file_path, parse_info):
        state.writer.assembly_type(record)
        state.summary["assembly_types_total"] = int(state.summary["assembly_types_total"]) + 1


def maybe_extract_embedded_candidate(
    input_path: Path,
    file_path: Path,
    output_dir: Path | None,
    candidate: EmbeddedCandidate,
    state: RunState,
    options: ExtractionOptions,
    registry: CapabilityRegistry,
) -> None:
    candidate_item = _candidate_item(candidate)
    state.writer.candidate(candidate_item)
    _sample_append(state.candidates_sample, candidate_item)
    if not should_extract_category(candidate.category, options.mode, options.include_categories, options.exclude_categories):
        return
    if not candidate.extractable or candidate.length is None:
        _record_skipped(
            state.writer,
            state.summary,
            state.skipped_sample,
            candidate_item | {"reason": candidate.reason or "found_not_extracted"},
        )
        return
    state.summary["planned_output_bytes"] = int(state.summary["planned_output_bytes"]) + candidate.length
    if output_dir is None:
        return
    if not _can_write_bytes(state.summary, options, candidate.length):
        _record_skipped(state.writer, state.summary, state.skipped_sample, candidate_item | {"reason": "blocked_output_budget"})
        return
    extension = _extension_for_type(candidate.detected_type, registry)
    content_hash = ""
    if options.naming == "hash":
        content_hash = sha256_range(file_path, candidate.offset, candidate.length, options.stream_chunk_size)
    relative = _asset_name(
        file_path,
        input_path,
        candidate.detected_type,
        extension,
        candidate.offset,
        content_hash,
        int(state.summary["extracted_total"]),
        options,
    )
    destination = output_dir / relative
    if destination.exists() and not options.overwrite:
        destination = ensure_unique(destination)
    digest = copy_range_streaming(
        file_path,
        destination,
        candidate.offset,
        candidate.length,
        options.stream_chunk_size,
        options.hash_policy != "never",
    )
    _record_extracted(
        state.writer,
        state.summary,
        state.extracted_sample,
        {
            "output_path": str(destination),
            "type": candidate.detected_type,
            "source_path": str(file_path),
            "source_offset": candidate.offset,
            "length": candidate.length,
            "sha256": digest,
            "validation_status": "range_valid",
            "category": candidate.category,
            "decompile_value": candidate.decompile_value,
        },
    )


def maybe_extract_embedded_source_candidate(
    input_path: Path,
    logical_path: Path,
    source: ArtifactSource,
    output_dir: Path | None,
    candidate: EmbeddedCandidate,
    state: RunState,
    options: ExtractionOptions,
    registry: CapabilityRegistry,
) -> None:
    candidate_item = _candidate_item(candidate) | {"logical_path": str(logical_path)}
    state.writer.candidate(candidate_item)
    _sample_append(state.candidates_sample, candidate_item)
    if not should_extract_category(candidate.category, options.mode, options.include_categories, options.exclude_categories):
        return
    if not candidate.extractable or candidate.length is None:
        _record_skipped(
            state.writer,
            state.summary,
            state.skipped_sample,
            candidate_item | {"reason": candidate.reason or "found_not_extracted"},
        )
        return
    state.summary["planned_output_bytes"] = int(state.summary["planned_output_bytes"]) + candidate.length
    if output_dir is None:
        return
    if not _can_write_bytes(state.summary, options, candidate.length):
        _record_skipped(state.writer, state.summary, state.skipped_sample, candidate_item | {"reason": "blocked_output_budget"})
        return
    extension = _extension_for_type(candidate.detected_type, registry)
    content_hash = (
        sha256_artifact_range(source, candidate.offset, candidate.length)
        if options.naming == "hash"
        else ""
    )
    relative = _asset_name(
        logical_path,
        input_path,
        candidate.detected_type,
        extension,
        candidate.offset,
        content_hash,
        int(state.summary["extracted_total"]),
        options,
    )
    destination = output_dir / relative
    if destination.exists() and not options.overwrite:
        destination = ensure_unique(destination)
    digest = copy_artifact_range(
        source,
        destination,
        candidate.offset,
        candidate.length,
        hash_output=options.hash_policy != "never",
    )
    _record_extracted(
        state.writer,
        state.summary,
        state.extracted_sample,
        {
            "output_path": str(destination),
            "type": candidate.detected_type,
            "source_path": str(logical_path),
            "source_offset": candidate.offset,
            "length": candidate.length,
            "sha256": digest,
            "validation_status": "range_valid",
            "category": candidate.category,
            "decompile_value": candidate.decompile_value,
        },
    )


def _container_entry_limit_reached(state: RunState, options: ExtractionOptions) -> bool:
    limit = options.max_container_entries
    return limit is not None and int(state.summary["container_entries_total"]) >= limit


def _logical_container_entry_path(container_path: Path, entry_name: str) -> Path:
    return container_path.parent / f"{container_path.stem}.contents" / Path(*Path(entry_name).parts)


def process_container_entry_artifact(
    input_path: Path,
    container_path: Path,
    physical_container_path: Path,
    entry: object,
    handler: object,
    output_dir: Path | None,
    state: RunState,
    options: ExtractionOptions,
    registry: CapabilityRegistry,
    depth: int,
) -> None:
    source = source_for_container_entry(handler, physical_container_path, entry, options.stream_chunk_size)
    if source is None:
        state.warnings.append(f"{container_path}:{entry.name}: container_entry_source_unavailable")
        return
    logical_path = _logical_container_entry_path(container_path, entry.name)
    try:
        probe = probe_artifact_source(source, logical_path, options, registry)
    except Exception as exc:
        _record_failure(state, container_path, f"artifact_probe_failed:{exc}", entry.name)
        return
    artifact_item = _probe_file_item(probe) | {
        "stream": "container_artifact",
        "container_path": str(container_path),
        "entry_name": entry.name,
        "depth": depth,
    }
    state.warnings.extend(f"{logical_path}: {warning}" for warning in probe.warnings)
    _record_capability_event(state, artifact_item)
    state.summary["embedded_candidates_total"] = int(state.summary["embedded_candidates_total"]) + len(probe.embedded_candidates)
    state.summary["embedded_extractable_total"] = int(state.summary["embedded_extractable_total"]) + sum(
        1 for candidate in probe.embedded_candidates if candidate.extractable
    )
    context = _capability_context(
        root=input_path,
        file_path=logical_path,
        output_dir=output_dir,
        identified_type=probe.identified_type,
        category=probe.category,
        decompile_value=probe.decompile_value,
        parse_info=probe.parse_info,
        state=state,
        options=options,
        registry=registry,
        probe=probe,
        depth=depth,
        source=source,
    )
    _run_registered_processors(
        "converter",
        registry.matching_converters(logical_path, probe.identified_type, probe.category),
        context,
        state,
    )
    _run_registered_processors(
        "reconstructor",
        registry.matching_reconstructors(logical_path, probe.identified_type, probe.category),
        context,
        state,
    )
    for candidate in probe.embedded_candidates:
        if _deadline_exceeded(state):
            break
        maybe_extract_embedded_source_candidate(
            input_path,
            logical_path,
            source,
            output_dir,
            candidate,
            state,
            options,
            registry,
        )
    if depth >= options.max_container_depth or source.size > options.max_in_memory_bytes:
        return
    try:
        with source.materialized(logical_path.suffix) as materialized_path:
            nested_handler = registry.find_container_handler(materialized_path, options.container_deep_scan)
            if nested_handler is not None:
                process_nested_container(
                    input_path,
                    logical_path,
                    materialized_path,
                    output_dir,
                    nested_handler,
                    state,
                    options,
                    registry,
                    depth + 1,
                )
    except Exception as exc:
        _record_failure(state, container_path, f"nested_container_failed:{exc}", entry.name)


def process_nested_container(
    input_path: Path,
    logical_path: Path,
    materialized_path: Path,
    output_dir: Path | None,
    handler: object,
    state: RunState,
    options: ExtractionOptions,
    registry: CapabilityRegistry,
    depth: int,
) -> None:
    opened = handler.open(materialized_path)
    state.summary["containers_total"] = int(state.summary["containers_total"]) + 1
    _record_capability_event(
        state,
        {
            "stream": "nested_container",
            "path": str(logical_path),
            "container_type": handler.type_name,
            "depth": depth,
            "container": opened.info.to_dict(),
        }
    )
    relative = safe_relative_path(logical_path, input_path if input_path.is_dir() else input_path.parent)
    container_output = output_dir / "containers" / relative.parent / logical_path.stem if output_dir else None
    for nested_entry in opened.iter_entries():
        if _deadline_exceeded(state):
            break
        if _container_entry_limit_reached(state, options):
            state.warnings.append(f"container_entry_limit_reached:{options.max_container_entries}")
            break
        state.summary["container_entries_total"] = int(state.summary["container_entries_total"]) + 1
        state.summary["deep_container_entries_total"] = int(state.summary["deep_container_entries_total"]) + 1
        state.summary["embedded_candidates_total"] = int(state.summary["embedded_candidates_total"]) + 1
        state.summary["embedded_extractable_total"] = int(state.summary["embedded_extractable_total"]) + 1
        entry_item = nested_entry.to_dict() | {
            "source_container": str(logical_path),
            "container_type": handler.type_name,
            "depth": depth,
        }
        state.writer.container_entry(entry_item)
        maybe_extract_container_entry(
            materialized_path,
            nested_entry,
            handler,
            container_output,
            state,
            options,
            registry,
            source_display_path=logical_path,
        )
        process_container_entry_artifact(
            input_path,
            logical_path,
            materialized_path,
            nested_entry,
            handler,
            output_dir,
            state,
            options,
            registry,
            depth,
        )


def process_container(
    input_path: Path,
    file_path: Path,
    output_dir: Path | None,
    handler: object,
    state: RunState,
    options: ExtractionOptions,
    registry: CapabilityRegistry,
) -> None:
    opened = handler.open(file_path)
    classification = classify_asset(str(file_path), handler.type_name, registry)
    file_item = {
        "path": str(file_path),
        "size": file_path.stat().st_size,
        "sha256": sha256_file(file_path) if options.hash_policy == "always" else "",
        "extension": file_path.suffix.lower(),
        "identified_type": handler.type_name,
        "confidence": 1.0,
        "status": "archive_index_valid",
        "category": classification["category"],
        "decompile_value": classification["decompile_value"],
        "reason": classification["role"],
        "container": opened.info.to_dict(),
        "parse_info": {"parser": "container_handler", "status": "parsed_index", "container": opened.info.to_dict()},
    }
    state.writer.file(file_item)
    _sample_append(state.files_sample, file_item)
    state.summary["files_total"] = int(state.summary["files_total"]) + 1
    state.summary["containers_total"] = int(state.summary["containers_total"]) + 1
    _bump(state.summary["by_type"], handler.type_name)
    _bump(state.summary["by_category"], classification["category"])
    _bump(state.summary["by_decompile_value"], classification["decompile_value"])
    context = _capability_context(
        root=input_path,
        file_path=file_path,
        output_dir=output_dir,
        identified_type=handler.type_name,
        category=classification["category"],
        decompile_value=classification["decompile_value"],
        parse_info=file_item["parse_info"],
        state=state,
        options=options,
        registry=registry,
    )
    _run_registered_processors(
        "converter",
        registry.matching_converters(file_path, handler.type_name, classification["category"]),
        context,
        state,
    )

    entries = opened.iter_entries()
    container_output = _output_base_for_container(input_path, file_path, output_dir) if output_dir else None
    for entry in entries:
        if _deadline_exceeded(state):
            break
        if _container_entry_limit_reached(state, options):
            state.warnings.append(f"container_entry_limit_reached:{options.max_container_entries}")
            break
        state.summary["container_entries_total"] = int(state.summary["container_entries_total"]) + 1
        state.summary["deep_container_entries_total"] = int(state.summary["deep_container_entries_total"]) + 1
        state.summary["embedded_candidates_total"] = int(state.summary["embedded_candidates_total"]) + 1
        state.summary["embedded_extractable_total"] = int(state.summary["embedded_extractable_total"]) + 1
        entry_item = entry.to_dict() | {"container_type": handler.type_name}
        state.writer.container_entry(entry_item)
        if handler.type_name in {"unreal_pak", "utoc"}:
            state.writer.unreal_entry(entry_item)
            state.summary["unreal_entries_total"] = int(state.summary["unreal_entries_total"]) + 1
        maybe_extract_container_entry(file_path, entry, handler, container_output, state, options, registry)
        process_container_entry_artifact(
            input_path,
            file_path,
            file_path,
            entry,
            handler,
            output_dir,
            state,
            options,
            registry,
            1,
        )


def process_regular_file(
    input_path: Path,
    file_path: Path,
    output_dir: Path | None,
    state: RunState,
    options: ExtractionOptions,
    registry: CapabilityRegistry,
    direct_extract_known_only: bool = False,
) -> None:
    probe = probe_file(file_path, options, registry)
    file_item = _probe_file_item(probe)
    state.writer.file(file_item)
    _sample_append(state.files_sample, file_item)
    state.summary["files_total"] = int(state.summary["files_total"]) + 1
    _bump(state.summary["by_type"], probe.identified_type)
    _bump(state.summary["by_category"], probe.category)
    _bump(state.summary["by_decompile_value"], probe.decompile_value)
    state.summary["embedded_candidates_total"] = int(state.summary["embedded_candidates_total"]) + len(probe.embedded_candidates)
    state.summary["embedded_extractable_total"] = int(state.summary["embedded_extractable_total"]) + sum(
        1 for candidate in probe.embedded_candidates if candidate.extractable
    )
    state.warnings.extend(f"{file_path}: {warning}" for warning in probe.warnings)
    context = _capability_context(
        root=input_path,
        file_path=file_path,
        output_dir=output_dir,
        identified_type=probe.identified_type,
        category=probe.category,
        decompile_value=probe.decompile_value,
        parse_info=probe.parse_info,
        state=state,
        options=options,
        registry=registry,
        probe=probe,
    )
    _run_registered_processors(
        "converter",
        registry.matching_converters(file_path, probe.identified_type, probe.category),
        context,
        state,
    )
    _run_registered_processors(
        "reconstructor",
        registry.matching_reconstructors(file_path, probe.identified_type, probe.category),
        context,
        state,
    )
    maybe_extract_direct_file(input_path, file_path, output_dir, probe, file_item, state, options, registry, direct_extract_known_only)
    for candidate in probe.embedded_candidates:
        if _deadline_exceeded(state):
            break
        maybe_extract_embedded_candidate(input_path, file_path, output_dir, candidate, state, options, registry)


def process_size_limited_file(
    file_path: Path,
    state: RunState,
    options: ExtractionOptions,
    registry: CapabilityRegistry,
) -> None:
    probe = probe_file(file_path, options, registry)
    file_item = _probe_file_item(probe)
    state.writer.file(file_item)
    _sample_append(state.files_sample, file_item)
    state.summary["files_total"] = int(state.summary["files_total"]) + 1
    _bump(state.summary["by_type"], probe.identified_type)
    _bump(state.summary["by_category"], probe.category)
    _bump(state.summary["by_decompile_value"], probe.decompile_value)
    state.warnings.extend(f"{file_path}: {warning}" for warning in probe.warnings)
    _record_skipped(
        state.writer,
        state.summary,
        state.skipped_sample,
        file_item | {"reason": "blocked_file_size_limit"},
    )


def _excluded_outputs(input_path: Path, output_dir: Path | None) -> list[Path]:
    if output_dir is not None and input_path.is_dir() and _is_within(output_dir, input_path):
        return [output_dir]
    return []


def _run_decompilation(
    input_path: Path,
    output_dir: Path | None,
    options: ExtractionOptions,
    direct_extract_known_only: bool = False,
) -> DecompilationReport:
    if input_path.is_dir() and output_dir is not None and input_path.resolve() == output_dir.resolve(strict=False):
        raise ValueError("output directory must not be the same directory as the input root")
    started_at = _now()
    registry = _registry_for_options(options)
    with JsonlManifestWriter(output_dir) as writer:
        state = RunState(
            writer=writer,
            deadline=(monotonic() + options.max_processing_seconds if options.max_processing_seconds is not None else None),
        )
        with use_registry(registry):
            state.warnings.extend(f"capability_registry: {warning}" for warning in registry.load_errors)
            excluded_outputs = _excluded_outputs(input_path, output_dir)

            def discover() -> Iterable[Path]:
                return _discover(
                    input_path,
                    options.recursive,
                    excluded_outputs,
                    sort_paths=options.sort_paths,
                )

            run_context = RunContext(
                input_path=input_path,
                output_dir=output_dir,
                options=options,
                registry=registry,
                summary=state.summary,
                warnings=state.warnings,
                services=state.services,
                discover=discover,
            )
            state.services["deadline_exceeded"] = lambda: _deadline_exceeded(state)
            for hook in registry.run_hooks:
                if _deadline_exceeded(state):
                    break
                try:
                    hook.hook(run_context)
                except Exception as exc:
                    registry.record_runtime_error(hook, input_path, exc)
                    state.warnings.append(f"run_hook_failed:{hook.capability_id}:{exc}")
            for file_path in discover():
                if _deadline_exceeded(state):
                    break
                try:
                    if (
                        options.max_file_size_mb is not None
                        and file_path.stat().st_size > options.max_file_size_mb * 1024 * 1024
                    ):
                        process_size_limited_file(file_path, state, options, registry)
                        continue
                    handler = registry.find_container_handler(file_path, options.container_deep_scan)
                    if handler is not None:
                        process_container(input_path, file_path, output_dir, handler, state, options, registry)
                    else:
                        process_regular_file(input_path, file_path, output_dir, state, options, registry, direct_extract_known_only)
                except Exception as exc:
                    _record_failure(state, file_path, str(exc))
                state.warnings.extend(
                    f"capability_runtime: {warning}" for warning in registry.drain_runtime_errors()
                )

        finished_at = _now()
        payload = {
            "version": VERSION,
            "input_path": str(input_path),
            "started_at": started_at,
            "finished_at": finished_at,
            "mode": options.mode,
            "summary": state.summary,
            "warnings": state.warnings,
            "manifest_paths": writer.paths.to_dict(),
        }
        writer.summary(payload)
        return DecompilationReport(
            version=VERSION,
            input_path=str(input_path),
            started_at=started_at,
            finished_at=finished_at,
            mode=options.mode,
            summary=state.summary,
            warnings=state.warnings,
            manifest_paths=writer.paths,
            files_sample=state.files_sample,
            candidates_sample=state.candidates_sample,
            output_dir=str(output_dir) if output_dir is not None else "",
            extracted_sample=state.extracted_sample,
            skipped_sample=state.skipped_sample,
            failed_sample=state.failed_sample,
        )


def plan_path(
    input_path: str | Path,
    output_dir: str | Path | None = None,
    options: ScanOptions | None = None,
) -> DecompilationPlan:
    plan_options = ExtractionOptions(**(_coerce_scan_options(options).to_dict()))
    plan_options.mode = "manifest_only"
    report = _run_decompilation(Path(input_path), Path(output_dir) if output_dir is not None else None, plan_options)
    return DecompilationPlan(
        version=report.version,
        input_path=report.input_path,
        started_at=report.started_at,
        finished_at=report.finished_at,
        mode=report.mode,
        summary=report.summary,
        warnings=report.warnings,
        manifest_paths=report.manifest_paths,
        files_sample=report.files_sample,
        candidates_sample=report.candidates_sample,
    )


def decompile_path(
    input_path: str | Path,
    output_dir: str | Path,
    options: ExtractionOptions | None = None,
) -> DecompilationReport:
    decompile_options = _coerce_extraction_options(options)
    return _run_decompilation(Path(input_path), Path(output_dir), decompile_options)


def _asset_name(
    source_path: Path,
    root: Path,
    type_name: str,
    extension: str,
    offset: int,
    content_hash: str,
    index: int,
    options: ExtractionOptions,
) -> Path:
    suffix = extension if extension.startswith(".") else f".{extension}"
    if options.naming == "hash":
        if not content_hash:
            raise ValueError("hash naming requires a content hash")
        name = f"{type_name}_{content_hash[:16]}{suffix}"
    elif options.naming == "type_index":
        name = f"{type_name}_{index:04d}{suffix}"
    else:
        name = f"{type_name}_{offset:08x}{suffix}"
    if options.preserve_paths:
        relative_parent = safe_relative_path(source_path, root if root.is_dir() else root.parent).parent
        return relative_parent / name
    return Path(name)


def _extracted_asset_from_item(item: dict[str, object]) -> ExtractedAsset:
    return ExtractedAsset(
        output_path=str(item.get("output_path", "")),
        type=str(item.get("type", "unknown")),
        source_path=str(item.get("source_path", "")),
        source_offset=int(item.get("source_offset") or 0),
        length=int(item.get("length") or 0),
        sha256=str(item.get("sha256", "")),
        validation_status=str(item.get("validation_status", "")),
    )


def _file_report_from_item(item: dict[str, object]) -> FileReport:
    entropy = item.get("entropy")
    return FileReport(
        path=str(item.get("path", "")),
        size=int(item.get("size") or 0),
        sha256=str(item.get("sha256", "")),
        extension=str(item.get("extension", "")),
        identified_type=str(item.get("identified_type", "unknown")),
        confidence=float(item.get("confidence") or 0.0),
        magic=str(item.get("magic", "")),
        entropy=float(entropy) if isinstance(entropy, (int, float)) else None,
        strings_preview=list(item.get("strings_preview") or []),
        embedded_candidates=[],
        compression_hints=list(item.get("compression_hints") or []),
        status=str(item.get("status", "")),
        warnings=list(item.get("warnings") or []),
        category=str(item.get("category", "unknown")),
        decompile_value=str(item.get("decompile_value", "none")),
        reason=str(item.get("reason", "")),
        parse_info=dict(item.get("parse_info") or {}),
    )


def extract_path(
    input_path: str | Path,
    output_dir: str | Path,
    options: ExtractionOptions | None = None,
) -> ExtractionReport:
    extraction_options = ExtractionOptions(**_coerce_extraction_options(options).to_dict())
    extraction_options.mode = "full"
    excluded = set(extraction_options.exclude_categories or [])
    excluded.add("unknown")
    extraction_options.exclude_categories = list(excluded)
    root = Path(input_path)
    out = Path(output_dir)
    report = _run_decompilation(root, out, extraction_options, direct_extract_known_only=True)
    extracted = [_extracted_asset_from_item(item) for item in report.extracted_sample]
    warnings = list(report.warnings)
    if int(report.summary.get("extracted_total", 0)) > len(extracted):
        warning_prefix = "legacy_extract_path_container_report_truncated" if root.is_file() else "legacy_extract_path_report_truncated"
        warnings.append(f"{warning_prefix}: use decompile_path() and extracted.jsonl for complete results")
    legacy_report = ExtractionReport(
        version=VERSION,
        input_path=str(root),
        started_at=report.started_at,
        finished_at=report.finished_at,
        files=[_file_report_from_item(item) for item in report.files_sample],
        summary=report.summary,
        warnings=warnings,
        output_dir=str(out),
        extracted=extracted,
        failed=report.failed_sample,
        skipped=report.skipped_sample,
    )
    write_text_atomic(out / "deinserter-manifest.json", json.dumps(legacy_report.to_dict(), indent=2))
    return legacy_report
