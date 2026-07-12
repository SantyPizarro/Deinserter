from __future__ import annotations

from pathlib import Path

from .registry import CapabilityContext, CapabilityRegistry, RunContext
from .semantic import build_semantic_conversion, semantic_spec_for_extension


def semantic_converter(context: CapabilityContext):
    semantic_spec = semantic_spec_for_extension(context.logical_path.suffix)
    needs_full_materialization = semantic_spec is not None and semantic_spec.strategy in {"mo_to_po", "extract_glb_json_chunk"}
    if needs_full_materialization and context.source.size > context.options.max_in_memory_bytes:
        item = {
            "source_path": str(context.logical_path),
            "status": "blocked_materialization_limit",
            "output_path": "",
            "required_bytes": context.source.size,
            "max_in_memory_bytes": context.options.max_in_memory_bytes,
        }
        context.emit("semantic_conversion", item)
        return item
    direct_path = (
        context.source.is_direct_file
        and context.source.source_path is not None
        and context.source.source_path.resolve(strict=False) == context.logical_path.resolve(strict=False)
    )

    def convert(input_path):
        return build_semantic_conversion(
            context.root,
            context.logical_path,
            context.output_dir,
            context.logical_path.suffix.lower(),
            context.identified_type,
            context.category,
            context.parse_info,
            context.options.mode,
            context.options.overwrite,
            context.can_write,
            input_path,
        )

    if direct_path:
        item = convert(context.logical_path)
    elif context.source.size <= context.options.max_in_memory_bytes:
        with context.source.materialized(context.logical_path.suffix) as materialized_path:
            item = convert(materialized_path)
    else:
        item = {
            "source_path": str(context.logical_path),
            "status": "blocked_materialization_limit",
            "output_path": "",
        }
    if item is not None:
        context.emit("semantic_conversion", item)
    return item


def unity_reconstructor(context: CapabilityContext):
    probe = context.services.get("probe")
    state = context.services.get("state")
    if probe is None or state is None:
        return None
    if not context.source.is_direct_file or context.source.source_path is None:
        return {"status": "source_reconstructor_not_supported", "type": "unity"}
    from .pipeline import process_unity_artifacts

    process_unity_artifacts(
        context.logical_path,
        context.output_dir,
        probe,
        state,
        context.options,
        context.registry,
    )
    return None


def assembly_metadata_converter(context: CapabilityContext):
    probe = context.services.get("probe")
    state = context.services.get("state")
    if probe is None or state is None:
        return None
    if not context.source.is_direct_file or context.source.source_path is None:
        return {"status": "source_converter_not_supported", "type": "dotnet_assembly_metadata"}
    from .pipeline import process_assembly_artifacts

    process_assembly_artifacts(context.logical_path, probe, state)
    return None


def _is_unity_resource_path(path: Path) -> bool:
    name = path.name.lower()
    return path.suffix.lower() in {".resource", ".ress"} or name.endswith(".resS".lower())


def prepare_unity_run(context: RunContext) -> None:
    if not context.options.unity_object_scan:
        return
    from .unity.index import UnityProjectIndex

    def eligible(paths):
        for path in paths:
            try:
                size = path.stat().st_size
            except OSError as exc:
                context.warnings.append(f"{path}: unity_index_stat_error:{exc}")
                continue
            if context.options.max_file_size_mb is not None and size > context.options.max_file_size_mb * 1024 * 1024:
                continue
            yield path

    resource_files = [path for path in eligible(context.discover()) if _is_unity_resource_path(path)]
    unity_index = UnityProjectIndex()
    unity_index.build(eligible(context.discover()))
    context.services["unity_resource_files"] = resource_files
    context.services["unity_index"] = unity_index
    context.summary["unity_indexed_files_total"] = unity_index.indexed_files_total
    context.summary["unity_indexed_objects_total"] = unity_index.indexed_objects_total
    context.warnings.extend(
        f"{path}: unity_index_parse_error:{reason}"
        for path, reason in sorted(unity_index.parse_errors.items())
    )


def register_builtin_processors(registry: CapabilityRegistry) -> None:
    registry.add_run_hook(
        prepare_unity_run,
        name="builtin_unity_run_preparation",
        capability_id="builtin:run_hook:unity",
    )
    registry.add_converter(
        semantic_converter,
        name="builtin_semantic_conversion",
        capability_id="builtin:converter:semantic",
        predicate=lambda path, _type, _category: semantic_spec_for_extension(path.suffix) is not None,
    )
    registry.add_reconstructor(
        unity_reconstructor,
        name="builtin_unity_reconstruction",
        capability_id="builtin:reconstructor:unity",
        predicate=lambda path, identified_type, _category: identified_type in {
            "unity_serialized", "unity_bundle", "unity_resource", "fsb"
        }
        or path.name.lower() in {"globalgamemanagers", "unity default resources"}
        or path.suffix.lower() in {".assets", ".bundle", ".resource", ".ress"},
    )
    registry.add_converter(
        assembly_metadata_converter,
        name="builtin_dotnet_assembly_metadata",
        capability_id="builtin:converter:assembly_metadata",
        type_names={"dll", "exe"},
        extensions={".dll", ".exe"},
    )
