from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

from .formats import load_format_specs
from .models import ExtractionOptions, ScanOptions
from .pipeline import decompile_path, extract_path, plan_path, probe_file, scan_path
from .registry import build_capability_registry, register_plugin_callable
from .resources import write_text_atomic


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _add_scan_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("input", help="File or directory to scan.")
    parser.add_argument("--no-recursive", action="store_true", help="Only scan direct children.")
    parser.add_argument("--no-sort-paths", action="store_true", help="Process discovered files in filesystem order.")
    parser.add_argument("--max-file-size-mb", type=_non_negative_int, default=None, help="Skip probing files above this size.")
    parser.add_argument("--string-min-length", type=_positive_int, default=6, help="Minimum length for strings preview.")
    parser.add_argument("--entropy-block-size", type=_positive_int, default=4096, help="Entropy sample block size.")
    parser.add_argument("--no-embedded-scan", action="store_true", help="Disable embedded asset candidate scanning.")
    parser.add_argument("--max-in-memory-bytes", type=_non_negative_int, default=64 * 1024 * 1024)
    parser.add_argument("--stream-chunk-size", type=_positive_int, default=8 * 1024 * 1024)
    parser.add_argument("--hash-policy", choices=["extracted", "always", "never"], default="extracted")
    parser.add_argument("--max-output-bytes", type=_non_negative_int, default=None)
    parser.add_argument("--include-categories", default=None, help="Comma-separated categories to include.")
    parser.add_argument("--exclude-categories", default=None, help="Comma-separated categories to exclude.")
    parser.add_argument("--unity-external-resource-roots", default=None, help="Comma-separated roots for Unity .resS/.resource lookup.")
    parser.add_argument("--unity-decode-media", action="store_true", help="Enable optional Unity media decoders when installed.")
    parser.add_argument("--no-container-deep-scan", action="store_true", help="Disable deep handlers for versioned containers.")
    parser.add_argument("--container-keyring-path", default=None, help="Path to user-provided container keys; no key discovery is attempted.")
    parser.add_argument("--max-container-depth", type=_non_negative_int, default=4)
    parser.add_argument("--max-container-entries", type=_non_negative_int, default=100_000)
    parser.add_argument("--max-embedded-candidates", type=_non_negative_int, default=100_000)
    parser.add_argument("--max-processing-seconds", type=_positive_float, default=None)
    parser.add_argument("--format-pack", action="append", default=None, help="Path to a formats.toml file or directory containing one.")
    parser.add_argument("--disable-plugin", action="append", default=None, help="Entry-point plugin name to disable for this run.")
    parser.add_argument("--json", action="store_true", help="Print JSON output.")


def _add_format_pack_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format-pack", action="append", default=None, help="Path to a formats.toml file or directory containing one.")
    parser.add_argument("--disable-plugin", action="append", default=None, help="Entry-point plugin name to disable for this run.")
    parser.add_argument("--json", action="store_true", help="Print JSON output.")


def _csv(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


def _scan_options(args: argparse.Namespace) -> ScanOptions:
    return ScanOptions(
        recursive=not args.no_recursive,
        sort_paths=not args.no_sort_paths,
        max_file_size_mb=args.max_file_size_mb,
        string_min_length=args.string_min_length,
        entropy_block_size=args.entropy_block_size,
        embedded_scan=not args.no_embedded_scan,
        max_in_memory_bytes=args.max_in_memory_bytes,
        stream_chunk_size=args.stream_chunk_size,
        hash_policy=args.hash_policy,
        max_output_bytes=args.max_output_bytes,
        include_categories=_csv(args.include_categories),
        exclude_categories=_csv(args.exclude_categories),
        unity_external_resource_roots=_csv(args.unity_external_resource_roots),
        unity_decode_media=args.unity_decode_media,
        container_deep_scan=not args.no_container_deep_scan,
        container_keyring_path=args.container_keyring_path,
        format_pack_paths=args.format_pack,
        disabled_plugins=args.disable_plugin,
        max_container_depth=args.max_container_depth,
        max_container_entries=args.max_container_entries,
        max_embedded_candidates=args.max_embedded_candidates,
        max_processing_seconds=args.max_processing_seconds,
    )


def _extract_options(args: argparse.Namespace) -> ExtractionOptions:
    return ExtractionOptions(
        recursive=not args.no_recursive,
        sort_paths=not args.no_sort_paths,
        max_file_size_mb=args.max_file_size_mb,
        string_min_length=args.string_min_length,
        entropy_block_size=args.entropy_block_size,
        embedded_scan=not args.no_embedded_scan,
        max_in_memory_bytes=args.max_in_memory_bytes,
        stream_chunk_size=args.stream_chunk_size,
        hash_policy=args.hash_policy,
        max_output_bytes=args.max_output_bytes,
        mode=getattr(args, "mode", "full"),
        include_categories=_csv(args.include_categories),
        exclude_categories=_csv(args.exclude_categories),
        unity_external_resource_roots=_csv(args.unity_external_resource_roots),
        unity_decode_media=args.unity_decode_media,
        container_deep_scan=not args.no_container_deep_scan,
        container_keyring_path=args.container_keyring_path,
        format_pack_paths=args.format_pack,
        disabled_plugins=args.disable_plugin,
        max_container_depth=args.max_container_depth,
        max_container_entries=args.max_container_entries,
        max_embedded_candidates=args.max_embedded_candidates,
        max_processing_seconds=args.max_processing_seconds,
        overwrite=args.overwrite,
        preserve_paths=not args.no_preserve_paths,
        naming=args.naming,
        validate_outputs=not args.no_validate_outputs,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="deinserter")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan files and print a manifest.")
    _add_scan_options(scan_parser)

    plan_parser = subparsers.add_parser("plan", help="Create a streaming decompilation plan.")
    _add_scan_options(plan_parser)
    plan_parser.add_argument("--out", default=None, help="Optional directory for JSONL manifests.")

    decompile_parser = subparsers.add_parser("decompile", help="Run the streaming-first decompiler.")
    _add_scan_options(decompile_parser)
    decompile_parser.add_argument("--out", required=True, help="Output directory.")
    decompile_parser.add_argument("--mode", choices=["manifest_only", "selective", "full"], default="manifest_only")
    decompile_parser.add_argument("--overwrite", action="store_true", help="Overwrite existing outputs.")
    decompile_parser.add_argument("--no-preserve-paths", action="store_true", help="Do not mirror source directories.")
    decompile_parser.add_argument("--naming", choices=["hash", "offset", "type_index"], default="offset")
    decompile_parser.add_argument("--no-validate-outputs", action="store_true", help="Write candidates without validation.")

    extract_parser = subparsers.add_parser("extract", help="Extract verified assets.")
    _add_scan_options(extract_parser)
    extract_parser.add_argument("--out", required=True, help="Output directory.")
    extract_parser.add_argument("--overwrite", action="store_true", help="Overwrite existing outputs.")
    extract_parser.add_argument("--no-preserve-paths", action="store_true", help="Do not mirror source directories.")
    extract_parser.add_argument("--naming", choices=["hash", "offset", "type_index"], default="offset")
    extract_parser.add_argument("--no-validate-outputs", action="store_true", help="Write candidates without validation.")

    probe_parser = subparsers.add_parser("probe", help="Probe one file and explain detected capabilities.")
    probe_parser.add_argument("input", help="File to probe.")
    _add_format_pack_option(probe_parser)
    probe_parser.add_argument("--explain", action="store_true", help="Include registry capability context.")

    formats_parser = subparsers.add_parser("formats", help="Inspect format capabilities.")
    formats_subparsers = formats_parser.add_subparsers(dest="formats_command", required=True)
    formats_list_parser = formats_subparsers.add_parser("list", help="List registered formats.")
    _add_format_pack_option(formats_list_parser)
    formats_unknown_parser = formats_subparsers.add_parser("unknown", help="List files that remain unidentified.")
    _add_scan_options(formats_unknown_parser)

    plugin_parser = subparsers.add_parser("plugin", help="Create and validate Deinserter capability packs.")
    plugin_subparsers = plugin_parser.add_subparsers(dest="plugin_command", required=True)
    plugin_init_parser = plugin_subparsers.add_parser("init", help="Scaffold a local plugin/format pack.")
    plugin_init_parser.add_argument("path", help="Directory to create or update.")
    plugin_init_parser.add_argument("--name", default=None, help="Plugin package name. Defaults to the directory name.")
    plugin_init_parser.add_argument(
        "--template",
        choices=["descriptor", "detector", "parser", "converter", "container", "full"],
        default="descriptor",
    )
    plugin_validate_parser = plugin_subparsers.add_parser("validate", help="Validate a formats.toml file or plugin directory.")
    plugin_validate_parser.add_argument("path", help="Path to a formats.toml file or directory containing one.")
    plugin_validate_parser.add_argument("--json", action="store_true", help="Print JSON output.")
    plugin_test_parser = plugin_subparsers.add_parser("test", help="Probe a sample with a local plugin and assert its type.")
    plugin_test_parser.add_argument("path", help="Plugin directory.")
    plugin_test_parser.add_argument("sample", help="Sample file to probe.")
    plugin_test_parser.add_argument("--expected-type", default=None)
    plugin_test_parser.add_argument("--json", action="store_true", help="Print JSON output.")
    return parser


def _formats_payload(format_pack_paths: list[str] | None, disabled_plugins: list[str] | None = None) -> dict[str, object]:
    registry = build_capability_registry(format_pack_paths, disabled_plugins=disabled_plugins or ())
    return {
        "formats": [
            {
                "type_name": spec.type_name,
                "extensions": list(spec.extensions),
                "category": spec.category,
                "role": spec.role,
                "decompile_value": spec.decompile_value,
                "text": spec.text,
            }
            for spec in registry.formats
        ],
        "detectors": [getattr(detector, "type_name", "unknown") for detector in registry.detectors],
        "streaming_detectors": [detector.type_name for detector in registry.streaming_detectors],
        "containers": [getattr(handler, "type_name", "unknown") for handler in registry.container_handlers],
        "parsers": [parser.name for parser in registry.parsers],
        "converters": [converter.name for converter in registry.converters],
        "reconstructors": [reconstructor.name for reconstructor in registry.reconstructors],
        "run_hooks": [hook.name for hook in registry.run_hooks],
        "api_version": registry.api_version,
        "plugins": registry.plugins,
        "conflicts": registry.conflicts,
        "load_errors": registry.load_errors,
    }


def _unknown_formats_payload(args: argparse.Namespace) -> dict[str, object]:
    report = scan_path(Path(args.input), _scan_options(args))
    unknown = [
        {
            "path": item.path,
            "extension": item.extension,
            "magic": item.magic,
            "size": item.size,
            "status": item.status,
            "category": item.category,
            "reason": item.reason,
        }
        for item in report.files
        if item.identified_type == "unknown" or item.category == "unknown"
    ]
    by_extension: dict[str, int] = {}
    for item in unknown:
        extension = str(item["extension"] or "<none>")
        by_extension[extension] = by_extension.get(extension, 0) + 1
    return {
        "input_path": report.input_path,
        "unknown_count": len(unknown),
        "by_extension": by_extension,
        "unknown": unknown,
        "warnings": report.warnings,
    }


def _plugin_name(path: Path, requested: str | None) -> str:
    raw = requested or path.name or "deinserter_plugin"
    return "".join(ch.lower() if ch.isalnum() else "_" for ch in raw).strip("_") or "deinserter_plugin"


def _plugin_template_code(template: str) -> str:
    registrations: list[str] = ["    registry.add_formats(load_format_specs(Path(__file__).with_name(\"formats.toml\")))"]
    definitions: list[str] = []
    if template in {"detector", "full"}:
        definitions.append(
            '''class ExampleDetector:
    type_name = "example_dialogue"
    extension = ".dialogue"

    def identify(self, data, path):
        if not data.startswith(b"DIALOGUE\\0"):
            return None
        from deinserter import FileIdentification
        return FileIdentification(str(path), self.type_name, 1.0, path.suffix.lower(), data[:8].hex())

    def find_embedded(self, data, source_file):
        return []

    def validate(self, data):
        return data.startswith(b"DIALOGUE\\0")


def example_stream_length(source, offset, signature):
    return source.size - offset
'''
        )
        registrations.extend(
            [
                '    registry.add_detector(ExampleDetector(), capability_id="example:detector", priority=100)',
                '    registry.add_streaming_detector(type_name="example_dialogue", signatures=(b"DIALOGUE\\0",), length_reader=example_stream_length, extension=".dialogue", capability_id="example:streaming", priority=100)',
            ]
        )
    if template in {"parser", "full"}:
        definitions.append(
            '''def parse_dialogue(source, path):
    return {"parser": "example_dialogue", "status": "parsed", "size": source.size}
'''
        )
        registrations.append(
            '    registry.add_source_parser(parse_dialogue, name="example_dialogue", capability_id="example:parser", extensions={".dialogue"}, priority=100)'
        )
    if template in {"converter", "full"}:
        definitions.append(
            '''def convert_dialogue(context):
    return {"status": "planned", "bytes": context.source.size}
'''
        )
        registrations.append(
            '    registry.add_converter(convert_dialogue, name="example_dialogue", capability_id="example:converter", extensions={".dialogue"}, priority=100)'
        )
    if template in {"container", "full"}:
        definitions.append(
            '''class ExampleContainerHandler:
    type_name = "example_container"

    def sniff(self, path):
        return False

    def open(self, path):
        raise ValueError("example container parser not implemented")

    def extract_entry(self, path, entry, output_dir, overwrite, chunk_size, hash_output):
        raise ValueError("example container extractor not implemented")
'''
        )
        registrations.append(
            '    registry.add_container_handler(ExampleContainerHandler(), capability_id="example:container", priority=100)'
        )
    definitions_text = "\n\n".join(definitions)
    return f'''"""Example Deinserter capability plugin."""

from pathlib import Path

from deinserter import CAPABILITY_API_VERSION
from deinserter.formats import load_format_specs

DEINSERTER_API_VERSION = CAPABILITY_API_VERSION

{definitions_text}

def register(registry):
{chr(10).join(registrations)}
'''


def _init_plugin(path: Path, name: str | None = None, template: str = "descriptor") -> dict[str, object]:
    plugin_name = _plugin_name(path, name)
    path.mkdir(parents=True, exist_ok=True)
    files: dict[Path, str] = {
        path / "formats.toml": """# Add extension-only formats here. Python code is optional.
[[formats]]
type_name = "example_dialogue"
extensions = [".dialogue"]
category = "data"
role = "game_dialogue_text"
decompile_value = "high"
text = true
""",
        path / "deinserter_plugin.py": _plugin_template_code(template),
        path / "pyproject.toml": f'''[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "{plugin_name.replace("_", "-")}"
version = "0.1.0"
dependencies = ["deinserter"]

[project.entry-points."deinserter.plugins"]
{plugin_name} = "deinserter_plugin:register"

[tool.setuptools]
py-modules = ["deinserter_plugin"]

[tool.setuptools.package-data]
"*" = ["formats.toml"]
''',
    }
    created: list[str] = []
    skipped: list[str] = []
    for file_path, content in files.items():
        if file_path.exists():
            skipped.append(str(file_path))
            continue
        write_text_atomic(file_path, content)
        created.append(str(file_path))
    return {"path": str(path), "plugin_name": plugin_name, "template": template, "created": created, "skipped_existing": skipped}


def _validate_plugin(path: Path) -> dict[str, object]:
    format_file = path / "formats.toml" if path.is_dir() else path
    plugin_file = path / "deinserter_plugin.py" if path.is_dir() else None
    try:
        specs = load_format_specs(format_file) if format_file.exists() else ()
        registry = build_capability_registry([format_file] if format_file.exists() else (), load_plugins=False)
        before = {
            "detectors": len(registry.detectors),
            "streaming_detectors": len(registry.streaming_detectors),
            "containers": len(registry.container_handlers),
            "parsers": len(registry.parsers),
            "converters": len(registry.converters),
            "reconstructors": len(registry.reconstructors),
            "run_hooks": len(registry.run_hooks),
        }
        if plugin_file is not None and plugin_file.exists():
            register = _load_local_register(plugin_file)
            register_plugin_callable(registry, path.name, register)
        after = {
            "detectors": len(registry.detectors),
            "streaming_detectors": len(registry.streaming_detectors),
            "containers": len(registry.container_handlers),
            "parsers": len(registry.parsers),
            "converters": len(registry.converters),
            "reconstructors": len(registry.reconstructors),
            "run_hooks": len(registry.run_hooks),
        }
        added = {key: after[key] - before[key] for key in before}
    except Exception as exc:
        return {
            "path": str(path),
            "valid": False,
            "format_count": 0,
            "formats": [],
            "capabilities_added": {},
            "load_errors": [str(exc)],
        }
    return {
        "path": str(format_file),
        "valid": not registry.load_errors and not registry.conflicts,
        "format_count": len(specs),
        "formats": [
            {
                "type_name": spec.type_name,
                "extensions": list(spec.extensions),
                "category": spec.category,
                "role": spec.role,
                "decompile_value": spec.decompile_value,
                "text": spec.text,
            }
            for spec in specs
        ],
        "capabilities_added": added,
        "plugins": registry.plugins,
        "conflicts": registry.conflicts,
        "load_errors": registry.load_errors,
    }


def _load_local_register(plugin_file: Path):
    module_name = f"_deinserter_validate_{abs(hash(plugin_file.resolve()))}"
    spec = importlib.util.spec_from_file_location(module_name, plugin_file)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load plugin module: {plugin_file}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    register = getattr(module, "register", None)
    if not callable(register):
        raise ValueError(f"plugin module does not define callable register(registry): {plugin_file}")
    declared_version = getattr(module, "DEINSERTER_API_VERSION", None)
    if declared_version is not None:
        register.DEINSERTER_API_VERSION = declared_version
    return register


def _test_plugin(path: Path, sample: Path, expected_type: str | None) -> dict[str, object]:
    format_file = path / "formats.toml"
    registry = build_capability_registry([format_file] if format_file.exists() else (), load_plugins=False)
    plugin_file = path / "deinserter_plugin.py"
    if plugin_file.exists():
        register_plugin_callable(registry, path.name, _load_local_register(plugin_file))
    report = probe_file(sample, ScanOptions(), registry)
    matched = expected_type is None or report.identified_type == expected_type
    return {
        "plugin_path": str(path),
        "sample": str(sample),
        "expected_type": expected_type or "",
        "identified_type": report.identified_type,
        "matched": matched,
        "probe": report.to_dict(),
        "load_errors": registry.load_errors,
    }


def _print_payload(payload: dict[str, object], as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2))
    else:
        print(json.dumps(payload, indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        report = scan_path(Path(args.input), _scan_options(args))
    elif args.command == "plan":
        report = plan_path(Path(args.input), Path(args.out) if args.out else None, _scan_options(args))
    elif args.command == "decompile":
        report = decompile_path(Path(args.input), Path(args.out), _extract_options(args))
    elif args.command == "extract":
        report = extract_path(Path(args.input), Path(args.out), _extract_options(args))
    elif args.command == "probe":
        payload = probe_file(
            Path(args.input),
            ScanOptions(format_pack_paths=args.format_pack, disabled_plugins=args.disable_plugin),
        ).to_dict()
        if args.explain:
            payload = {"probe": payload, "registry": _formats_payload(args.format_pack, args.disable_plugin)}
        _print_payload(payload, args.json)
        return 0
    elif args.command == "formats":
        if args.formats_command == "list":
            _print_payload(_formats_payload(args.format_pack, args.disable_plugin), args.json)
        elif args.formats_command == "unknown":
            _print_payload(_unknown_formats_payload(args), args.json)
        return 0
    elif args.command == "plugin":
        if args.plugin_command == "init":
            _print_payload(_init_plugin(Path(args.path), args.name, args.template), True)
        elif args.plugin_command == "validate":
            _print_payload(_validate_plugin(Path(args.path)), args.json)
        elif args.plugin_command == "test":
            payload = _test_plugin(Path(args.path), Path(args.sample), args.expected_type)
            _print_payload(payload, args.json)
            return 0 if payload["matched"] and not payload["load_errors"] else 1
        return 0
    else:
        parser.error(f"unknown command: {args.command}")
        return 2

    payload = report.to_dict()
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(json.dumps(payload["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
