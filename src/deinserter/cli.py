from __future__ import annotations

import argparse
import json
from pathlib import Path

from .formats import load_format_specs
from .models import ExtractionOptions, ScanOptions
from .pipeline import decompile_path, extract_path, plan_path, probe_file, scan_path
from .registry import build_capability_registry


def _add_scan_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("input", help="File or directory to scan.")
    parser.add_argument("--no-recursive", action="store_true", help="Only scan direct children.")
    parser.add_argument("--no-sort-paths", action="store_true", help="Process discovered files in filesystem order.")
    parser.add_argument("--max-file-size-mb", type=int, default=None, help="Skip probing files above this size.")
    parser.add_argument("--string-min-length", type=int, default=6, help="Minimum length for strings preview.")
    parser.add_argument("--entropy-block-size", type=int, default=4096, help="Reserved for streaming entropy tuning.")
    parser.add_argument("--no-embedded-scan", action="store_true", help="Disable embedded asset candidate scanning.")
    parser.add_argument("--max-in-memory-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--stream-chunk-size", type=int, default=8 * 1024 * 1024)
    parser.add_argument("--hash-policy", choices=["extracted", "always", "never"], default="extracted")
    parser.add_argument("--max-output-bytes", type=int, default=None)
    parser.add_argument("--include-categories", default=None, help="Comma-separated categories to include.")
    parser.add_argument("--exclude-categories", default=None, help="Comma-separated categories to exclude.")
    parser.add_argument("--unity-external-resource-roots", default=None, help="Comma-separated roots for Unity .resS/.resource lookup.")
    parser.add_argument("--unity-decode-media", action="store_true", help="Enable optional Unity media decoders when installed.")
    parser.add_argument("--no-container-deep-scan", action="store_true", help="Disable deep handlers for versioned containers.")
    parser.add_argument("--container-keyring-path", default=None, help="Path to user-provided container keys; no key discovery is attempted.")
    parser.add_argument("--format-pack", action="append", default=None, help="Path to a formats.toml file or directory containing one.")
    parser.add_argument("--json", action="store_true", help="Print JSON output.")


def _add_format_pack_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format-pack", action="append", default=None, help="Path to a formats.toml file or directory containing one.")
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
    plugin_validate_parser = plugin_subparsers.add_parser("validate", help="Validate a formats.toml file or plugin directory.")
    plugin_validate_parser.add_argument("path", help="Path to a formats.toml file or directory containing one.")
    plugin_validate_parser.add_argument("--json", action="store_true", help="Print JSON output.")
    return parser


def _formats_payload(format_pack_paths: list[str] | None) -> dict[str, object]:
    registry = build_capability_registry(format_pack_paths)
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
        "containers": [getattr(handler, "type_name", "unknown") for handler in registry.container_handlers],
        "parsers": [parser.name for parser in registry.parsers],
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


def _init_plugin(path: Path, name: str | None = None) -> dict[str, object]:
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
        path / "deinserter_plugin.py": '''"""Example Deinserter plugin.

The local formats.toml can be used directly with --format-pack.
Install this package when you want entry-point auto-loading.
"""

from pathlib import Path

from deinserter.formats import load_format_specs


def register(registry):
    registry.add_formats(load_format_specs(Path(__file__).with_name("formats.toml")))
''',
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
        file_path.write_text(content, encoding="utf-8")
        created.append(str(file_path))
    return {"path": str(path), "plugin_name": plugin_name, "created": created, "skipped_existing": skipped}


def _validate_plugin(path: Path) -> dict[str, object]:
    format_file = path / "formats.toml" if path.is_dir() else path
    specs = load_format_specs(format_file)
    registry = build_capability_registry([format_file], load_plugins=False)
    return {
        "path": str(format_file),
        "valid": not registry.load_errors,
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
        payload = probe_file(Path(args.input), ScanOptions(format_pack_paths=args.format_pack)).to_dict()
        if args.explain:
            payload = {"probe": payload, "registry": _formats_payload(args.format_pack)}
        _print_payload(payload, args.json)
        return 0
    elif args.command == "formats":
        if args.formats_command == "list":
            _print_payload(_formats_payload(args.format_pack), args.json)
        elif args.formats_command == "unknown":
            _print_payload(_unknown_formats_payload(args), args.json)
        return 0
    elif args.command == "plugin":
        if args.plugin_command == "init":
            _print_payload(_init_plugin(Path(args.path), args.name), True)
        elif args.plugin_command == "validate":
            _print_payload(_validate_plugin(Path(args.path)), args.json)
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
