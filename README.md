# Deinserter

Deinserter is a local Python library and CLI for safe asset triage, extraction,
and reconstruction from game-related files.

It is intentionally conservative: it detects known formats, extracts only when
boundaries can be verified, reports embedded candidates, and does not attempt to
bypass encryption, DRM, or proprietary bytecode protections.

## Capability System

Deinserter is built around a versioned capability registry. A capability can be a
format descriptor, detector, streaming detector, container handler, path/source
parser, converter, reconstructor, or run hook. Capabilities have stable IDs,
priorities, source metadata, explicit replacement rules, and isolated runtime
errors. This lets the project grow without turning every new extension into a
core-code change.

Support can be added in layers:

- `descriptor`: extension, category, role, value, and text/binary expectation.
- `detector`: signature or validation logic, including embedded asset scanning.
- `container`: index parsing and safe entry extraction.
- `parser`: metadata extraction for a known format.
- `converter/reconstructor`: richer conversion into a more useful output.
- `run hook`: optional project-wide preparation such as building a reference index.

Container entries are exposed as bounded `ArtifactSource` objects and pass through
the same detection, parsing, conversion, reconstruction, and nested-container
pipeline without requiring a permanent extraction first. Depth, entry count,
candidate count, memory, file-size, cooperative time, and output-byte limits apply
to this work.

Unknown files do not block a run. They are inventoried with extension, magic,
size, entropy/string hints, and conservative classification so they can become
the next format pack or plugin.

## Format Packs

Simple extension support lives in TOML. Built-in formats are defined in
[src/deinserter/builtin_formats.toml](src/deinserter/builtin_formats.toml).

Example:

```toml
[[formats]]
type_name = "dialogue"
extensions = [".dialogue"]
category = "data"
role = "game_dialogue_text"
decompile_value = "high"
text = true
```

Use a local pack directly:

```powershell
deinserter scan game-folder --format-pack ./my-pack/formats.toml --json
deinserter decompile game-folder --out out --mode selective --format-pack ./my-pack
```

Use entry point plugins for installed third-party packs:

```toml
[project.entry-points."deinserter.plugins"]
my_pack = "deinserter_plugin:register"
```

Plugins should declare the supported contract version. They can register source
parsers, streaming signatures, converters, reconstructors, and run hooks in the
same `register(registry)` function:

```python
from deinserter import CAPABILITY_API_VERSION

DEINSERTER_API_VERSION = CAPABILITY_API_VERSION

def register(registry):
    registry.add_source_parser(
        parse_dialogue,
        capability_id="my_pack:parser:dialogue",
        extensions={".dialogue"},
        priority=100,
    )
    registry.add_converter(
        convert_dialogue,
        capability_id="my_pack:converter:dialogue",
        extensions={".dialogue"},
        priority=100,
    )
```

## Python API

```python
from deinserter import ExtractionOptions, ScanOptions, build_capability_registry
from deinserter import plan_path, decompile_path, scan_path, extract_path, read_manifest

scan = scan_path("fixtures")
print(scan.to_dict())

plan = plan_path("game-folder", "out/plan")
print(plan.summary)

report = decompile_path(
    "game-folder",
    "out/decompiled",
    ExtractionOptions(mode="selective", format_pack_paths=["./my-pack"]),
)
print(report.to_dict())

registry = build_capability_registry(["./my-pack"])
print(registry.format_by_extension[".dialogue"])

reader = read_manifest("out/decompiled")
for item in reader.iter_extracted(category="data"):
    print(item["output_path"])
```

## CLI

```powershell
deinserter plan . --out plan --json
deinserter decompile . --out extracted --mode selective --json
deinserter scan . --json
deinserter extract . --out extracted --json
deinserter probe sample.asset --explain --json
deinserter formats list --json
deinserter formats unknown game-folder --json
deinserter plugin init ./deinserter-my-game
deinserter plugin init ./deinserter-my-game --template full
deinserter plugin validate ./deinserter-my-game --json
deinserter plugin test ./deinserter-my-game ./sample.dialogue --expected-type example_dialogue --json
```

The streaming-first commands write `deinserter-summary.json` plus JSONL files
for files, candidates, extracted assets, skipped items, failures, capability
events, objects, reconstructed Unity records, semantic conversions, and container
entries. Manifest paths are absolute so readers remain valid when the caller
changes its working directory.

Writes use same-file protection, destination-root containment, temporary files,
and atomic replacement. `--overwrite` never permits an input file or archive to
replace itself. `--max-output-bytes` covers extracted payloads, semantic outputs,
Unity sidecars, and reconstructed artifacts (manifest files are excluded).

`decompile_path` and the `decompile` CLI command are the canonical APIs for
containers and large projects. `extract_path` and the `extract` CLI command
remain for legacy small-file workflows; for containers, their in-memory report
may contain only a bounded sample, so use `extracted.jsonl` for complete output.

## Built-In Coverage

Built-in descriptors cover common engine, asset, script, data, container,
shader, localization, font, runtime, and bytecode files. Signature validators
exist for formats such as PNG, GLB, WAV, OGG, ZIP, JPEG, DDS, TGA, FSB5, MO,
SFNT fonts, WASM, ELF, PE, PDB, Wwise banks, FBX, Unreal packages, RPF, and KTX.

Built-in container handlers include GPAK, ZIP, Quake PAK, VPK, open RPF,
unencrypted Unreal PAK, and unencrypted UTOC/UCAS IoStore ranges.

For contribution details, see [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).
For the processing and plugin contracts, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
For the long-term roadmap, see [docs/EXPANSION_PLAN.md](docs/EXPANSION_PLAN.md).
