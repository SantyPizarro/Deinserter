# Deinserter

Deinserter is a local Python library and CLI for safe asset triage, extraction,
and reconstruction from game-related files.

It is intentionally conservative: it detects known formats, extracts only when
boundaries can be verified, reports embedded candidates, and does not attempt to
bypass encryption, DRM, or proprietary bytecode protections.

## Capability System

Deinserter is built around a capability registry. A capability can be a format
descriptor, detector, container handler, parser, semantic converter, or
reconstruction path. This lets the project grow constantly without turning every
new extension into a core-code change.

Support can be added in layers:

- `descriptor`: extension, category, role, value, and text/binary expectation.
- `detector`: signature or validation logic, including embedded asset scanning.
- `container`: index parsing and safe entry extraction.
- `parser`: metadata extraction for a known format.
- `converter/reconstructor`: richer conversion into a more useful output.

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
deinserter plugin validate ./deinserter-my-game --json
```

The streaming-first commands write `deinserter-summary.json` plus JSONL files
for files, candidates, extracted assets, skipped items, objects, reconstructed
Unity records, semantic conversions, and container entries.

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
For the long-term roadmap, see [docs/EXPANSION_PLAN.md](docs/EXPANSION_PLAN.md).
