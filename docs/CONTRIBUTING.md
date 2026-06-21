# Contributing Capabilities

Deinserter grows by adding capabilities. Start with the smallest useful layer
and only add code when a descriptor is not enough.

## 1. Add a Descriptor

Use a format pack when support is extension-based:

```toml
[[formats]]
type_name = "dialogue"
extensions = [".dialogue"]
category = "data"
role = "game_dialogue_text"
decompile_value = "high"
text = true
```

Validate it:

```powershell
deinserter plugin validate ./my-pack --json
deinserter probe ./sample.dialogue --format-pack ./my-pack --json
```

Descriptors should use stable, lowercase `type_name` values. Prefer specific
roles like `quest_definition_text` over generic roles like `data_file`.

## 2. Add a Detector

Add a detector when an extension alone is too weak or when embedded extraction
needs trustworthy byte ranges.

A detector should provide:

- `identify(data, path)` for magic/signature identification.
- `validate(data)` when full-file validation is possible.
- `extract_length(data, offset)` when embedded candidates can be bounded.
- `find_embedded(data, source_file)` for in-memory scans.

Register it from a plugin:

```python
def register(registry):
    registry.add_detector(MyDetector())
```

## 3. Add a Container Handler

Add a container handler when the file has an index or directory that can list
entries safely.

A handler should implement:

- `sniff(path)` without expensive full extraction.
- `open(path)` returning container info and entries.
- `extract_entry(path, entry, output_dir, overwrite, chunk_size, hash_output)`.

Keep encrypted or compressed formats conservative. Report unsupported states
instead of guessing ranges.

## 4. Add a Parser

Parsers describe metadata without promising reconstruction. Register a parser
when a format can expose useful counts, dimensions, headers, streams, or schema
clues.

```python
def register(registry):
    registry.add_parser(
        parse_dialogue,
        name="dialogue",
        type_names={"dialogue"},
        extensions={".dialogue"},
    )
```

## 5. Add a Converter or Reconstructor

Converters should be deterministic and explicit about limits. If a result is
heuristic, call it pseudocode or metadata rather than source.

## Testing Expectations

Use tiny synthetic fixtures whenever possible. A good contribution proves:

- the file is identified correctly;
- classification category/value are correct;
- parse info is useful and stable;
- extraction either succeeds with verified bounds or is skipped with a reason;
- unknown files continue to be reported rather than failing the run.

Run:

```powershell
python -m unittest
```

## Safety Rules

Do not add key discovery, DRM bypasses, or speculative decryptors. Deinserter can
use user-provided keys for formats that explicitly support them in the future,
but it should not attempt to recover secrets.
