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
    registry.add_detector(
        MyDetector(),
        capability_id="my_pack:detector:dialogue",
        priority=100,
    )
```

For embedded scanning above `max_in_memory_bytes`, register a streaming signature
whose length reader works against a bounded `ArtifactSource`:

```python
registry.add_streaming_detector(
    type_name="dialogue",
    signatures=(b"DLG0",),
    length_reader=dialogue_length,
    extension=".dialogue",
    capability_id="my_pack:streaming:dialogue",
    priority=100,
)
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
    registry.add_source_parser(
        parse_dialogue,
        name="dialogue",
        capability_id="my_pack:parser:dialogue",
        type_names={"dialogue"},
        extensions={".dialogue"},
        priority=100,
    )
```

Source parsers work for files, bounded ranges, compressed entries, and nested
containers. Existing path parsers remain supported with `add_parser`. Mark a path
parser `stream_safe=True` only when its implementation performs bounded/range
reads; otherwise it is skipped above `max_in_memory_bytes`.

## 5. Add a Converter or Reconstructor

Converters should be deterministic and explicit about limits. If a result is
heuristic, call it pseudocode or metadata rather than source.

Register converters and reconstructors instead of editing the main pipeline.
They receive a `CapabilityContext` containing the logical path, bounded source,
options, registry, and budget helpers. Use `context.can_write(size)` before an
output and `context.emit("output", {"output_length": size})` after committing it.

Use run hooks only for bounded project-wide preparation such as reference indexes.
Hooks receive a repeatable `discover()` iterator and shared run services.

## Plugin Contract

Declare `DEINSERTER_API_VERSION = CAPABILITY_API_VERSION`. IDs must be stable and
namespaced. Higher priorities run first; duplicate IDs require explicit
`replace=True`. Registration is transactional and runtime exceptions are isolated
to the capability that raised them.

```powershell
deinserter plugin init ./my-pack --template full
deinserter plugin validate ./my-pack --json
deinserter plugin test ./my-pack ./sample.dialogue --expected-type dialogue --json
```

## Testing Expectations

Use tiny synthetic fixtures whenever possible. A good contribution proves:

- the file is identified correctly;
- classification category/value are correct;
- parse info is useful and stable;
- extraction either succeeds with verified bounds or is skipped with a reason;
- unknown files continue to be reported rather than failing the run.
- source and streaming paths behave consistently across the memory threshold;
- nested containers obey depth, entry, candidate, file-size, cooperative time, and output limits;
- malicious archive paths cannot leave the output root;
- plugin exceptions do not stop unrelated files or capabilities.

Run:

```powershell
python -m unittest
```

## Safety Rules

Do not add key discovery, DRM bypasses, or speculative decryptors. Deinserter can
use user-provided keys for formats that explicitly support them in the future,
but it should not attempt to recover secrets.

Every destination must resolve beneath its assigned output root. Use the atomic
resource helpers instead of truncating output files directly, and reject aliases
between an input and destination. A keyring is delivered only to handlers that
implement `configure(options)`; otherwise the run reports it as unused.
