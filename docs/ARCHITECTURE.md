# Deinserter Architecture

## Processing Model

Every input is represented by an `ArtifactSource`: a named, seekable, bounded
view over a file, byte range, or compressed container entry. The canonical flow
is:

1. discover physical files lazily;
2. run prioritized container sniffers or file detectors;
3. scan embedded signatures through registered streaming detectors;
4. parse through a source parser, bounded temporary path adapter, or descriptor;
5. execute all matching converters and reconstructors in priority order;
6. extract requested outputs through atomic, same-file-safe writers;
7. feed container entries back into the same flow until a configured limit stops it;
8. emit complete JSONL event/failure streams and a bounded in-memory report sample.

Run hooks provide optional project-wide preparation. Unity uses one to build its
cross-file reference index; the core run loop has no Unity-specific preparation
branch.

## Capability Contract

The registry API version is `CAPABILITY_API_VERSION`. Installed plugins declare
the same value as `DEINSERTER_API_VERSION` and expose `register(registry)` through
the `deinserter.plugins` entry-point group.

| Capability | Registration | Input |
| --- | --- | --- |
| Descriptor | `add_format` | extension metadata |
| Detector | `add_detector` | bounded in-memory bytes |
| Streaming detector | `add_streaming_detector` | `ArtifactSource`, offset, signature |
| Container | `add_container_handler` | physical/materialized path |
| Path parser | `add_parser` | path; large inputs require `stream_safe=True` |
| Source parser | `add_source_parser` | any `ArtifactSource` |
| Converter | `add_converter` | `CapabilityContext` |
| Reconstructor | `add_reconstructor` | `CapabilityContext` |
| Run hook | `add_run_hook` | `RunContext` with repeatable discovery |

Every code capability has an ID, source, priority, and registration sequence.
Higher priority runs first. Duplicate IDs fail unless `replace=True`; plugin
registration is transactional, so partial registrations are rolled back.
Plugins load after built-ins, allowing an explicit replacement of a built-in
capability. Extension detectors are generated from the final descriptor set.

## Limits and Budgets

`ScanOptions` validates all resource settings. The decompilation pipeline enforces:

- maximum physical file size before container or Unity parsing;
- maximum in-memory/materialized artifact size;
- maximum recursive container depth and total entry count;
- maximum embedded candidates per artifact;
- cooperative processing deadline at file, entry, candidate, hook, and processor boundaries;
- maximum Unity object size;
- one global output-byte budget covering payloads, semantic conversions,
  reconstructed files, and Unity sidecars.

Manifest files and bounded temporary materializations are intentionally excluded
from the output budget. Plugins must call `context.can_write(size)` before writing
and emit an `output` event with `output_length` after committing an output.

## Safety Invariants

- An input and output may never resolve to the same file.
- Archive paths may not be absolute, UNC, parent-traversing, drive-qualified, or
  Windows-reserved.
- A resolved archive destination must remain beneath its assigned output root.
- Built-in writes use a sibling temporary file, flush it, and atomically replace
  the destination only after successful completion.
- Malformed files and third-party capability exceptions are isolated and written
  to `failures.jsonl`; they do not stop unrelated files.
- Keys are never discovered. A provided keyring is delivered only to container
  handlers that explicitly accept it through `configure(options)`.

## Manifest Streams

The summary declares absolute paths for files, candidates, extracted outputs,
skipped work, failures, generic capability events, container entries, semantic
conversions, Unity objects/references/resources, reconstructions, and assembly
types. Report objects retain only bounded samples; JSONL streams are authoritative.
