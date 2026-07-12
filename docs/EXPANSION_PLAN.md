# Expansion Plan

This plan keeps Deinserter ready for constant extension growth from the core
project, local experiments, and external forks.

## Implemented Foundation

- Versioned, prioritized, transactional capability registration with explicit IDs,
  conflict reporting, plugin disablement, and per-capability runtime isolation.
- Plugin-capable descriptors, detectors, streaming detectors, container handlers,
  path/source parsers, converters, reconstructors, and run hooks.
- Bounded `ArtifactSource` processing for archive entries and recursive containers,
  with depth, entry, candidate, memory, file-size, and output-byte limits.
- Atomic same-file-safe writes, output-root containment, complete failure JSONL,
  generic capability events, and portable absolute manifest paths.
- Descriptor/detector/parser/converter/container/full scaffolds plus local plugin
  validation and sample-based plugin tests.

The phases below now describe ongoing ecosystem expansion rather than missing core
architecture.

## Phase 1: Stable Registry Contract (implemented)

- Keep `CapabilityRegistry` as the central integration point.
- Preserve the public wrappers: `probe_file`, `scan_path`, `plan_path`,
  `decompile_path`, `extract_path`, `parse_file`, and `classify_asset`.
- Treat `builtin_formats.toml` as the canonical descriptor example.

## Phase 2: Better Unknown Reports

- Extend `formats unknown` with grouped magic signatures and sample paths.
- Emit suggested descriptor stubs for repeated unknown extensions.
- Add optional JSONL output for unknown-only inventories.

## Phase 3: Format Pack Ecosystem

- Create focused packs such as `deinserter-renpy`, `deinserter-rpgmaker`,
  `deinserter-godot-extra`, and `deinserter-unity-extra`.
- Encourage packs to begin descriptor-only and add code only when signatures,
  containers, or parsers are justified.
- Keep packs installable through Python entry points and usable directly with
  `--format-pack`.

## Phase 4: Container Backends (foundation implemented)

- Split complex engine/container handlers into optional packages when they need
  dependencies or version-specific logic.
- Add explicit status values for encrypted, compressed, versioned, and partially
  supported containers.
- Keep range validation mandatory before extraction.

## Phase 5: Parser and Semantic Layers (plugin foundation implemented)

- Move simple parser registrations into plugin-friendly modules.
- Add parser diagnostics to `deinserter probe`.
- Expand deterministic converters first: localization, GLB chunks, structured
  text, metadata sidecars, and Unity object reconstruction.

## Phase 6: Contributor Tooling (initial implementation complete)

- Improve `deinserter plugin init` with templates for descriptor-only,
  detector, container, and parser plugins.
- Add `deinserter plugin test` for a sample file plus expected identification.
- Add CI examples for third-party packs.

## Success Criteria

New game-specific extensions should usually require only a `formats.toml` entry.
New binary formats should be isolated to a detector/parser/container class and a
small test fixture. The core pipeline should not need edits unless a new kind of
capability is introduced.
