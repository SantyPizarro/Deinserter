from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import ManifestPaths


MANIFEST_KEYS = {
    "files",
    "candidates",
    "extracted",
    "skipped",
    "objects",
    "reconstructed",
    "assembly_types",
    "semantic_conversions",
    "unity_references",
    "unity_external_resources",
    "unreal_entries",
    "container_entries",
}


class JsonlManifestWriter:
    def __init__(self, output_dir: str | Path | None):
        self.output_dir = Path(output_dir) if output_dir is not None else None
        self.paths = ManifestPaths()
        self._handles: dict[str, Any] = {}
        if self.output_dir is not None:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            self.paths = ManifestPaths(
                summary=str(self.output_dir / "deinserter-summary.json"),
                files=str(self.output_dir / "files.jsonl"),
                candidates=str(self.output_dir / "candidates.jsonl"),
                extracted=str(self.output_dir / "extracted.jsonl"),
                skipped=str(self.output_dir / "skipped.jsonl"),
                objects=str(self.output_dir / "objects.jsonl"),
                reconstructed=str(self.output_dir / "reconstructed.jsonl"),
                assembly_types=str(self.output_dir / "assembly-types.jsonl"),
                semantic_conversions=str(self.output_dir / "semantic-conversions.jsonl"),
                unity_references=str(self.output_dir / "unity-references.jsonl"),
                unity_external_resources=str(self.output_dir / "unity-external-resources.jsonl"),
                unreal_entries=str(self.output_dir / "unreal-entries.jsonl"),
                container_entries=str(self.output_dir / "container-entries.jsonl"),
            )
            for key in (
                "files",
                "candidates",
                "extracted",
                "skipped",
                "objects",
                "reconstructed",
                "assembly_types",
                "semantic_conversions",
                "unity_references",
                "unity_external_resources",
                "unreal_entries",
                "container_entries",
            ):
                Path(getattr(self.paths, key)).write_text("", encoding="utf-8")

    def _write_jsonl(self, key: str, item: dict[str, Any]) -> None:
        if self.output_dir is None:
            return
        handle = self._handles.get(key)
        if handle is None:
            path = getattr(self.paths, key)
            handle = Path(path).open("w", encoding="utf-8")
            self._handles[key] = handle
        handle.write(json.dumps(item, ensure_ascii=False) + "\n")

    def file(self, item: dict[str, Any]) -> None:
        self._write_jsonl("files", item)

    def candidate(self, item: dict[str, Any]) -> None:
        self._write_jsonl("candidates", item)

    def extracted(self, item: dict[str, Any]) -> None:
        self._write_jsonl("extracted", item)

    def skipped(self, item: dict[str, Any]) -> None:
        self._write_jsonl("skipped", item)

    def object(self, item: dict[str, Any]) -> None:
        self._write_jsonl("objects", item)

    def reconstructed(self, item: dict[str, Any]) -> None:
        self._write_jsonl("reconstructed", item)

    def assembly_type(self, item: dict[str, Any]) -> None:
        self._write_jsonl("assembly_types", item)

    def semantic_conversion(self, item: dict[str, Any]) -> None:
        self._write_jsonl("semantic_conversions", item)

    def unity_reference(self, item: dict[str, Any]) -> None:
        self._write_jsonl("unity_references", item)

    def unity_external_resource(self, item: dict[str, Any]) -> None:
        self._write_jsonl("unity_external_resources", item)

    def unreal_entry(self, item: dict[str, Any]) -> None:
        self._write_jsonl("unreal_entries", item)

    def container_entry(self, item: dict[str, Any]) -> None:
        self._write_jsonl("container_entries", item)

    def summary(self, item: dict[str, Any]) -> None:
        if self.output_dir is None:
            return
        Path(self.paths.summary).write_text(json.dumps(item, indent=2, ensure_ascii=False), encoding="utf-8")

    def close(self) -> None:
        for handle in self._handles.values():
            handle.close()
        self._handles.clear()

    def __enter__(self) -> "JsonlManifestWriter":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()


class ManifestReader:
    def __init__(self, path: str | Path):
        source = Path(path)
        if source.is_dir():
            self.output_dir = source
            self.summary_path = source / "deinserter-summary.json"
            self.legacy_manifest_path = source / "deinserter-manifest.json"
        else:
            self.output_dir = source.parent
            self.summary_path = source
            self.legacy_manifest_path = source if source.name == "deinserter-manifest.json" else source.parent / "deinserter-manifest.json"

    def load_summary(self) -> dict[str, Any]:
        if self.summary_path.exists():
            return json.loads(self.summary_path.read_text(encoding="utf-8"))
        if self.legacy_manifest_path.exists():
            return json.loads(self.legacy_manifest_path.read_text(encoding="utf-8"))
        raise FileNotFoundError(self.summary_path)

    def path_for(self, key: str) -> Path:
        if key not in MANIFEST_KEYS:
            raise KeyError(f"unknown manifest stream: {key}")
        summary = self.load_summary()
        manifest_paths = summary.get("manifest_paths", {})
        declared = manifest_paths.get(key)
        if declared:
            return Path(declared)
        filename = key.replace("_", "-") + ".jsonl"
        if key == "assembly_types":
            filename = "assembly-types.jsonl"
        elif key == "semantic_conversions":
            filename = "semantic-conversions.jsonl"
        elif key == "unity_references":
            filename = "unity-references.jsonl"
        elif key == "unity_external_resources":
            filename = "unity-external-resources.jsonl"
        elif key == "unreal_entries":
            filename = "unreal-entries.jsonl"
        elif key == "container_entries":
            filename = "container-entries.jsonl"
        return self.output_dir / filename

    def iter_records(
        self,
        key: str,
        *,
        category: str | None = None,
        type: str | None = None,
        status: str | None = None,
        decompile_value: str | None = None,
        **fields: object,
    ):
        path = self.path_for(key)
        if not path.exists():
            return
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                item = json.loads(line)
                if self._matches(item, category, type, status, decompile_value, fields):
                    yield item

    def _matches(
        self,
        item: dict[str, Any],
        category: str | None,
        type_name: str | None,
        status: str | None,
        decompile_value: str | None,
        fields: dict[str, object],
    ) -> bool:
        if category is not None and item.get("category") != category:
            return False
        if decompile_value is not None and item.get("decompile_value") != decompile_value:
            return False
        if type_name is not None:
            values = {
                item.get("type"),
                item.get("identified_type"),
                item.get("detected_type"),
                item.get("type_name"),
                item.get("semantic_type"),
            }
            if type_name not in values:
                return False
        if status is not None:
            values = {
                item.get("status"),
                item.get("validation_status"),
                item.get("reconstruction_status"),
                item.get("semantic_status"),
                item.get("decode_status"),
                item.get("resolution_status"),
            }
            if status not in values:
                return False
        return all(item.get(key) == value for key, value in fields.items())

    def iter_files(self, **filters: object):
        yield from self.iter_records("files", **filters)

    def iter_candidates(self, **filters: object):
        yield from self.iter_records("candidates", **filters)

    def iter_extracted(self, **filters: object):
        yield from self.iter_records("extracted", **filters)

    def iter_skipped(self, **filters: object):
        yield from self.iter_records("skipped", **filters)

    def iter_objects(self, **filters: object):
        yield from self.iter_records("objects", **filters)

    def iter_reconstructions(self, **filters: object):
        yield from self.iter_records("reconstructed", **filters)

    def iter_assembly_types(self, **filters: object):
        yield from self.iter_records("assembly_types", **filters)

    def iter_semantic_conversions(self, **filters: object):
        yield from self.iter_records("semantic_conversions", **filters)

    def iter_unity_references(self, **filters: object):
        yield from self.iter_records("unity_references", **filters)

    def iter_unity_external_resources(self, **filters: object):
        yield from self.iter_records("unity_external_resources", **filters)

    def iter_unreal_entries(self, **filters: object):
        yield from self.iter_records("unreal_entries", **filters)

    def iter_container_entries(self, **filters: object):
        yield from self.iter_records("container_entries", **filters)


def read_manifest(path: str | Path) -> ManifestReader:
    return ManifestReader(path)


def load_manifest_summary(path: str | Path) -> dict[str, Any]:
    return ManifestReader(path).load_summary()


def iter_manifest_records(path: str | Path, key: str, **filters: object):
    yield from ManifestReader(path).iter_records(key, **filters)
