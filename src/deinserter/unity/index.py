from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .serialized import UnityExternal, UnityObject, UnityReference, UnitySerializedInfo, inspect_serialized_file


UNITY_SERIALIZED_SUFFIXES = {".assets", ".sharedassets"}


def _norm(path: str | Path) -> str:
    try:
        return str(Path(path).resolve())
    except OSError:
        return str(Path(path).absolute())


def _key(path: str | Path) -> str:
    return _norm(path).lower()


@dataclass(slots=True)
class UnityIndexedObject:
    source_file: str
    path_id: int
    class_id: int
    type_id: int
    type_name: str
    offset: int
    size: int

    @classmethod
    def from_object(cls, obj: UnityObject) -> "UnityIndexedObject":
        return cls(
            source_file=_norm(obj.source_path),
            path_id=obj.path_id,
            class_id=obj.class_id,
            type_id=obj.type_id,
            type_name=obj.type_name,
            offset=obj.offset,
            size=obj.size,
        )


@dataclass(slots=True)
class ResolvedUnityReference:
    target_file: str = ""
    target_path_id: int | None = None
    resolved: bool = False
    resolution_status: str = "unresolved"
    target_type_name: str = ""
    target_class_id: int | None = None

    def apply_to(self, reference: UnityReference) -> UnityReference:
        reference.target_file = self.target_file
        reference.target_path_id = self.target_path_id
        reference.resolved = self.resolved
        reference.resolution_status = self.resolution_status
        reference.target_type_name = self.target_type_name
        reference.target_class_id = self.target_class_id
        return reference


@dataclass(slots=True)
class UnityProjectIndex:
    infos_by_path: dict[str, UnitySerializedInfo] = field(default_factory=dict)
    objects_by_file: dict[str, dict[int, UnityIndexedObject]] = field(default_factory=dict)
    externals_by_file: dict[str, dict[int, UnityExternal]] = field(default_factory=dict)
    candidates_by_name: dict[str, list[str]] = field(default_factory=dict)
    parse_errors: dict[str, str] = field(default_factory=dict)

    @property
    def indexed_files_total(self) -> int:
        return len(self.infos_by_path)

    @property
    def indexed_objects_total(self) -> int:
        return sum(len(items) for items in self.objects_by_file.values())

    def should_index_path(self, path: Path) -> bool:
        suffix = path.suffix.lower()
        return suffix in UNITY_SERIALIZED_SUFFIXES or path.name.lower().endswith(".assets")

    def add_info(self, path: Path, info: UnitySerializedInfo) -> None:
        normalized = _key(path)
        if not info.status.startswith("parsed"):
            self.parse_errors[normalized] = info.error or info.status
            return
        self.infos_by_path[normalized] = info
        self.objects_by_file[normalized] = {
            obj.path_id: UnityIndexedObject.from_object(obj)
            for obj in info.objects
        }
        self.externals_by_file[normalized] = {external.file_id: external for external in info.externals}
        self.candidates_by_name.setdefault(path.name.lower(), []).append(normalized)

    def ensure_file(self, path: Path) -> UnitySerializedInfo:
        normalized = _key(path)
        if normalized not in self.infos_by_path and normalized not in self.parse_errors:
            self.add_info(path, inspect_serialized_file(path))
        info = self.infos_by_path.get(normalized)
        if info is not None:
            return info
        return inspect_serialized_file(path)

    def build(self, paths: list[Path]) -> None:
        for path in paths:
            if self.should_index_path(path):
                try:
                    self.add_info(path, inspect_serialized_file(path))
                except OSError as exc:
                    self.parse_errors[_key(path)] = str(exc)

    def _object_result(self, file_key: str, path_id: int, status: str) -> ResolvedUnityReference:
        target = self.objects_by_file.get(file_key, {}).get(path_id)
        if target is None:
            return ResolvedUnityReference(
                target_file=_norm(file_key),
                target_path_id=path_id,
                resolution_status="missing_target_path_id",
            )
        return ResolvedUnityReference(
            target_file=target.source_file,
            target_path_id=target.path_id,
            resolved=True,
            resolution_status=status,
            target_type_name=target.type_name,
            target_class_id=target.class_id,
        )

    def _external_candidates(self, source_file: Path, path_name: str) -> tuple[str, list[str]]:
        if not path_name:
            return "", []
        declared = source_file.parent / path_name
        declared_key = _key(declared)
        if declared_key in self.infos_by_path:
            return declared_key, [declared_key]
        basename_matches = list(self.candidates_by_name.get(Path(path_name).name.lower(), []))
        normalized_tail = Path(path_name).as_posix().lower()
        tail_matches = [
            candidate
            for candidate in self.infos_by_path
            if Path(candidate).as_posix().lower().endswith(normalized_tail)
        ]
        candidates = sorted(set(basename_matches + tail_matches))
        if declared.exists() and not candidates:
            return declared_key, []
        return declared_key, candidates

    def resolve_reference(self, reference: UnityReference) -> ResolvedUnityReference:
        source_key = _key(reference.source_file)
        if reference.file_id == 0:
            if source_key not in self.infos_by_path:
                return ResolvedUnityReference(
                    target_file=_norm(reference.source_file),
                    target_path_id=reference.path_id,
                    resolution_status="unindexed_external_file",
                )
            return self._object_result(source_key, reference.path_id, "resolved_internal")

        external = self.externals_by_file.get(source_key, {}).get(reference.file_id)
        if external is None:
            return ResolvedUnityReference(resolution_status="unresolved")

        declared_key, candidates = self._external_candidates(Path(reference.source_file), external.path_name)
        if not candidates:
            if declared_key in self.parse_errors:
                return ResolvedUnityReference(
                    target_file=_norm(declared_key),
                    target_path_id=reference.path_id,
                    resolution_status="unindexed_external_file",
                )
            return ResolvedUnityReference(
                target_file=_norm(declared_key) if declared_key else "",
                target_path_id=reference.path_id,
                resolution_status="missing_external_file",
            )
        if len(candidates) > 1:
            return ResolvedUnityReference(
                target_file="",
                target_path_id=reference.path_id,
                resolution_status="ambiguous_external_file",
            )
        return self._object_result(candidates[0], reference.path_id, "resolved_external")

    def resolve_object_references(self, obj: UnityObject) -> None:
        for reference in obj.pptr_references:
            self.resolve_reference(reference).apply_to(reference)
