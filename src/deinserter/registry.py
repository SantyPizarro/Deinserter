from __future__ import annotations

import sys
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from .formats import FormatSpec, SUPPORTED_FORMATS, load_format_specs
from .resources import ArtifactSource

ParserFunction = Callable[[Path], dict[str, Any]]
SourceParserFunction = Callable[[ArtifactSource, Path], dict[str, Any]]
ParserPredicate = Callable[[Path, str, str], bool]
ProcessorFunction = Callable[["CapabilityContext"], dict[str, Any] | list[dict[str, Any]] | None]
RunHookFunction = Callable[["RunContext"], None]
StreamingLengthReader = Callable[[ArtifactSource, int, bytes], int | tuple[int | None, str] | None]

ENTRY_POINT_GROUP = "deinserter.plugins"
CAPABILITY_API_VERSION = 1
SUPPORTED_PLUGIN_API_VERSIONS = frozenset({CAPABILITY_API_VERSION})


@dataclass(slots=True)
class CapabilityContext:
    root: Path
    logical_path: Path
    source: ArtifactSource
    identified_type: str
    category: str
    decompile_value: str
    parse_info: dict[str, Any]
    output_dir: Path | None
    options: Any
    registry: "CapabilityRegistry"
    depth: int = 0
    services: dict[str, Any] = field(default_factory=dict)

    def emit(self, stream: str, item: dict[str, Any]) -> None:
        emitter = self.services.get("emit")
        if callable(emitter):
            emitter(stream, item)

    def can_write(self, size: int) -> bool:
        predicate = self.services.get("can_write")
        return bool(predicate(size)) if callable(predicate) else True

    def deadline_exceeded(self) -> bool:
        predicate = self.services.get("deadline_exceeded")
        return bool(predicate()) if callable(predicate) else False


@dataclass(slots=True)
class RunContext:
    input_path: Path
    output_dir: Path | None
    options: Any
    registry: "CapabilityRegistry"
    summary: dict[str, Any]
    warnings: list[str]
    services: dict[str, Any]
    discover: Callable[[], Iterable[Path]]

    def deadline_exceeded(self) -> bool:
        predicate = self.services.get("deadline_exceeded")
        return bool(predicate()) if callable(predicate) else False


@dataclass(frozen=True, slots=True)
class CapabilityMatcher:
    type_names: frozenset[str] = frozenset()
    extensions: frozenset[str] = frozenset()
    file_names: frozenset[str] = frozenset()
    categories: frozenset[str] = frozenset()
    predicate: ParserPredicate | None = None

    def matches(self, path: Path, identified_type: str, category: str) -> bool:
        suffix = path.suffix.lower()
        file_name = path.name.lower()
        normalized_type = identified_type.lower()
        if self.predicate is not None and self.predicate(path, normalized_type, category):
            return True
        if normalized_type in self.type_names:
            return True
        if suffix in self.extensions:
            return True
        if file_name in self.file_names:
            return True
        return bool(category and category in self.categories)


@dataclass(frozen=True, slots=True)
class ParserCapability:
    parser: ParserFunction | None
    source_parser: SourceParserFunction | None
    name: str
    capability_id: str
    source: str
    priority: int
    sequence: int
    matcher: CapabilityMatcher
    stream_safe: bool = False

    def matches(self, path: Path, identified_type: str, category: str) -> bool:
        return self.matcher.matches(path, identified_type, category)

    @property
    def type_names(self) -> frozenset[str]:
        return self.matcher.type_names

    @property
    def extensions(self) -> frozenset[str]:
        return self.matcher.extensions

    @property
    def file_names(self) -> frozenset[str]:
        return self.matcher.file_names

    @property
    def categories(self) -> frozenset[str]:
        return self.matcher.categories

    @property
    def predicate(self) -> ParserPredicate | None:
        return self.matcher.predicate


@dataclass(frozen=True, slots=True)
class ProcessorCapability:
    processor: ProcessorFunction
    name: str
    capability_id: str
    source: str
    priority: int
    sequence: int
    matcher: CapabilityMatcher

    def matches(self, path: Path, identified_type: str, category: str) -> bool:
        return self.matcher.matches(path, identified_type, category)


@dataclass(frozen=True, slots=True)
class StreamingDetectorCapability:
    type_name: str
    signatures: tuple[bytes, ...]
    length_reader: StreamingLengthReader
    extension: str
    capability_id: str
    source: str
    priority: int
    sequence: int


@dataclass(frozen=True, slots=True)
class RunHookCapability:
    hook: RunHookFunction
    name: str
    capability_id: str
    source: str
    priority: int
    sequence: int


@dataclass(frozen=True, slots=True)
class RegisteredObjectCapability:
    value: object
    capability_id: str
    source: str
    priority: int
    sequence: int


class CapabilityRegistry:
    def __init__(self) -> None:
        self.api_version = CAPABILITY_API_VERSION
        self._formats: list[FormatSpec] = []
        self._formats_by_type: dict[str, FormatSpec] = {}
        self._formats_by_extension: dict[str, FormatSpec] = {}
        self._detector_records: list[RegisteredObjectCapability] = []
        self._container_records: list[RegisteredObjectCapability] = []
        self._streaming_detectors: list[StreamingDetectorCapability] = []
        self.parsers: list[ParserCapability] = []
        self.converters: list[ProcessorCapability] = []
        self.reconstructors: list[ProcessorCapability] = []
        self.run_hooks: list[RunHookCapability] = []
        self.load_errors: list[str] = []
        self.runtime_errors: list[str] = []
        self.conflicts: list[str] = []
        self.plugins: list[dict[str, Any]] = []
        self._current_source = "application"
        self._sequence = 0
        self._capability_ids: dict[str, dict[str, object]] = {
            "detector": {},
            "container": {},
            "streaming_detector": {},
            "parser": {},
            "converter": {},
            "reconstructor": {},
            "run_hook": {},
        }

    @contextmanager
    def registration_source(self, source: str) -> Iterator[None]:
        previous = self._current_source
        self._current_source = source
        try:
            yield
        finally:
            self._current_source = previous

    def _next_sequence(self) -> int:
        self._sequence += 1
        return self._sequence

    def _checkpoint(self) -> dict[str, Any]:
        return {
            "formats": self._formats[:],
            "formats_by_type": self._formats_by_type.copy(),
            "formats_by_extension": self._formats_by_extension.copy(),
            "detectors": self._detector_records[:],
            "containers": self._container_records[:],
            "streaming": self._streaming_detectors[:],
            "parsers": self.parsers[:],
            "converters": self.converters[:],
            "reconstructors": self.reconstructors[:],
            "run_hooks": self.run_hooks[:],
            "ids": {kind: values.copy() for kind, values in self._capability_ids.items()},
            "sequence": self._sequence,
        }

    def _restore(self, checkpoint: dict[str, Any]) -> None:
        self._formats = checkpoint["formats"]
        self._formats_by_type = checkpoint["formats_by_type"]
        self._formats_by_extension = checkpoint["formats_by_extension"]
        self._detector_records = checkpoint["detectors"]
        self._container_records = checkpoint["containers"]
        self._streaming_detectors = checkpoint["streaming"]
        self.parsers = checkpoint["parsers"]
        self.converters = checkpoint["converters"]
        self.reconstructors = checkpoint["reconstructors"]
        self.run_hooks = checkpoint["run_hooks"]
        self._capability_ids = checkpoint["ids"]
        self._sequence = checkpoint["sequence"]

    def _default_priority(self) -> int:
        return -100 if self._current_source == "builtin" else 0

    def _claim_id(self, kind: str, capability_id: str, value: object, replace: bool) -> object | None:
        existing = self._capability_ids[kind].get(capability_id)
        if existing is not None and not replace:
            message = f"duplicate {kind} capability id '{capability_id}' from {self._current_source}"
            self.conflicts.append(message)
            raise ValueError(message)
        self._capability_ids[kind][capability_id] = value
        return existing

    @staticmethod
    def _sort_key(item: Any) -> tuple[int, int]:
        return (-int(item.priority), int(item.sequence))

    @property
    def formats(self) -> tuple[FormatSpec, ...]:
        return tuple(self._formats)

    @property
    def format_by_type(self) -> dict[str, FormatSpec]:
        return dict(self._formats_by_type)

    @property
    def format_by_extension(self) -> dict[str, FormatSpec]:
        return dict(self._formats_by_extension)

    @property
    def text_extensions(self) -> frozenset[str]:
        return frozenset(extension for spec in self._formats if spec.text for extension in spec.extensions)

    @property
    def detectors(self) -> list[object]:
        return [record.value for record in self._detector_records]

    @property
    def detector_capabilities(self) -> tuple[RegisteredObjectCapability, ...]:
        return tuple(self._detector_records)

    @property
    def container_handlers(self) -> list[object]:
        return [record.value for record in self._container_records]

    @property
    def container_capabilities(self) -> tuple[RegisteredObjectCapability, ...]:
        return tuple(self._container_records)

    @property
    def streaming_detectors(self) -> tuple[StreamingDetectorCapability, ...]:
        return tuple(self._streaming_detectors)

    def add_format(self, spec: FormatSpec, *, replace: bool = False) -> None:
        if not spec.type_name or spec.type_name != spec.type_name.lower():
            raise ValueError("format type_name must be non-empty and lowercase")
        if not spec.extensions or any(extension != _normalize_extension(extension) for extension in spec.extensions):
            raise ValueError(f"format {spec.type_name} has invalid extensions")
        if spec.decompile_value not in {"none", "low", "medium", "high"}:
            raise ValueError(f"format {spec.type_name} has invalid decompile_value: {spec.decompile_value}")
        for extension in spec.extensions:
            other = self._formats_by_extension.get(extension)
            if other is not None and other.type_name != spec.type_name and not replace:
                message = f"format extension conflict for {extension}: {other.type_name} vs {spec.type_name}"
                self.conflicts.append(message)
                raise ValueError(message)
        existing = self._formats_by_type.get(spec.type_name)
        if existing is not None:
            self._formats = [item for item in self._formats if item.type_name != spec.type_name]
            for extension in existing.extensions:
                if self._formats_by_extension.get(extension) == existing:
                    del self._formats_by_extension[extension]
        self._formats.append(spec)
        self._formats_by_type[spec.type_name] = spec
        for extension in spec.extensions:
            self._formats_by_extension[extension] = spec

    def add_formats(self, specs: Iterable[FormatSpec], *, replace: bool = False) -> None:
        checkpoint = self._checkpoint()
        try:
            for spec in specs:
                self.add_format(spec, replace=replace)
        except Exception:
            self._restore(checkpoint)
            raise

    def _object_capability_id(self, kind: str, value: object) -> str:
        type_name = getattr(value, "type_name", "")
        cls = value.__class__
        return f"{kind}:{cls.__module__}.{cls.__qualname__}:{type_name}"

    def add_detector(
        self,
        detector: object,
        *,
        capability_id: str | None = None,
        priority: int | None = None,
        replace: bool = False,
    ) -> None:
        missing = (["type_name"] if not getattr(detector, "type_name", "") else []) + [
            name
            for name in ("identify", "find_embedded", "validate")
            if not callable(getattr(detector, name, None))
        ]
        if missing:
            raise TypeError(f"invalid detector contract; missing: {', '.join(missing)}")
        identifier = capability_id or self._object_capability_id("detector", detector)
        existing = self._claim_id("detector", identifier, detector, replace)
        if existing is not None:
            self._detector_records = [item for item in self._detector_records if item.capability_id != identifier]
        self._detector_records.append(
            RegisteredObjectCapability(detector, identifier, self._current_source, self._default_priority() if priority is None else priority, self._next_sequence())
        )
        self._detector_records.sort(key=self._sort_key)

    def add_detectors(self, detectors: Iterable[object], **kwargs: Any) -> None:
        for detector in detectors:
            self.add_detector(detector, **kwargs)

    def add_container_handler(
        self,
        handler: object,
        *,
        capability_id: str | None = None,
        priority: int | None = None,
        replace: bool = False,
    ) -> None:
        missing = (["type_name"] if not getattr(handler, "type_name", "") else []) + [
            name for name in ("sniff", "open", "extract_entry") if not callable(getattr(handler, name, None))
        ]
        if missing:
            raise TypeError(f"invalid container handler contract; missing: {', '.join(missing)}")
        identifier = capability_id or self._object_capability_id("container", handler)
        existing = self._claim_id("container", identifier, handler, replace)
        if existing is not None:
            self._container_records = [item for item in self._container_records if item.capability_id != identifier]
        self._container_records.append(
            RegisteredObjectCapability(handler, identifier, self._current_source, self._default_priority() if priority is None else priority, self._next_sequence())
        )
        self._container_records.sort(key=self._sort_key)

    def add_container_handlers(self, handlers: Iterable[object], **kwargs: Any) -> None:
        for handler in handlers:
            self.add_container_handler(handler, **kwargs)

    def _matcher(
        self,
        type_names: Iterable[str],
        extensions: Iterable[str],
        file_names: Iterable[str],
        categories: Iterable[str],
        predicate: ParserPredicate | None,
    ) -> CapabilityMatcher:
        return CapabilityMatcher(
            type_names=frozenset(item.lower() for item in type_names),
            extensions=frozenset(_normalize_extension(item) for item in extensions),
            file_names=frozenset(item.lower() for item in file_names),
            categories=frozenset(item.lower() for item in categories),
            predicate=predicate,
        )

    def add_parser(
        self,
        parser: ParserFunction,
        *,
        name: str | None = None,
        capability_id: str | None = None,
        priority: int | None = None,
        replace: bool = False,
        type_names: Iterable[str] = (),
        extensions: Iterable[str] = (),
        file_names: Iterable[str] = (),
        categories: Iterable[str] = (),
        predicate: ParserPredicate | None = None,
        stream_safe: bool = False,
    ) -> None:
        if not callable(parser):
            raise TypeError("parser must be callable")
        self._add_parser_capability(
            parser=parser,
            source_parser=None,
            name=name or parser.__name__,
            capability_id=capability_id,
            priority=priority,
            replace=replace,
            type_names=type_names,
            extensions=extensions,
            file_names=file_names,
            categories=categories,
            predicate=predicate,
            stream_safe=stream_safe,
        )

    def add_source_parser(
        self,
        parser: SourceParserFunction,
        *,
        name: str | None = None,
        capability_id: str | None = None,
        priority: int | None = None,
        replace: bool = False,
        type_names: Iterable[str] = (),
        extensions: Iterable[str] = (),
        file_names: Iterable[str] = (),
        categories: Iterable[str] = (),
        predicate: ParserPredicate | None = None,
    ) -> None:
        if not callable(parser):
            raise TypeError("source parser must be callable")
        self._add_parser_capability(
            parser=None,
            source_parser=parser,
            name=name or parser.__name__,
            capability_id=capability_id,
            priority=priority,
            replace=replace,
            type_names=type_names,
            extensions=extensions,
            file_names=file_names,
            categories=categories,
            predicate=predicate,
            stream_safe=True,
        )

    def _add_parser_capability(self, **values: Any) -> None:
        name = str(values["name"])
        identifier = values["capability_id"] or f"parser:{self._current_source}:{name}"
        matcher = self._matcher(
            values["type_names"], values["extensions"], values["file_names"], values["categories"], values["predicate"]
        )
        existing = self._claim_id("parser", identifier, values.get("parser") or values.get("source_parser"), values["replace"])
        if existing is not None:
            self.parsers = [item for item in self.parsers if item.capability_id != identifier]
        self.parsers.append(
            ParserCapability(
                parser=values["parser"],
                source_parser=values["source_parser"],
                name=name,
                capability_id=identifier,
                source=self._current_source,
                priority=self._default_priority() if values["priority"] is None else int(values["priority"]),
                sequence=self._next_sequence(),
                matcher=matcher,
                stream_safe=bool(values["stream_safe"]),
            )
        )
        self.parsers.sort(key=self._sort_key)

    def _add_processor(
        self,
        kind: str,
        target: list[ProcessorCapability],
        processor: ProcessorFunction,
        *,
        name: str | None,
        capability_id: str | None,
        priority: int | None,
        replace: bool,
        type_names: Iterable[str],
        extensions: Iterable[str],
        file_names: Iterable[str],
        categories: Iterable[str],
        predicate: ParserPredicate | None,
    ) -> None:
        if not callable(processor):
            raise TypeError(f"{kind} must be callable")
        capability_name = name or processor.__name__
        identifier = capability_id or f"{kind}:{self._current_source}:{capability_name}"
        matcher = self._matcher(type_names, extensions, file_names, categories, predicate)
        existing = self._claim_id(kind, identifier, processor, replace)
        if existing is not None:
            target[:] = [item for item in target if item.capability_id != identifier]
        target.append(
            ProcessorCapability(
                processor=processor,
                name=capability_name,
                capability_id=identifier,
                source=self._current_source,
                priority=self._default_priority() if priority is None else priority,
                sequence=self._next_sequence(),
                matcher=matcher,
            )
        )
        target.sort(key=self._sort_key)

    def add_converter(self, converter: ProcessorFunction, **kwargs: Any) -> None:
        self._add_processor("converter", self.converters, converter, **_processor_kwargs(kwargs))

    def add_reconstructor(self, reconstructor: ProcessorFunction, **kwargs: Any) -> None:
        self._add_processor("reconstructor", self.reconstructors, reconstructor, **_processor_kwargs(kwargs))

    def add_run_hook(
        self,
        hook: RunHookFunction,
        *,
        name: str | None = None,
        capability_id: str | None = None,
        priority: int | None = None,
        replace: bool = False,
    ) -> None:
        if not callable(hook):
            raise TypeError("run hook must be callable")
        capability_name = name or hook.__name__
        identifier = capability_id or f"run_hook:{self._current_source}:{capability_name}"
        existing = self._claim_id("run_hook", identifier, hook, replace)
        if existing is not None:
            self.run_hooks = [item for item in self.run_hooks if item.capability_id != identifier]
        self.run_hooks.append(
            RunHookCapability(
                hook=hook,
                name=capability_name,
                capability_id=identifier,
                source=self._current_source,
                priority=self._default_priority() if priority is None else priority,
                sequence=self._next_sequence(),
            )
        )
        self.run_hooks.sort(key=self._sort_key)

    def add_streaming_detector(
        self,
        *,
        type_name: str,
        signatures: Iterable[bytes],
        length_reader: StreamingLengthReader,
        extension: str | None = None,
        capability_id: str | None = None,
        priority: int | None = None,
        replace: bool = False,
    ) -> None:
        normalized_type = type_name.strip().lower()
        normalized_signatures = tuple(bytes(signature) for signature in signatures if signature)
        if not normalized_type or not normalized_signatures:
            raise ValueError("streaming detectors require a type_name and at least one signature")
        identifier = capability_id or f"streaming_detector:{self._current_source}:{normalized_type}"
        existing = self._claim_id("streaming_detector", identifier, length_reader, replace)
        if existing is not None:
            self._streaming_detectors = [item for item in self._streaming_detectors if item.capability_id != identifier]
        self._streaming_detectors.append(
            StreamingDetectorCapability(
                type_name=normalized_type,
                signatures=normalized_signatures,
                length_reader=length_reader,
                extension=_normalize_extension(extension or normalized_type),
                capability_id=identifier,
                source=self._current_source,
                priority=self._default_priority() if priority is None else priority,
                sequence=self._next_sequence(),
            )
        )
        self._streaming_detectors.sort(key=self._sort_key)

    def find_format_by_extension(self, extension: str) -> FormatSpec | None:
        return self._formats_by_extension.get(_normalize_extension(extension)) if extension else None

    def find_format_by_type(self, type_name: str) -> FormatSpec | None:
        return self._formats_by_type.get(type_name.lower())

    def find_streaming_detector(self, type_name: str) -> StreamingDetectorCapability | None:
        normalized = type_name.lower()
        return next((item for item in self._streaming_detectors if item.type_name == normalized), None)

    def find_container_handler(self, path: str | Path, deep_scan: bool = True) -> object | None:
        from .containers import DEEP_CONTAINER_TYPES

        file_path = Path(path)
        for record in self._container_records:
            handler = record.value
            if not deep_scan and getattr(handler, "type_name", "") in DEEP_CONTAINER_TYPES:
                continue
            try:
                if handler.sniff(file_path):
                    return handler
            except Exception as exc:
                self.record_runtime_error(record, file_path, exc)
        return None

    def parse_file(self, path: str | Path, identified_type: str, category: str = "") -> dict[str, Any]:
        file_path = Path(path)
        normalized_type = identified_type.lower()
        failures: list[tuple[str, str]] = []
        for parser in self.parsers:
            try:
                matches = parser.matches(file_path, normalized_type, category.lower())
            except Exception as exc:
                self.record_runtime_error(parser, file_path, exc)
                continue
            if not matches or parser.parser is None:
                continue
            try:
                return parser.parser(file_path)
            except Exception as exc:
                failures.append((parser.name, str(exc)))
                self.record_runtime_error(parser, file_path, exc)

        if failures:
            return {"parser": failures[0][0], "status": "parser_failed", "errors": [error for _name, error in failures]}
        return self._descriptor_parse(file_path, normalized_type, category)

    def parse_source(
        self,
        source: ArtifactSource,
        logical_path: str | Path,
        identified_type: str,
        category: str = "",
        materialize_limit: int | None = None,
    ) -> dict[str, Any]:
        file_path = Path(logical_path)
        normalized_type = identified_type.lower()
        failures: list[tuple[str, str]] = []
        direct_path = (
            source.is_direct_file
            and source.source_path is not None
            and source.source_path.resolve(strict=False) == file_path.resolve(strict=False)
        )
        for parser in self.parsers:
            try:
                matches = parser.matches(file_path, normalized_type, category.lower())
            except Exception as exc:
                self.record_runtime_error(parser, file_path, exc)
                continue
            if not matches:
                continue
            try:
                if parser.source_parser is not None:
                    return parser.source_parser(source, file_path)
                if (
                    parser.parser is not None
                    and direct_path
                    and (
                        materialize_limit is None
                        or source.size <= materialize_limit
                        or parser.stream_safe
                    )
                ):
                    return parser.parser(file_path)
                if parser.parser is not None and materialize_limit is not None and source.size <= materialize_limit:
                    with source.materialized(file_path.suffix) as materialized_path:
                        return parser.parser(materialized_path)
            except Exception as exc:
                failures.append((parser.name, str(exc)))
                self.record_runtime_error(parser, file_path, exc)
        if failures:
            return {"parser": failures[0][0], "status": "parser_failed", "errors": [error for _name, error in failures]}
        return self._descriptor_parse(file_path, normalized_type, category)

    def _descriptor_parse(self, file_path: Path, normalized_type: str, category: str) -> dict[str, Any]:
        spec = self.find_format_by_type(normalized_type) or self.find_format_by_extension(file_path.suffix)
        if spec is not None:
            return {
                "parser": "extension_descriptor",
                "status": "extension_only",
                "type": spec.type_name,
                "category": spec.category,
                "role": spec.role,
                "text_expected": spec.text,
            }
        if category and category != "unknown":
            return {"parser": "semantic_classifier", "status": "classified_without_format_parser", "category": category}
        return {"parser": "none", "status": "unidentified"}

    def describe_file(self, path: str | Path, identified_type: str, category: str = "") -> dict[str, Any]:
        return self._descriptor_parse(Path(path), identified_type.lower(), category.lower())

    def matching_converters(self, path: Path, identified_type: str, category: str) -> list[ProcessorCapability]:
        return self._matching_processors(self.converters, path, identified_type, category)

    def matching_reconstructors(self, path: Path, identified_type: str, category: str) -> list[ProcessorCapability]:
        return self._matching_processors(self.reconstructors, path, identified_type, category)

    def _matching_processors(
        self,
        capabilities: list[ProcessorCapability],
        path: Path,
        identified_type: str,
        category: str,
    ) -> list[ProcessorCapability]:
        matches: list[ProcessorCapability] = []
        for capability in capabilities:
            try:
                if capability.matches(path, identified_type, category.lower()):
                    matches.append(capability)
            except Exception as exc:
                self.record_runtime_error(capability, path, exc)
        return matches

    def record_runtime_error(self, capability: object, path: Path, exc: Exception) -> None:
        name = getattr(capability, "capability_id", None) or getattr(capability, "name", None) or getattr(capability, "type_name", None)
        if not name and isinstance(capability, RegisteredObjectCapability):
            name = capability.capability_id
        self.runtime_errors.append(f"{name or capability.__class__.__name__} ({path}): {exc}")

    def drain_runtime_errors(self) -> list[str]:
        errors = self.runtime_errors[:]
        self.runtime_errors.clear()
        return errors

    def configure(self, options: Any) -> None:
        keyring_requested = bool(getattr(options, "container_keyring_path", None))
        keyring_consumed = False
        for record in self._container_records:
            configure = getattr(record.value, "configure", None)
            if not callable(configure):
                continue
            try:
                result = configure(options)
                if keyring_requested and result is not False:
                    keyring_consumed = True
            except Exception as exc:
                self.record_runtime_error(record, Path(getattr(options, "container_keyring_path", "")), exc)
        if keyring_requested and not keyring_consumed:
            message = "container_keyring_path was provided but no registered container handler accepts keyring configuration"
            if message not in self.load_errors:
                self.load_errors.append(message)


def _processor_kwargs(values: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "name",
        "capability_id",
        "priority",
        "replace",
        "type_names",
        "extensions",
        "file_names",
        "categories",
        "predicate",
    }
    unknown = set(values) - allowed
    if unknown:
        raise TypeError(f"unknown processor capability option(s): {', '.join(sorted(unknown))}")
    defaults: dict[str, Any] = {
        "name": None,
        "capability_id": None,
        "priority": None,
        "replace": False,
        "type_names": (),
        "extensions": (),
        "file_names": (),
        "categories": (),
        "predicate": None,
    }
    defaults.update(values)
    return defaults


_ACTIVE_REGISTRY: ContextVar[CapabilityRegistry | None] = ContextVar("deinserter_active_registry", default=None)
_DEFAULT_REGISTRY: CapabilityRegistry | None = None


def _normalize_extension(extension: str) -> str:
    value = extension.strip().lower()
    if not value:
        raise ValueError("extension cannot be empty")
    return value if value.startswith(".") else f".{value}"


def _format_pack_file(path: str | Path) -> Path:
    file_path = Path(path)
    return file_path / "formats.toml" if file_path.is_dir() else file_path


def load_format_pack(registry: CapabilityRegistry, path: str | Path) -> None:
    with registry.registration_source(f"format-pack:{path}"):
        registry.add_formats(load_format_specs(_format_pack_file(path)))


def _plugin_api_version(register: object) -> int:
    declared = getattr(register, "DEINSERTER_API_VERSION", None)
    module = sys.modules.get(getattr(register, "__module__", ""))
    if declared is None and module is not None:
        declared = getattr(module, "DEINSERTER_API_VERSION", None)
    return CAPABILITY_API_VERSION if declared is None else int(declared)


def register_plugin_callable(registry: CapabilityRegistry, name: str, register: Callable[[CapabilityRegistry], Any]) -> dict[str, Any]:
    api_version = _plugin_api_version(register)
    if api_version not in SUPPORTED_PLUGIN_API_VERSIONS:
        raise ValueError(f"unsupported plugin API version {api_version}; supported: {sorted(SUPPORTED_PLUGIN_API_VERSIONS)}")
    checkpoint = registry._checkpoint()
    try:
        with registry.registration_source(f"plugin:{name}"):
            register(registry)
    except Exception:
        registry._restore(checkpoint)
        raise
    metadata = {"name": name, "status": "loaded", "api_version": api_version}
    registry.plugins.append(metadata)
    return metadata


def load_entry_point_plugins(registry: CapabilityRegistry, disabled_plugins: Iterable[str] = ()) -> None:
    disabled = frozenset(disabled_plugins)
    for entry_point in entry_points(group=ENTRY_POINT_GROUP):
        if entry_point.name in disabled:
            registry.plugins.append({"name": entry_point.name, "status": "disabled"})
            continue
        try:
            register = entry_point.load()
            register_plugin_callable(registry, entry_point.name, register)
        except Exception as exc:
            registry.load_errors.append(f"{entry_point.name}: {exc}")
            registry.plugins.append({"name": entry_point.name, "status": "failed", "error": str(exc)})


def build_capability_registry(
    format_pack_paths: Iterable[str | Path] | None = None,
    *,
    load_plugins: bool = True,
    disabled_plugins: Iterable[str] = (),
) -> CapabilityRegistry:
    registry = CapabilityRegistry()
    with registry.registration_source("builtin"):
        registry.add_formats(SUPPORTED_FORMATS)

    for path in format_pack_paths or ():
        try:
            load_format_pack(registry, path)
        except (OSError, ValueError) as exc:
            registry.load_errors.append(f"{path}: {exc}")

    from .containers import build_builtin_container_handlers
    from .detectors import ExtensionDetector, TextScriptDetector, build_builtin_detectors
    from .parsers import register_builtin_parsers
    from .processors import register_builtin_processors
    from .stream_scanner import register_builtin_streaming_detectors

    with registry.registration_source("builtin"):
        registry.add_detectors(
            build_builtin_detectors(
                registry.formats,
                include_extension_detectors=False,
                include_text_detector=False,
            )
        )
        registry.add_container_handlers(build_builtin_container_handlers())
        register_builtin_parsers(registry)
        register_builtin_streaming_detectors(registry)
        register_builtin_processors(registry)
    if load_plugins:
        load_entry_point_plugins(registry, disabled_plugins)
    with registry.registration_source("builtin"):
        for spec in registry.formats:
            registry.add_detector(
                ExtensionDetector(spec),
                capability_id=f"builtin:detector:extension:{spec.type_name}",
            )
        registry.add_detector(
            TextScriptDetector(registry.text_extensions),
            capability_id="builtin:detector:text_script",
        )
    return registry


def get_default_registry() -> CapabilityRegistry:
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is None:
        _DEFAULT_REGISTRY = build_capability_registry()
    return _DEFAULT_REGISTRY


def get_active_registry() -> CapabilityRegistry:
    return _ACTIVE_REGISTRY.get() or get_default_registry()


@contextmanager
def use_registry(registry: CapabilityRegistry) -> Iterator[CapabilityRegistry]:
    token = _ACTIVE_REGISTRY.set(registry)
    try:
        yield registry
    finally:
        _ACTIVE_REGISTRY.reset(token)
