from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from .formats import FormatSpec, SUPPORTED_FORMATS, load_format_specs

ParserFunction = Callable[[Path], dict[str, Any]]
ParserPredicate = Callable[[Path, str, str], bool]

ENTRY_POINT_GROUP = "deinserter.plugins"


@dataclass(frozen=True, slots=True)
class ParserCapability:
    parser: ParserFunction
    name: str
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


class CapabilityRegistry:
    def __init__(self) -> None:
        self._formats: list[FormatSpec] = []
        self._formats_by_type: dict[str, FormatSpec] = {}
        self._formats_by_extension: dict[str, FormatSpec] = {}
        self.detectors: list[object] = []
        self.container_handlers: list[object] = []
        self.parsers: list[ParserCapability] = []
        self.load_errors: list[str] = []

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

    def add_format(self, spec: FormatSpec) -> None:
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

    def add_formats(self, specs: Iterable[FormatSpec]) -> None:
        for spec in specs:
            self.add_format(spec)

    def add_detector(self, detector: object) -> None:
        self.detectors.append(detector)

    def add_detectors(self, detectors: Iterable[object]) -> None:
        for detector in detectors:
            self.add_detector(detector)

    def add_container_handler(self, handler: object) -> None:
        self.container_handlers.append(handler)

    def add_container_handlers(self, handlers: Iterable[object]) -> None:
        for handler in handlers:
            self.add_container_handler(handler)

    def add_parser(
        self,
        parser: ParserFunction,
        *,
        name: str | None = None,
        type_names: Iterable[str] = (),
        extensions: Iterable[str] = (),
        file_names: Iterable[str] = (),
        categories: Iterable[str] = (),
        predicate: ParserPredicate | None = None,
    ) -> None:
        self.parsers.append(
            ParserCapability(
                parser=parser,
                name=name or parser.__name__,
                type_names=frozenset(item.lower() for item in type_names),
                extensions=frozenset(_normalize_extension(item) for item in extensions),
                file_names=frozenset(item.lower() for item in file_names),
                categories=frozenset(item for item in categories),
                predicate=predicate,
            )
        )

    def find_format_by_extension(self, extension: str) -> FormatSpec | None:
        return self._formats_by_extension.get(_normalize_extension(extension)) if extension else None

    def find_format_by_type(self, type_name: str) -> FormatSpec | None:
        return self._formats_by_type.get(type_name.lower())

    def find_container_handler(self, path: str | Path, deep_scan: bool = True) -> object | None:
        from .containers import DEEP_CONTAINER_TYPES

        file_path = Path(path)
        for handler in self.container_handlers:
            if not deep_scan and getattr(handler, "type_name", "") in DEEP_CONTAINER_TYPES:
                continue
            if handler.sniff(file_path):
                return handler
        return None

    def parse_file(self, path: str | Path, identified_type: str, category: str = "") -> dict[str, Any]:
        file_path = Path(path)
        normalized_type = identified_type.lower()
        for parser in self.parsers:
            if parser.matches(file_path, normalized_type, category):
                return parser.parser(file_path)

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


_ACTIVE_REGISTRY: ContextVar[CapabilityRegistry | None] = ContextVar("deinserter_active_registry", default=None)
_DEFAULT_REGISTRY: CapabilityRegistry | None = None


def _normalize_extension(extension: str) -> str:
    value = extension.strip().lower()
    return value if value.startswith(".") else f".{value}"


def _format_pack_file(path: str | Path) -> Path:
    file_path = Path(path)
    return file_path / "formats.toml" if file_path.is_dir() else file_path


def load_format_pack(registry: CapabilityRegistry, path: str | Path) -> None:
    registry.add_formats(load_format_specs(_format_pack_file(path)))


def load_entry_point_plugins(registry: CapabilityRegistry) -> None:
    for entry_point in entry_points(group=ENTRY_POINT_GROUP):
        try:
            register = entry_point.load()
            register(registry)
        except Exception as exc:  # pragma: no cover - defensive boundary for third-party plugins
            registry.load_errors.append(f"{entry_point.name}: {exc}")


def build_capability_registry(
    format_pack_paths: Iterable[str | Path] | None = None,
    *,
    load_plugins: bool = True,
) -> CapabilityRegistry:
    registry = CapabilityRegistry()
    registry.add_formats(SUPPORTED_FORMATS)

    for path in format_pack_paths or ():
        try:
            load_format_pack(registry, path)
        except (OSError, ValueError) as exc:
            registry.load_errors.append(f"{path}: {exc}")

    if load_plugins:
        load_entry_point_plugins(registry)

    from .containers import build_builtin_container_handlers
    from .detectors import build_builtin_detectors
    from .parsers import register_builtin_parsers

    registry.add_detectors(build_builtin_detectors(registry.formats))
    registry.add_container_handlers(build_builtin_container_handlers())
    register_builtin_parsers(registry)
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
