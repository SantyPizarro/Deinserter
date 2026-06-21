from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


MAX_TYPE_TREE_RECURSION = 64
MAX_TYPE_TREE_ARRAY_ITEMS = 100_000
MAX_DECODE_BYTES = 16 * 1024 * 1024


COMMON_STRING_TABLE: dict[int, str] = {
    0: "AABB",
    5: "AnimationClip",
    19: "AnimationCurve",
    34: "AnimationState",
    49: "Array",
    55: "Base",
    60: "BitField",
    69: "bitset",
    76: "bool",
    81: "char",
    86: "ColorRGBA",
    96: "Component",
    106: "data",
    111: "deque",
    117: "double",
    124: "dynamic_array",
    138: "FastPropertyName",
    155: "first",
    161: "float",
    167: "Font",
    172: "GameObject",
    183: "Generic Mono",
    196: "GradientNEW",
    208: "GUID",
    213: "GUIStyle",
    222: "int",
    226: "list",
    231: "long long",
    241: "map",
    245: "Matrix4x4f",
    256: "MdFour",
    263: "MonoBehaviour",
    277: "MonoScript",
    288: "m_ByteSize",
    299: "m_Curve",
    307: "m_EditorClassIdentifier",
    331: "m_EditorHideFlags",
    349: "m_Enabled",
    359: "m_ExtensionPtr",
    374: "m_GameObject",
    387: "m_Index",
    395: "m_IsArray",
    405: "m_IsStatic",
    416: "m_MetaFlag",
    427: "m_Name",
    434: "m_ObjectHideFlags",
    452: "m_PrefabInternal",
    469: "m_PrefabParentObject",
    490: "m_Script",
    499: "m_StaticEditorFlags",
    519: "m_StringArgument",
    536: "m_Type",
    543: "m_Version",
    553: "Object",
    560: "PPtr<Component>",
    576: "PPtr<GameObject>",
    593: "PPtr<Material>",
    608: "PPtr<MonoBehaviour>",
    628: "PPtr<MonoScript>",
    645: "PPtr<Object>",
    658: "PPtr<Prefab>",
    671: "PPtr<Sprite>",
    684: "PPtr<Texture>",
    698: "PPtr<Texture2D>",
    714: "Quaternionf",
    726: "Rectf",
    732: "RectInt",
    740: "second",
    747: "set",
    751: "short",
    757: "size",
    762: "SInt16",
    769: "SInt32",
    776: "SInt64",
    783: "SInt8",
    789: "staticvector",
    802: "string",
    809: "TextAsset",
    819: "Texture2D",
    829: "UInt16",
    836: "UInt32",
    843: "UInt64",
    850: "UInt8",
    856: "unsigned int",
    869: "unsigned long long",
    888: "unsigned short",
    903: "vector",
    910: "Vector2f",
    919: "Vector3f",
    928: "Vector4f",
}


CLASS_NAMES: dict[int, str] = {
    1: "GameObject",
    4: "Transform",
    21: "Material",
    28: "Texture2D",
    43: "Mesh",
    48: "Shader",
    49: "TextAsset",
    74: "AnimationClip",
    83: "AudioClip",
    91: "AnimatorController",
    95: "Animator",
    114: "MonoBehaviour",
    115: "MonoScript",
    128: "Font",
    213: "Sprite",
}


@dataclass(slots=True)
class UnityTypeTreeNode:
    type_name: str
    field_name: str
    byte_size: int
    index: int
    version: int
    depth: int
    is_array: bool
    flags: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type_name,
            "name": self.field_name,
            "byte_size": self.byte_size,
            "index": self.index,
            "version": self.version,
            "depth": self.depth,
            "is_array": self.is_array,
            "flags": self.flags,
        }


@dataclass(slots=True)
class UnityExternal:
    file_id: int
    path_name: str
    guid: str = ""
    type: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"file_id": self.file_id, "path_name": self.path_name, "guid": self.guid, "type": self.type}


@dataclass(slots=True)
class UnityReference:
    file_id: int
    path_id: int
    source_file: str
    source_path_id: int
    target_file: str = ""
    target_path_id: int | None = None
    resolved: bool = False
    resolution_status: str = "unresolved"
    target_type_name: str = ""
    target_class_id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_id": self.file_id,
            "path_id": self.path_id,
            "source_file": self.source_file,
            "source_path_id": self.source_path_id,
            "target_file": self.target_file,
            "target_path_id": self.target_path_id,
            "resolved": self.resolved,
            "resolution_status": self.resolution_status,
            "target_type_name": self.target_type_name,
            "target_class_id": self.target_class_id,
        }


@dataclass(slots=True)
class UnityType:
    type_id: int
    class_id: int
    script_type_index: int = -1
    is_stripped_type: bool = False
    type_tree_nodes: list[UnityTypeTreeNode] = field(default_factory=list)

    @property
    def type_name(self) -> str:
        return CLASS_NAMES.get(self.class_id, f"ClassID_{self.class_id}")


@dataclass(slots=True)
class UnityObject:
    source_path: str
    path_id: int
    class_id: int
    type_id: int
    offset: int
    size: int
    type_name: str
    source: str = "serialized_file"
    external_resource: dict[str, Any] | None = None
    decoded_fields: dict[str, Any] = field(default_factory=dict)
    decode_status: str = "raw_payload"
    pptr_references: list[UnityReference] = field(default_factory=list)
    streaming_infos: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "unity_object",
            "source_path": self.source_path,
            "path_id": self.path_id,
            "class_id": self.class_id,
            "type_id": self.type_id,
            "type_name": self.type_name,
            "source_offset": self.offset,
            "size": self.size,
            "source": self.source,
            "external_resource": self.external_resource,
            "decode_status": self.decode_status,
            "decoded_fields": self.decoded_fields,
            "pptr_references": [item.to_dict() for item in self.pptr_references],
            "streaming_infos": self.streaming_infos,
        }


@dataclass(slots=True)
class UnitySerializedInfo:
    path: str
    status: str
    file_size: int
    format_version: int = 0
    unity_version: str = ""
    metadata_size: int = 0
    declared_file_size: int = 0
    data_offset: int = 0
    endianness: str = "little_or_unspecified"
    target_platform: int | None = None
    type_tree_enabled: bool | None = None
    type_count: int = 0
    object_count: int = 0
    types: list[UnityType] = field(default_factory=list)
    objects: list[UnityObject] = field(default_factory=list)
    externals: list[UnityExternal] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        by_class: dict[str, int] = {}
        by_type: dict[str, int] = {}
        for item in self.objects:
            by_class[str(item.class_id)] = by_class.get(str(item.class_id), 0) + 1
            by_type[item.type_name] = by_type.get(item.type_name, 0) + 1
        return {
            "parser": "unity_serialized_file",
            "status": self.status,
            "file_size": self.file_size,
            "format_version": self.format_version,
            "unity_version": self.unity_version,
            "metadata_size": self.metadata_size,
            "declared_file_size": self.declared_file_size,
            "data_offset": self.data_offset,
            "endianness": self.endianness,
            "target_platform_raw": self.target_platform,
            "type_tree_enabled_raw": int(self.type_tree_enabled) if self.type_tree_enabled is not None else None,
            "type_count": self.type_count,
            "object_count": self.object_count,
            "unity_serialized": {
                "format_version": self.format_version,
                "unity_version": self.unity_version,
                "endianness": self.endianness,
                "metadata_size": self.metadata_size,
                "data_offset": self.data_offset,
                "object_count": self.object_count,
                "type_count": self.type_count,
                "external_count": len(self.externals),
            },
            "unity_object_summary": {
                "object_count": self.object_count,
                "type_count": self.type_count,
                "by_class_id": by_class,
                "by_type": by_type,
                "extractable_objects": self.object_count,
                "objects_sample": [item.to_dict() for item in self.objects[:50]],
            },
            "types_sample": [
                {
                    "type_id": item.type_id,
                    "class_id": item.class_id,
                    "type_name": item.type_name,
                    "type_tree_nodes_sample": [node.to_dict() for node in item.type_tree_nodes[:32]],
                }
                for item in self.types[:50]
            ],
            "externals_sample": [item.to_dict() for item in self.externals[:50]],
            **({"error": self.error} if self.error else {}),
        }


def _read_at(path: Path, offset: int, length: int) -> bytes:
    with path.open("rb") as handle:
        handle.seek(offset)
        return handle.read(length)


def _c_string(data: bytes, cursor: int) -> tuple[str, int]:
    end = data.find(b"\0", cursor)
    if end == -1:
        return "", cursor
    return data[cursor:end].decode("utf-8", errors="replace"), end + 1


def _align(cursor: int, alignment: int = 4) -> int:
    return (cursor + alignment - 1) & ~(alignment - 1)


def _unity_string(data: bytes, cursor: int, endian: str) -> tuple[str, int]:
    if cursor + 4 > len(data):
        raise ValueError("truncated Unity string length")
    length = struct.unpack_from(f"{endian}I", data, cursor)[0]
    cursor += 4
    if length > len(data) - cursor:
        raise ValueError("Unity string exceeds object payload")
    value = data[cursor : cursor + length].decode("utf-8", errors="replace")
    return value, _align(cursor + length)


def _type_tree_string(string_buffer: bytes, offset: int) -> str:
    if offset < 0:
        common_index = offset & 0x7FFFFFFF
        return COMMON_STRING_TABLE.get(common_index, f"common_string_{common_index}")
    if offset >= len(string_buffer):
        return ""
    end = string_buffer.find(b"\0", offset)
    if end == -1:
        end = len(string_buffer)
    return string_buffer[offset:end].decode("utf-8", errors="replace")


@dataclass(slots=True)
class _TypeTreeBranch:
    node: UnityTypeTreeNode
    children: list["_TypeTreeBranch"] = field(default_factory=list)


def _build_type_tree(nodes: list[UnityTypeTreeNode]) -> _TypeTreeBranch | None:
    if not nodes:
        return None
    root = _TypeTreeBranch(nodes[0])
    stack: list[_TypeTreeBranch] = [root]
    for node in nodes[1:]:
        branch = _TypeTreeBranch(node)
        while stack and stack[-1].node.depth >= node.depth:
            stack.pop()
        if stack:
            stack[-1].children.append(branch)
        else:
            root.children.append(branch)
        stack.append(branch)
    return root


class _UnityDecodeError(ValueError):
    pass


class _UnityDecodePartial(_UnityDecodeError):
    def __init__(self, message: str, partial: Any):
        super().__init__(message)
        self.partial = partial


class _ObjectReader:
    def __init__(self, data: bytes, endian: str):
        self.data = data
        self.endian = endian
        self.cursor = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.cursor

    def require(self, length: int) -> None:
        if length < 0 or self.cursor + length > len(self.data):
            raise _UnityDecodeError("Unity object payload truncated")

    def align(self, alignment: int = 4) -> None:
        self.cursor = _align(self.cursor, alignment)
        if self.cursor > len(self.data):
            raise _UnityDecodeError("Unity object alignment exceeded payload")

    def read_string(self) -> str:
        self.require(4)
        length = struct.unpack_from(f"{self.endian}I", self.data, self.cursor)[0]
        self.cursor += 4
        if length > self.remaining:
            raise _UnityDecodeError("Unity string exceeds object payload")
        value = self.data[self.cursor : self.cursor + length].decode("utf-8", errors="replace")
        self.cursor += length
        self.align()
        return value

    def read_primitive(self, type_name: str) -> Any:
        normalized = type_name.lower()
        formats: dict[str, tuple[str, int]] = {
            "sint8": ("b", 1),
            "char": ("b", 1),
            "uint8": ("B", 1),
            "unsigned char": ("B", 1),
            "sint16": ("h", 2),
            "short": ("h", 2),
            "uint16": ("H", 2),
            "unsigned short": ("H", 2),
            "int": ("i", 4),
            "sint32": ("i", 4),
            "unsigned int": ("I", 4),
            "uint32": ("I", 4),
            "long long": ("q", 8),
            "sint64": ("q", 8),
            "unsigned long long": ("Q", 8),
            "uint64": ("Q", 8),
            "float": ("f", 4),
            "double": ("d", 8),
        }
        if normalized in {"bool", "boolean"}:
            self.require(1)
            value = bool(self.data[self.cursor])
            self.cursor += 1
            return value
        if normalized == "string":
            return self.read_string()
        if normalized not in formats:
            raise _UnityDecodeError(f"unsupported Unity primitive: {type_name}")
        fmt, length = formats[normalized]
        self.require(length)
        value = struct.unpack_from(f"{self.endian}{fmt}", self.data, self.cursor)[0]
        self.cursor += length
        return value


def _parse_type_tree_nodes(reader: "_Reader", metadata: bytes, cursor: int, node_count: int, string_buffer_size: int) -> tuple[list[UnityTypeTreeNode], int]:
    nodes_raw = metadata[cursor : cursor + node_count * 32]
    string_buffer = metadata[cursor + node_count * 32 : cursor + node_count * 32 + string_buffer_size]
    if len(nodes_raw) != node_count * 32 or len(string_buffer) != string_buffer_size:
        raise ValueError("truncated Unity type tree")
    nodes: list[UnityTypeTreeNode] = []
    for index in range(node_count):
        node_offset = index * 32
        version = reader.i16(cursor + node_offset)
        depth = reader.u8(cursor + node_offset + 2)
        is_array = bool(reader.u8(cursor + node_offset + 3))
        type_offset = reader.i32(cursor + node_offset + 4)
        name_offset = reader.i32(cursor + node_offset + 8)
        byte_size = reader.i32(cursor + node_offset + 12)
        node_index = reader.i32(cursor + node_offset + 16)
        flags = reader.i32(cursor + node_offset + 20)
        nodes.append(
            UnityTypeTreeNode(
                type_name=_type_tree_string(string_buffer, type_offset),
                field_name=_type_tree_string(string_buffer, name_offset),
                byte_size=byte_size,
                index=node_index,
                version=version,
                depth=depth,
                is_array=is_array,
                flags=flags,
            )
        )
    return nodes, cursor + node_count * 32 + string_buffer_size


def _field_key(branch: _TypeTreeBranch) -> str:
    return branch.node.field_name or branch.node.type_name or f"field_{branch.node.index}"


def _normalized(value: str) -> str:
    return value.lower().replace(" ", "").replace("_", "")


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _value_by_alias(payload: dict[str, Any], aliases: set[str]) -> Any:
    for key, value in payload.items():
        if _normalized(str(key)) in aliases:
            return value
    return None


def _normalize_streaming_info(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": str(_value_by_alias(payload, {"path", "mpath"}) or ""),
        "offset": _as_int(_value_by_alias(payload, {"offset", "moffset"})),
        "size": _as_int(_value_by_alias(payload, {"size", "msize"})),
    }


def _is_primitive_type(type_name: str) -> bool:
    return _normalized(type_name) in {
        "bool",
        "boolean",
        "sint8",
        "char",
        "uint8",
        "unsignedchar",
        "sint16",
        "short",
        "uint16",
        "unsignedshort",
        "int",
        "sint32",
        "unsignedint",
        "uint32",
        "longlong",
        "sint64",
        "unsignedlonglong",
        "uint64",
        "float",
        "double",
        "string",
    }


def _array_branch(branch: _TypeTreeBranch) -> _TypeTreeBranch | None:
    if branch.node.is_array or _normalized(branch.node.type_name) == "array" or _normalized(branch.node.field_name) == "array":
        return branch
    for child in branch.children:
        if child.node.is_array or _normalized(child.node.type_name) == "array" or _normalized(child.node.field_name) == "array":
            return child
    return None


def _array_data_branch(array: _TypeTreeBranch) -> _TypeTreeBranch | None:
    for child in array.children:
        if _normalized(child.node.field_name) == "data":
            return child
    return array.children[-1] if array.children else None


def _is_streaming_info_branch(branch: _TypeTreeBranch) -> bool:
    type_name = _normalized(branch.node.type_name)
    field_name = _normalized(branch.node.field_name)
    return type_name in {"streaminginfo", "streamedresource"} or field_name in {
        "mstreamdata",
        "mstreaminginfo",
        "streaminginfo",
        "streamdata",
    }


def _read_array_size(reader: _ObjectReader, array: _TypeTreeBranch) -> int:
    for child in array.children:
        if _normalized(child.node.field_name) == "size":
            size = reader.read_primitive(child.node.type_name)
            if not isinstance(size, int):
                raise _UnityDecodeError("Unity array size is not an integer")
            if size < 0 or size > MAX_TYPE_TREE_ARRAY_ITEMS:
                raise _UnityDecodeError(f"untrusted Unity array size: {size}")
            return size
    size = reader.read_primitive("int")
    if size < 0 or size > MAX_TYPE_TREE_ARRAY_ITEMS:
        raise _UnityDecodeError(f"untrusted Unity array size: {size}")
    return size


def _decode_pptr(reader: _ObjectReader, obj: UnityObject, references: list[UnityReference]) -> dict[str, Any]:
    reader.require(12)
    file_id = struct.unpack_from(f"{reader.endian}i", reader.data, reader.cursor)[0]
    path_id = struct.unpack_from(f"{reader.endian}q", reader.data, reader.cursor + 4)[0]
    reader.cursor += 12
    ref = UnityReference(
        file_id=file_id,
        path_id=path_id,
        source_file=obj.source_path,
        source_path_id=obj.path_id,
        target_path_id=path_id if file_id == 0 else None,
    )
    references.append(ref)
    return ref.to_dict()


def _decode_streaming_info(
    reader: _ObjectReader,
    branch: _TypeTreeBranch,
    obj: UnityObject,
    references: list[UnityReference],
    streaming_infos: list[dict[str, Any]],
    depth: int,
) -> dict[str, Any]:
    if branch.children:
        payload = _decode_struct(reader, branch, obj, references, streaming_infos, depth + 1)
        info = _normalize_streaming_info(payload)
    else:
        reader.require(12)
        offset = struct.unpack_from(f"{reader.endian}Q", reader.data, reader.cursor)[0]
        size = struct.unpack_from(f"{reader.endian}I", reader.data, reader.cursor + 8)[0]
        reader.cursor += 12
        path = reader.read_string()
        info = {"path": path, "offset": offset, "size": size}
    streaming_infos.append(info)
    return info


def _decode_array(
    reader: _ObjectReader,
    array: _TypeTreeBranch,
    obj: UnityObject,
    references: list[UnityReference],
    streaming_infos: list[dict[str, Any]],
    depth: int,
) -> list[Any]:
    size = _read_array_size(reader, array)
    data_branch = _array_data_branch(array)
    if data_branch is None:
        raise _UnityDecodeError("Unity array data node missing")
    return [_decode_branch(reader, data_branch, obj, references, streaming_infos, depth + 1) for _ in range(size)]


def _decode_map(
    reader: _ObjectReader,
    array: _TypeTreeBranch,
    obj: UnityObject,
    references: list[UnityReference],
    streaming_infos: list[dict[str, Any]],
    depth: int,
) -> list[dict[str, Any]]:
    entries = _decode_array(reader, array, obj, references, streaming_infos, depth + 1)
    mapped: list[dict[str, Any]] = []
    for entry in entries:
        if isinstance(entry, dict):
            mapped.append({"key": entry.get("first"), "value": entry.get("second")})
        else:
            mapped.append({"key": None, "value": entry})
    return mapped


def _decode_struct(
    reader: _ObjectReader,
    branch: _TypeTreeBranch,
    obj: UnityObject,
    references: list[UnityReference],
    streaming_infos: list[dict[str, Any]],
    depth: int,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for child in branch.children:
        key = _field_key(child)
        try:
            result[key] = _decode_branch(reader, child, obj, references, streaming_infos, depth + 1)
        except _UnityDecodeError as exc:
            result[key] = {"__decode_error__": str(exc)}
            raise _UnityDecodePartial(str(exc), result) from exc
    return result


def _decode_branch(
    reader: _ObjectReader,
    branch: _TypeTreeBranch,
    obj: UnityObject,
    references: list[UnityReference],
    streaming_infos: list[dict[str, Any]],
    depth: int = 0,
) -> Any:
    if depth > MAX_TYPE_TREE_RECURSION:
        raise _UnityDecodeError("Unity typetree recursion limit exceeded")
    lowered_type = _normalized(branch.node.type_name)
    value: Any
    if lowered_type.startswith("pptr<"):
        value = _decode_pptr(reader, obj, references)
    elif _is_streaming_info_branch(branch):
        value = _decode_streaming_info(reader, branch, obj, references, streaming_infos, depth)
    elif (array := _array_branch(branch)) is not None:
        if lowered_type == "map":
            value = _decode_map(reader, array, obj, references, streaming_infos, depth + 1)
        else:
            value = _decode_array(reader, array, obj, references, streaming_infos, depth + 1)
    elif branch.children:
        value = _decode_struct(reader, branch, obj, references, streaming_infos, depth + 1)
    elif _is_primitive_type(branch.node.type_name):
        value = reader.read_primitive(branch.node.type_name)
    else:
        raise _UnityDecodeError(f"unsupported Unity node: {branch.node.type_name} {branch.node.field_name}")
    if branch.node.flags & 0x4000:
        reader.align()
    return value


def _decode_object_payload(obj: UnityObject, type_entry: UnityType, endian: str) -> None:
    root = _build_type_tree(type_entry.type_tree_nodes)
    if root is None:
        return
    data = _read_at(Path(obj.source_path), obj.offset, min(obj.size, MAX_DECODE_BYTES))
    if obj.size > MAX_DECODE_BYTES:
        obj.decoded_fields = {"__decode_error__": f"object exceeds decode budget: {obj.size}"}
        obj.decode_status = "partial_typetree"
        return
    reader = _ObjectReader(data, endian)
    references: list[UnityReference] = []
    streaming_infos: list[dict[str, Any]] = []
    try:
        value = _decode_struct(reader, root, obj, references, streaming_infos, 0) if root.children else _decode_branch(
            reader,
            root,
            obj,
            references,
            streaming_infos,
            0,
        )
        obj.decoded_fields = value if isinstance(value, dict) else {_field_key(root): value}
        obj.pptr_references = references
        obj.streaming_infos = streaming_infos
        obj.external_resource = streaming_infos[0] if streaming_infos else None
        obj.decode_status = "decoded" if obj.decoded_fields else "partial_typetree"
    except _UnityDecodePartial as exc:
        obj.decoded_fields = exc.partial if isinstance(exc.partial, dict) else {"__decode_error__": str(exc), "partial": exc.partial}
        obj.pptr_references = references
        obj.streaming_infos = streaming_infos
        obj.external_resource = streaming_infos[0] if streaming_infos else None
        obj.decode_status = "partial_typetree"
    except (OSError, UnicodeDecodeError, struct.error, _UnityDecodeError, ValueError) as exc:
        obj.decoded_fields = {"__decode_error__": str(exc)}
        obj.pptr_references = references
        obj.streaming_infos = streaming_infos
        obj.external_resource = streaming_infos[0] if streaming_infos else None
        obj.decode_status = "partial_typetree"


class _Reader:
    def __init__(self, data: bytes, endian: str = ">"):
        self.data = data
        self.endian = endian

    def u8(self, cursor: int) -> int:
        return self.data[cursor]

    def i16(self, cursor: int) -> int:
        return struct.unpack_from(f"{self.endian}h", self.data, cursor)[0]

    def i32(self, cursor: int) -> int:
        return struct.unpack_from(f"{self.endian}i", self.data, cursor)[0]

    def u32(self, cursor: int) -> int:
        return struct.unpack_from(f"{self.endian}I", self.data, cursor)[0]

    def i64(self, cursor: int) -> int:
        return struct.unpack_from(f"{self.endian}q", self.data, cursor)[0]

    def u64(self, cursor: int) -> int:
        return struct.unpack_from(f"{self.endian}Q", self.data, cursor)[0]


def _parse_metadata(info: UnitySerializedInfo, metadata: bytes, cursor: int, endian: str) -> None:
    reader = _Reader(metadata, endian)
    if cursor + 5 > len(metadata):
        return
    info.target_platform = reader.i32(cursor)
    cursor += 4
    info.type_tree_enabled = bool(reader.u8(cursor))
    cursor += 1
    if cursor + 4 > len(metadata):
        info.status = "parsed_header"
        return
    type_count = reader.i32(cursor)
    cursor += 4
    if type_count < 0 or type_count > 1_000_000:
        raise ValueError(f"untrusted Unity type count: {type_count}")
    types: list[UnityType] = []
    for type_id in range(type_count):
        if cursor + 7 > len(metadata):
            raise ValueError("truncated Unity type table")
        type_tree_nodes: list[UnityTypeTreeNode] = []
        class_id = reader.i32(cursor)
        cursor += 4
        is_stripped = bool(reader.u8(cursor))
        cursor += 1
        script_type_index = reader.i16(cursor)
        cursor += 2
        if class_id == 114:
            cursor += 16
        cursor += 16
        if cursor > len(metadata):
            raise ValueError("truncated Unity type hash")
        if info.type_tree_enabled:
            if cursor + 8 > len(metadata):
                raise ValueError("truncated Unity type tree header")
            node_count = reader.i32(cursor)
            string_buffer_size = reader.i32(cursor + 4)
            cursor += 8
            if node_count < 0 or string_buffer_size < 0 or node_count > 5_000_000:
                raise ValueError("untrusted Unity type tree size")
            type_tree_nodes, cursor = _parse_type_tree_nodes(reader, metadata, cursor, node_count, string_buffer_size)
        types.append(
            UnityType(
                type_id=type_id,
                class_id=class_id,
                script_type_index=script_type_index,
                is_stripped_type=is_stripped,
                type_tree_nodes=type_tree_nodes,
            )
        )
    cursor = _align(cursor)
    if cursor + 4 > len(metadata):
        info.types = types
        info.type_count = len(types)
        info.status = "parsed_type_table"
        return
    object_count = reader.i32(cursor)
    cursor += 4
    if object_count < 0 or object_count > 5_000_000:
        raise ValueError(f"untrusted Unity object count: {object_count}")
    objects: list[UnityObject] = []
    for _ in range(object_count):
        cursor = _align(cursor)
        if cursor + 24 > len(metadata):
            raise ValueError("truncated Unity object table")
        path_id = reader.i64(cursor)
        cursor += 8
        byte_start = reader.u64(cursor)
        cursor += 8
        byte_size = reader.u32(cursor)
        cursor += 4
        type_id = reader.i32(cursor)
        cursor += 4
        if not 0 <= type_id < len(types):
            raise ValueError(f"Unity object references unknown type index: {type_id}")
        absolute_offset = info.data_offset + int(byte_start)
        if absolute_offset < 0 or absolute_offset + int(byte_size) > info.file_size:
            raise ValueError("Unity object range exceeds serialized file")
        type_entry = types[type_id]
        objects.append(
            UnityObject(
                source_path=info.path,
                path_id=path_id,
                class_id=type_entry.class_id,
                type_id=type_id,
                offset=absolute_offset,
                size=int(byte_size),
                type_name=type_entry.type_name,
            )
        )
    externals: list[UnityExternal] = []
    cursor = _align(cursor)
    if cursor + 4 <= len(metadata):
        external_count = reader.i32(cursor)
        cursor += 4
        if 0 <= external_count <= 1_000_000:
            for index in range(external_count):
                if cursor + 6 > len(metadata):
                    break
                file_id = reader.i32(cursor)
                cursor += 4
                path_length = struct.unpack_from(f"{endian}H", metadata, cursor)[0]
                cursor += 2
                if path_length < 0 or cursor + path_length > len(metadata):
                    break
                path_name = metadata[cursor : cursor + path_length].decode("utf-8", errors="replace")
                cursor += path_length
                externals.append(UnityExternal(file_id=file_id or index + 1, path_name=path_name))
    for obj in objects:
        _decode_object_payload(obj, types[obj.type_id], endian)
    info.types = types
    info.objects = objects
    info.externals = externals
    info.type_count = len(types)
    info.object_count = len(objects)
    info.status = "parsed"


def inspect_serialized_file(path: str | Path) -> UnitySerializedInfo:
    file_path = Path(path)
    file_size = file_path.stat().st_size
    header = _read_at(file_path, 0, min(file_size, 4096))
    if len(header) < 20:
        return UnitySerializedInfo(path=str(file_path), status="too_small", file_size=file_size)
    try:
        version = struct.unpack_from(">I", header, 8)[0]
        if version >= 22:
            if len(header) < 48:
                raise ValueError("serialized file v22 header too small")
            metadata_size = struct.unpack_from(">Q", header, 16)[0]
            declared_file_size = struct.unpack_from(">Q", header, 24)[0]
            data_offset = struct.unpack_from(">Q", header, 32)[0]
            endianness = "big" if header[40] else "little_or_unspecified"
            unity_version, metadata_cursor = _c_string(header, 48)
            metadata_offset = 48
        else:
            metadata_size = struct.unpack_from(">I", header, 0)[0]
            declared_file_size = struct.unpack_from(">I", header, 4)[0]
            data_offset = struct.unpack_from(">I", header, 12)[0]
            endianness = "big" if len(header) > 16 and header[16] else "little_or_unspecified"
            unity_version, metadata_cursor = _c_string(header, 20)
            metadata_offset = 20
        info = UnitySerializedInfo(
            path=str(file_path),
            status="parsed_header",
            file_size=file_size,
            format_version=version,
            unity_version=unity_version,
            metadata_size=int(metadata_size),
            declared_file_size=int(declared_file_size),
            data_offset=int(data_offset),
            endianness=endianness,
        )
        if metadata_size <= 0 or metadata_size > 512 * 1024 * 1024:
            return info
        metadata = _read_at(file_path, metadata_offset, min(int(metadata_size), max(0, file_size - metadata_offset)))
        metadata_cursor -= metadata_offset
        if metadata_cursor >= len(metadata):
            return info
        try:
            _parse_metadata(info, metadata, metadata_cursor, ">")
        except (struct.error, ValueError):
            _parse_metadata(info, metadata, metadata_cursor, "<")
        return info
    except (OSError, struct.error, ValueError) as exc:
        return UnitySerializedInfo(path=str(file_path), status="parse_error", file_size=file_size, error=str(exc))


def iter_unity_objects(path: str | Path) -> list[UnityObject]:
    return inspect_serialized_file(path).objects
