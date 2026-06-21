from __future__ import annotations

import io
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .formats import SUPPORTED_FORMATS, TEXT_EXTENSIONS, FormatSpec
from .models import EmbeddedCandidate, FileIdentification


@dataclass(frozen=True, slots=True)
class CandidateBounds:
    offset: int
    length: int | None
    confidence: float
    reason: str = ""


class Detector:
    type_name = "unknown"
    extension = ".bin"

    def identify(self, data: bytes, path: Path) -> FileIdentification | None:
        raise NotImplementedError

    def find_embedded(self, data: bytes, source_file: str) -> list[EmbeddedCandidate]:
        return []

    def extract_length(self, data: bytes, offset: int) -> int | None:
        return None

    def validate(self, data: bytes) -> bool:
        return False

    def candidate(self, source_file: str, bounds: CandidateBounds) -> EmbeddedCandidate:
        return EmbeddedCandidate(
            source_file=source_file,
            offset=bounds.offset,
            length=bounds.length,
            confidence=bounds.confidence,
            detected_type=self.type_name,
            extractable=bounds.length is not None,
            reason=bounds.reason,
        )


class PngDetector(Detector):
    type_name = "png"
    extension = ".png"
    signature = b"\x89PNG\r\n\x1a\n"

    def identify(self, data: bytes, path: Path) -> FileIdentification | None:
        if data.startswith(self.signature):
            confidence = 0.95 if self.validate(data) else 0.75
            return FileIdentification(str(path), self.type_name, confidence, path.suffix.lower(), data[:8].hex())
        return None

    def extract_length(self, data: bytes, offset: int) -> int | None:
        if not data.startswith(self.signature, offset):
            return None
        cursor = offset + len(self.signature)
        while cursor + 12 <= len(data):
            chunk_len = int.from_bytes(data[cursor : cursor + 4], "big")
            chunk_type = data[cursor + 4 : cursor + 8]
            next_cursor = cursor + 12 + chunk_len
            if next_cursor > len(data):
                return None
            cursor = next_cursor
            if chunk_type == b"IEND":
                return cursor - offset
        return None

    def find_embedded(self, data: bytes, source_file: str) -> list[EmbeddedCandidate]:
        candidates: list[EmbeddedCandidate] = []
        start = 0
        while True:
            offset = data.find(self.signature, start)
            if offset == -1:
                break
            length = self.extract_length(data, offset)
            reason = "" if length is not None else "png_iend_not_found_or_invalid"
            candidates.append(self.candidate(source_file, CandidateBounds(offset, length, 0.95, reason)))
            start = offset + 1
        return candidates

    def validate(self, data: bytes) -> bool:
        length = self.extract_length(data, 0)
        return length == len(data)


class GlbDetector(Detector):
    type_name = "glb"
    extension = ".glb"
    signature = b"glTF"

    def identify(self, data: bytes, path: Path) -> FileIdentification | None:
        if data.startswith(self.signature):
            confidence = 0.95 if self.validate(data) else 0.7
            return FileIdentification(str(path), self.type_name, confidence, path.suffix.lower(), data[:12].hex())
        return None

    def extract_length(self, data: bytes, offset: int) -> int | None:
        if offset + 12 > len(data) or not data.startswith(self.signature, offset):
            return None
        version, total_length = struct.unpack_from("<II", data, offset + 4)
        if version not in {1, 2}:
            return None
        if total_length < 12 or offset + total_length > len(data):
            return None
        return total_length

    def find_embedded(self, data: bytes, source_file: str) -> list[EmbeddedCandidate]:
        candidates: list[EmbeddedCandidate] = []
        start = 0
        while True:
            offset = data.find(self.signature, start)
            if offset == -1:
                break
            length = self.extract_length(data, offset)
            reason = "" if length is not None else "glb_length_untrusted"
            candidates.append(self.candidate(source_file, CandidateBounds(offset, length, 0.9, reason)))
            start = offset + 1
        return candidates

    def validate(self, data: bytes) -> bool:
        return self.extract_length(data, 0) == len(data)


class WavDetector(Detector):
    type_name = "wav"
    extension = ".wav"

    def identify(self, data: bytes, path: Path) -> FileIdentification | None:
        if data.startswith(b"RIFF") and data[8:12] == b"WAVE":
            confidence = 0.95 if self.validate(data) else 0.7
            return FileIdentification(str(path), self.type_name, confidence, path.suffix.lower(), data[:12].hex())
        return None

    def extract_length(self, data: bytes, offset: int) -> int | None:
        if offset + 12 > len(data) or not data.startswith(b"RIFF", offset) or data[offset + 8 : offset + 12] != b"WAVE":
            return None
        riff_size = struct.unpack_from("<I", data, offset + 4)[0]
        total = riff_size + 8
        if total < 12 or offset + total > len(data):
            return None
        return total

    def find_embedded(self, data: bytes, source_file: str) -> list[EmbeddedCandidate]:
        candidates: list[EmbeddedCandidate] = []
        start = 0
        while True:
            offset = data.find(b"RIFF", start)
            if offset == -1:
                break
            if data[offset + 8 : offset + 12] == b"WAVE":
                length = self.extract_length(data, offset)
                reason = "" if length is not None else "riff_size_untrusted"
                candidates.append(self.candidate(source_file, CandidateBounds(offset, length, 0.9, reason)))
            start = offset + 1
        return candidates

    def validate(self, data: bytes) -> bool:
        return self.extract_length(data, 0) == len(data)


class OggDetector(Detector):
    type_name = "ogg"
    extension = ".ogg"

    def identify(self, data: bytes, path: Path) -> FileIdentification | None:
        if data.startswith(b"OggS"):
            confidence = 0.9 if self.validate(data) else 0.65
            return FileIdentification(str(path), self.type_name, confidence, path.suffix.lower(), data[:8].hex())
        return None

    def _page_length(self, data: bytes, offset: int) -> tuple[int, bool] | None:
        if offset + 27 > len(data) or not data.startswith(b"OggS", offset):
            return None
        segment_count = data[offset + 26]
        segment_table_end = offset + 27 + segment_count
        if segment_table_end > len(data):
            return None
        body_size = sum(data[offset + 27 : segment_table_end])
        total = 27 + segment_count + body_size
        if offset + total > len(data):
            return None
        eos = bool(data[offset + 5] & 0x04)
        return total, eos

    def extract_length(self, data: bytes, offset: int) -> int | None:
        cursor = offset
        saw_page = False
        for _ in range(100000):
            parsed = self._page_length(data, cursor)
            if parsed is None:
                return None if not saw_page else cursor - offset
            page_len, eos = parsed
            saw_page = True
            cursor += page_len
            if eos:
                return cursor - offset
            if not data.startswith(b"OggS", cursor):
                return cursor - offset
        return None

    def find_embedded(self, data: bytes, source_file: str) -> list[EmbeddedCandidate]:
        candidates: list[EmbeddedCandidate] = []
        start = 0
        while True:
            offset = data.find(b"OggS", start)
            if offset == -1:
                break
            length = self.extract_length(data, offset)
            reason = "" if length is not None else "ogg_pages_untrusted"
            candidates.append(self.candidate(source_file, CandidateBounds(offset, length, 0.85, reason)))
            start = offset + 1
        return candidates

    def validate(self, data: bytes) -> bool:
        length = self.extract_length(data, 0)
        return length == len(data)


class ZipDetector(Detector):
    type_name = "zip"
    extension = ".zip"

    def identify(self, data: bytes, path: Path) -> FileIdentification | None:
        if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
            confidence = 0.95 if self.validate(data) else 0.65
            return FileIdentification(str(path), self.type_name, confidence, path.suffix.lower(), data[:8].hex())
        return None

    def extract_length(self, data: bytes, offset: int) -> int | None:
        if not data.startswith(b"PK", offset):
            return None
        eocd = data.find(b"PK\x05\x06", offset)
        while eocd != -1:
            if eocd + 22 <= len(data):
                comment_len = struct.unpack_from("<H", data, eocd + 20)[0]
                end = eocd + 22 + comment_len
                if end <= len(data):
                    candidate = data[offset:end]
                    if self.validate(candidate):
                        return len(candidate)
            eocd = data.find(b"PK\x05\x06", eocd + 1)
        return None

    def find_embedded(self, data: bytes, source_file: str) -> list[EmbeddedCandidate]:
        candidates: list[EmbeddedCandidate] = []
        start = 0
        while True:
            offset = data.find(b"PK\x03\x04", start)
            if offset == -1:
                break
            length = self.extract_length(data, offset)
            reason = "" if length is not None else "zip_eocd_not_found_or_invalid"
            candidates.append(self.candidate(source_file, CandidateBounds(offset, length, 0.9, reason)))
            start = offset + 1
        return candidates

    def validate(self, data: bytes) -> bool:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                return archive.testzip() is None
        except (zipfile.BadZipFile, OSError, ValueError, RuntimeError):
            return False


class JpegDetector(Detector):
    type_name = "jpg"
    extension = ".jpg"
    signature = b"\xff\xd8"

    def identify(self, data: bytes, path: Path) -> FileIdentification | None:
        if data.startswith(self.signature):
            confidence = 0.95 if self.validate(data) else 0.65
            return FileIdentification(str(path), self.type_name, confidence, path.suffix.lower(), data[:8].hex())
        return None

    def extract_length(self, data: bytes, offset: int) -> int | None:
        if offset + 4 > len(data) or not data.startswith(self.signature, offset):
            return None
        cursor = offset + 2
        while cursor < len(data):
            if data[cursor] != 0xFF:
                return None
            while cursor < len(data) and data[cursor] == 0xFF:
                cursor += 1
            if cursor >= len(data):
                return None
            marker = data[cursor]
            cursor += 1
            if marker == 0xD9:
                return cursor - offset
            if marker == 0xDA:
                if cursor + 2 > len(data):
                    return None
                segment_len = int.from_bytes(data[cursor : cursor + 2], "big")
                if segment_len < 2:
                    return None
                cursor += segment_len
                end = data.find(b"\xff\xd9", cursor)
                return None if end == -1 else end + 2 - offset
            if marker == 0x00 or 0xD0 <= marker <= 0xD8:
                continue
            if cursor + 2 > len(data):
                return None
            segment_len = int.from_bytes(data[cursor : cursor + 2], "big")
            if segment_len < 2:
                return None
            cursor += segment_len
        return None

    def find_embedded(self, data: bytes, source_file: str) -> list[EmbeddedCandidate]:
        candidates: list[EmbeddedCandidate] = []
        start = 0
        while True:
            offset = data.find(self.signature, start)
            if offset == -1:
                break
            length = self.extract_length(data, offset)
            reason = "" if length is not None else "jpeg_eoi_not_found_or_segments_invalid"
            candidates.append(self.candidate(source_file, CandidateBounds(offset, length, 0.9, reason)))
            start = offset + 1
        return candidates

    def validate(self, data: bytes) -> bool:
        return self.extract_length(data, 0) == len(data)


class DdsDetector(Detector):
    type_name = "dds"
    extension = ".dds"

    def identify(self, data: bytes, path: Path) -> FileIdentification | None:
        if data.startswith(b"DDS "):
            confidence = 0.9 if self.validate(data) else 0.55
            return FileIdentification(str(path), self.type_name, confidence, path.suffix.lower(), data[:8].hex())
        return None

    def extract_length(self, data: bytes, offset: int) -> int | None:
        if offset + 128 > len(data) or not data.startswith(b"DDS ", offset):
            return None
        if data[offset + 4 : offset + 8] != (124).to_bytes(4, "little"):
            return None
        height = struct.unpack_from("<I", data, offset + 12)[0]
        width = struct.unpack_from("<I", data, offset + 16)[0]
        depth = max(1, struct.unpack_from("<I", data, offset + 24)[0])
        mipmaps = max(1, struct.unpack_from("<I", data, offset + 28)[0])
        pixel_format_size = struct.unpack_from("<I", data, offset + 76)[0]
        flags = struct.unpack_from("<I", data, offset + 80)[0]
        fourcc = data[offset + 84 : offset + 88]
        rgb_bits = struct.unpack_from("<I", data, offset + 88)[0]
        caps2 = struct.unpack_from("<I", data, offset + 112)[0]
        if width == 0 or height == 0 or pixel_format_size != 32:
            return None
        header_size = 128
        block_bytes: int | None = None
        if flags & 0x4:
            if fourcc == b"DX10":
                if offset + 148 > len(data):
                    return None
                dxgi_format = struct.unpack_from("<I", data, offset + 128)[0]
                header_size = 148
                block_bytes = {
                    70: 8,
                    71: 8,
                    72: 8,
                    73: 16,
                    74: 16,
                    75: 16,
                    76: 16,
                    77: 16,
                    78: 16,
                    80: 8,
                    81: 8,
                    83: 16,
                    84: 16,
                    95: 16,
                    96: 16,
                    98: 16,
                    99: 16,
                }.get(dxgi_format)
            else:
                block_bytes = {
                    b"DXT1": 8,
                    b"BC1 ": 8,
                    b"DXT2": 16,
                    b"DXT3": 16,
                    b"DXT4": 16,
                    b"DXT5": 16,
                    b"ATI1": 8,
                    b"BC4U": 8,
                    b"BC4S": 8,
                    b"ATI2": 16,
                    b"BC5U": 16,
                    b"BC5S": 16,
                }.get(fourcc)
            if block_bytes is None:
                return None
        elif rgb_bits:
            block_bytes = None
        else:
            return None

        faces = 1
        if caps2 & 0x200:
            face_bits = [0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000]
            faces = max(1, sum(1 for bit in face_bits if caps2 & bit))
        total = 0
        for _face in range(faces):
            mip_width = width
            mip_height = height
            mip_depth = depth
            for _level in range(mipmaps):
                if flags & 0x4:
                    total += max(1, (mip_width + 3) // 4) * max(1, (mip_height + 3) // 4) * int(block_bytes)
                else:
                    row_bits = mip_width * rgb_bits
                    total += ((row_bits + 7) // 8) * mip_height * mip_depth
                mip_width = max(1, mip_width // 2)
                mip_height = max(1, mip_height // 2)
                mip_depth = max(1, mip_depth // 2)
        length = header_size + total
        if offset + length > len(data):
            return None
        return length

    def find_embedded(self, data: bytes, source_file: str) -> list[EmbeddedCandidate]:
        candidates: list[EmbeddedCandidate] = []
        start = 0
        while True:
            offset = data.find(b"DDS ", start)
            if offset == -1:
                break
            length = self.extract_length(data, offset)
            reason = "" if length is not None else "dds_payload_length_untrusted"
            candidates.append(self.candidate(source_file, CandidateBounds(offset, length, 0.85, reason)))
            start = offset + 1
        return candidates

    def validate(self, data: bytes) -> bool:
        return self.extract_length(data, 0) == len(data)


class TgaDetector(Detector):
    type_name = "tga"
    extension = ".tga"

    def identify(self, data: bytes, path: Path) -> FileIdentification | None:
        suffix = path.suffix.lower()
        if suffix != ".tga" and self.extract_length(data, 0) is None:
            return None
        confidence = 0.9 if self.validate(data) else 0.6
        return FileIdentification(str(path), self.type_name, confidence, suffix, data[:8].hex())

    def _rle_payload_end(self, data: bytes, cursor: int, pixel_count: int, bytes_per_pixel: int) -> int | None:
        written = 0
        while written < pixel_count and cursor < len(data):
            packet = data[cursor]
            cursor += 1
            count = (packet & 0x7F) + 1
            cursor += bytes_per_pixel if packet & 0x80 else count * bytes_per_pixel
            written += count
            if cursor > len(data):
                return None
        return cursor if written == pixel_count else None

    def extract_length(self, data: bytes, offset: int) -> int | None:
        if offset + 18 > len(data):
            return None
        header = data[offset : offset + 18]
        image_id_len = header[0]
        color_map_type = header[1]
        image_type = header[2]
        color_map_length = int.from_bytes(header[5:7], "little")
        color_map_entry_bits = header[7]
        width = int.from_bytes(header[12:14], "little")
        height = int.from_bytes(header[14:16], "little")
        pixel_depth = header[16]
        if color_map_type not in {0, 1} or image_type not in {1, 2, 3, 9, 10, 11}:
            return None
        if width == 0 or height == 0 or pixel_depth not in {8, 15, 16, 24, 32}:
            return None
        cursor = offset + 18 + image_id_len + color_map_length * ((color_map_entry_bits + 7) // 8)
        if cursor > len(data):
            return None
        bytes_per_pixel = (pixel_depth + 7) // 8
        pixel_count = width * height
        if image_type in {1, 2, 3}:
            cursor += pixel_count * bytes_per_pixel
        else:
            parsed_cursor = self._rle_payload_end(data, cursor, pixel_count, bytes_per_pixel)
            if parsed_cursor is None:
                return None
            cursor = parsed_cursor
        if cursor > len(data):
            return None
        if cursor + 26 <= len(data) and data[cursor + 8 : cursor + 26] == b"TRUEVISION-XFILE.\0":
            cursor += 26
        return cursor - offset

    def find_embedded(self, data: bytes, source_file: str) -> list[EmbeddedCandidate]:
        candidates: list[EmbeddedCandidate] = []
        start = 0
        while start + 18 <= len(data):
            length = self.extract_length(data, start)
            if length is not None:
                candidates.append(self.candidate(source_file, CandidateBounds(start, length, 0.65, "")))
                start += max(1, length)
            else:
                start += 1
        return candidates

    def validate(self, data: bytes) -> bool:
        return self.extract_length(data, 0) == len(data)


class FsbDetector(Detector):
    type_name = "fsb"
    extension = ".fsb"
    signature = b"FSB5"

    def identify(self, data: bytes, path: Path) -> FileIdentification | None:
        if data.startswith(self.signature):
            confidence = 0.95 if self.validate(data) else 0.7
            return FileIdentification(str(path), self.type_name, confidence, path.suffix.lower(), data[:8].hex())
        return None

    def extract_length(self, data: bytes, offset: int) -> int | None:
        if offset + 60 > len(data) or not data.startswith(self.signature, offset):
            return None
        version, sample_count, sample_headers_size, name_table_size, data_size, mode = struct.unpack_from("<6I", data, offset + 4)
        if version not in {0, 1} or sample_count > 1_000_000:
            return None
        _ = mode
        total = 60 + sample_headers_size + name_table_size + data_size
        if total < 60 or offset + total > len(data):
            return None
        return total

    def find_embedded(self, data: bytes, source_file: str) -> list[EmbeddedCandidate]:
        candidates: list[EmbeddedCandidate] = []
        start = 0
        while True:
            offset = data.find(self.signature, start)
            if offset == -1:
                break
            length = self.extract_length(data, offset)
            reason = "" if length is not None else "fsb5_length_untrusted"
            candidates.append(self.candidate(source_file, CandidateBounds(offset, length, 0.85, reason)))
            start = offset + 1
        return candidates

    def validate(self, data: bytes) -> bool:
        return self.extract_length(data, 0) == len(data)


class MoDetector(Detector):
    type_name = "mo"
    extension = ".mo"
    signatures = (b"\xde\x12\x04\x95", b"\x95\x04\x12\xde")

    def identify(self, data: bytes, path: Path) -> FileIdentification | None:
        if data[:4] in self.signatures:
            confidence = 0.95 if self.validate(data) else 0.65
            return FileIdentification(str(path), self.type_name, confidence, path.suffix.lower(), data[:8].hex())
        return None

    def extract_length(self, data: bytes, offset: int) -> int | None:
        if offset + 28 > len(data):
            return None
        magic = data[offset : offset + 4]
        endian = "<" if magic == b"\xde\x12\x04\x95" else ">" if magic == b"\x95\x04\x12\xde" else ""
        if not endian:
            return None
        _revision, count, original_offset, translated_offset, hash_size, hash_offset = struct.unpack_from(
            f"{endian}6I", data, offset + 4
        )
        if count > 1_000_000:
            return None
        tables_end = offset + max(original_offset + count * 8, translated_offset + count * 8)
        if tables_end > len(data):
            return None
        max_end = tables_end
        for table_offset in (original_offset, translated_offset):
            cursor = offset + table_offset
            for _ in range(count):
                length, string_offset = struct.unpack_from(f"{endian}2I", data, cursor)
                end = offset + string_offset + length
                if end > len(data):
                    return None
                max_end = max(max_end, end)
                cursor += 8
        if hash_size:
            hash_end = offset + hash_offset + hash_size * 4
            if hash_end > len(data):
                return None
            max_end = max(max_end, hash_end)
        return max_end - offset

    def find_embedded(self, data: bytes, source_file: str) -> list[EmbeddedCandidate]:
        candidates: list[EmbeddedCandidate] = []
        offsets = sorted({offset for signature in self.signatures for offset in _find_all(data, signature)})
        for offset in offsets:
            length = self.extract_length(data, offset)
            reason = "" if length is not None else "mo_tables_untrusted"
            candidates.append(self.candidate(source_file, CandidateBounds(offset, length, 0.8, reason)))
        return candidates

    def validate(self, data: bytes) -> bool:
        return self.extract_length(data, 0) == len(data)


class SfntDetector(Detector):
    def __init__(self, type_name: str, extension: str, signatures: tuple[bytes, ...]):
        self.type_name = type_name
        self.extension = extension
        self.signatures = signatures

    def identify(self, data: bytes, path: Path) -> FileIdentification | None:
        if data[:4] not in self.signatures:
            return None
        confidence = 0.95 if self.validate(data) else 0.7
        return FileIdentification(str(path), self.type_name, confidence, path.suffix.lower(), data[:8].hex())

    def extract_length(self, data: bytes, offset: int) -> int | None:
        if offset + 12 > len(data) or data[offset : offset + 4] not in self.signatures:
            return None
        table_count = struct.unpack_from(">H", data, offset + 4)[0]
        if table_count == 0 or table_count > 4096:
            return None
        directory_end = offset + 12 + table_count * 16
        if directory_end > len(data):
            return None
        max_end = directory_end
        for index in range(table_count):
            cursor = offset + 12 + index * 16
            table_offset = struct.unpack_from(">I", data, cursor + 8)[0]
            table_length = struct.unpack_from(">I", data, cursor + 12)[0]
            end = offset + table_offset + table_length
            if end > len(data):
                return None
            max_end = max(max_end, end)
        return max_end - offset

    def find_embedded(self, data: bytes, source_file: str) -> list[EmbeddedCandidate]:
        candidates: list[EmbeddedCandidate] = []
        offsets = sorted({offset for signature in self.signatures for offset in _find_all(data, signature)})
        for offset in offsets:
            length = self.extract_length(data, offset)
            reason = "" if length is not None else "sfnt_tables_untrusted"
            candidates.append(self.candidate(source_file, CandidateBounds(offset, length, 0.8, reason)))
        return candidates

    def validate(self, data: bytes) -> bool:
        return self.extract_length(data, 0) == len(data)


def _find_all(data: bytes, needle: bytes) -> list[int]:
    offsets: list[int] = []
    start = 0
    while True:
        offset = data.find(needle, start)
        if offset == -1:
            return offsets
        offsets.append(offset)
        start = offset + 1


def _read_uleb128(data: bytes, offset: int) -> tuple[int, int] | None:
    value = 0
    shift = 0
    cursor = offset
    for _ in range(5):
        if cursor >= len(data):
            return None
        byte = data[cursor]
        cursor += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, cursor
        shift += 7
    return None


class WasmDetector(Detector):
    type_name = "wasm"
    extension = ".wasm"
    signature = b"\0asm"

    def identify(self, data: bytes, path: Path) -> FileIdentification | None:
        if data.startswith(self.signature):
            confidence = 0.95 if self.validate(data) else 0.65
            return FileIdentification(str(path), self.type_name, confidence, path.suffix.lower(), data[:8].hex())
        return None

    def extract_length(self, data: bytes, offset: int) -> int | None:
        if offset + 8 > len(data) or not data.startswith(self.signature, offset) or data[offset + 4 : offset + 8] != b"\x01\0\0\0":
            return None
        cursor = offset + 8
        while cursor < len(data):
            section_id = data[cursor]
            if section_id > 12:
                return cursor - offset
            cursor += 1
            parsed = _read_uleb128(data, cursor)
            if parsed is None:
                return None
            payload_size, cursor = parsed
            next_cursor = cursor + payload_size
            if next_cursor > len(data):
                return None
            cursor = next_cursor
        return cursor - offset

    def find_embedded(self, data: bytes, source_file: str) -> list[EmbeddedCandidate]:
        candidates: list[EmbeddedCandidate] = []
        for offset in _find_all(data, self.signature):
            length = self.extract_length(data, offset)
            reason = "" if length is not None else "wasm_sections_untrusted"
            candidates.append(self.candidate(source_file, CandidateBounds(offset, length, 0.85, reason)))
        return candidates

    def validate(self, data: bytes) -> bool:
        return self.extract_length(data, 0) == len(data)


class ElfDetector(Detector):
    type_name = "so"
    extension = ".so"
    signature = b"\x7fELF"

    def identify(self, data: bytes, path: Path) -> FileIdentification | None:
        if data.startswith(self.signature):
            confidence = 0.9 if self.validate(data) else 0.65
            return FileIdentification(str(path), self.type_name, confidence, path.suffix.lower(), data[:8].hex())
        return None

    def extract_length(self, data: bytes, offset: int) -> int | None:
        if offset + 16 > len(data) or not data.startswith(self.signature, offset):
            return None
        elf_class = data[offset + 4]
        endian_marker = data[offset + 5]
        endian = "<" if endian_marker == 1 else ">" if endian_marker == 2 else ""
        if elf_class not in {1, 2} or not endian:
            return None
        if elf_class == 1:
            header_size = 52
            if offset + header_size > len(data):
                return None
            e_phoff, e_shoff = struct.unpack_from(f"{endian}II", data, offset + 28)
            e_phentsize, e_phnum, e_shentsize, e_shnum = struct.unpack_from(f"{endian}HHHH", data, offset + 42)
            program_file_size_offset = 16
            section_offset_offset = 16
            section_size_offset = 20
        else:
            header_size = 64
            if offset + header_size > len(data):
                return None
            e_phoff, e_shoff = struct.unpack_from(f"{endian}QQ", data, offset + 32)
            e_phentsize, e_phnum, e_shentsize, e_shnum = struct.unpack_from(f"{endian}HHHH", data, offset + 54)
            program_file_size_offset = 32
            section_offset_offset = 24
            section_size_offset = 32
        max_end = header_size
        if e_phoff:
            ph_end = e_phoff + e_phentsize * e_phnum
            if offset + ph_end > len(data):
                return None
            max_end = max(max_end, ph_end)
            for index in range(e_phnum):
                cursor = offset + e_phoff + index * e_phentsize
                if cursor + max(program_file_size_offset + 8, 24) > len(data):
                    return None
                if elf_class == 1:
                    p_offset, p_filesz = struct.unpack_from(f"{endian}II", data, cursor + 4)
                else:
                    p_offset = struct.unpack_from(f"{endian}Q", data, cursor + 8)[0]
                    p_filesz = struct.unpack_from(f"{endian}Q", data, cursor + program_file_size_offset)[0]
                max_end = max(max_end, p_offset + p_filesz)
        if e_shoff:
            sh_end = e_shoff + e_shentsize * e_shnum
            if offset + sh_end > len(data):
                return None
            max_end = max(max_end, sh_end)
            for index in range(e_shnum):
                cursor = offset + e_shoff + index * e_shentsize
                if cursor + section_size_offset + (8 if elf_class == 2 else 4) > len(data):
                    return None
                if elf_class == 1:
                    sh_offset = struct.unpack_from(f"{endian}I", data, cursor + section_offset_offset)[0]
                    sh_size = struct.unpack_from(f"{endian}I", data, cursor + section_size_offset)[0]
                else:
                    sh_offset = struct.unpack_from(f"{endian}Q", data, cursor + section_offset_offset)[0]
                    sh_size = struct.unpack_from(f"{endian}Q", data, cursor + section_size_offset)[0]
                max_end = max(max_end, sh_offset + sh_size)
        return max_end if offset + max_end <= len(data) else None

    def find_embedded(self, data: bytes, source_file: str) -> list[EmbeddedCandidate]:
        candidates: list[EmbeddedCandidate] = []
        for offset in _find_all(data, self.signature):
            length = self.extract_length(data, offset)
            reason = "" if length is not None else "elf_headers_untrusted"
            candidates.append(self.candidate(source_file, CandidateBounds(offset, length, 0.75, reason)))
        return candidates

    def validate(self, data: bytes) -> bool:
        return self.extract_length(data, 0) == len(data)


class PeDetector(Detector):
    type_name = "exe"
    extension = ".exe"
    signature = b"MZ"

    def identify(self, data: bytes, path: Path) -> FileIdentification | None:
        if not data.startswith(self.signature):
            return None
        detected_type = "dll" if path.suffix.lower() == ".dll" else "exe"
        confidence = 0.9 if self.validate(data) else 0.65
        return FileIdentification(str(path), detected_type, confidence, path.suffix.lower(), data[:8].hex(), "pe_header")

    def extract_length(self, data: bytes, offset: int) -> int | None:
        if offset + 0x40 > len(data) or not data.startswith(self.signature, offset):
            return None
        pe_offset = struct.unpack_from("<I", data, offset + 0x3C)[0]
        pe = offset + pe_offset
        if pe + 24 > len(data) or data[pe : pe + 4] != b"PE\0\0":
            return None
        section_count = struct.unpack_from("<H", data, pe + 6)[0]
        optional_size = struct.unpack_from("<H", data, pe + 20)[0]
        if section_count > 256:
            return None
        section_table = pe + 24 + optional_size
        section_table_size = section_count * 40
        if section_table + section_table_size > len(data):
            return None
        max_end = section_table + section_table_size - offset
        for index in range(section_count):
            cursor = section_table + index * 40
            raw_size = struct.unpack_from("<I", data, cursor + 16)[0]
            raw_pointer = struct.unpack_from("<I", data, cursor + 20)[0]
            if raw_size:
                max_end = max(max_end, raw_pointer + raw_size)
        return max_end if offset + max_end <= len(data) else None

    def find_embedded(self, data: bytes, source_file: str) -> list[EmbeddedCandidate]:
        candidates: list[EmbeddedCandidate] = []
        for offset in _find_all(data, self.signature):
            length = self.extract_length(data, offset)
            reason = "" if length is not None else "pe_sections_untrusted"
            candidates.append(self.candidate(source_file, CandidateBounds(offset, length, 0.75, reason)))
        return candidates

    def validate(self, data: bytes) -> bool:
        return self.extract_length(data, 0) == len(data)


class PdbDetector(Detector):
    type_name = "pdb"
    extension = ".pdb"
    signature = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"

    def identify(self, data: bytes, path: Path) -> FileIdentification | None:
        if data.startswith(self.signature):
            confidence = 0.9 if self.validate(data) else 0.65
            return FileIdentification(str(path), self.type_name, confidence, path.suffix.lower(), data[:8].hex())
        return None

    def extract_length(self, data: bytes, offset: int) -> int | None:
        if offset + 56 > len(data) or not data.startswith(self.signature, offset):
            return None
        block_size, block_count = struct.unpack_from("<II", data, offset + 32)[0], struct.unpack_from("<I", data, offset + 40)[0]
        if block_size not in {512, 1024, 2048, 4096} or block_count == 0:
            return None
        total = block_size * block_count
        return total if offset + total <= len(data) else None

    def find_embedded(self, data: bytes, source_file: str) -> list[EmbeddedCandidate]:
        candidates: list[EmbeddedCandidate] = []
        for offset in _find_all(data, self.signature):
            length = self.extract_length(data, offset)
            reason = "" if length is not None else "pdb_msf_superblock_untrusted"
            candidates.append(self.candidate(source_file, CandidateBounds(offset, length, 0.75, reason)))
        return candidates

    def validate(self, data: bytes) -> bool:
        return self.extract_length(data, 0) == len(data)


class BankDetector(Detector):
    type_name = "bank"
    extension = ".bank"
    signature = b"BKHD"

    def identify(self, data: bytes, path: Path) -> FileIdentification | None:
        if data.startswith(self.signature):
            confidence = 0.9 if self.validate(data) else 0.65
            return FileIdentification(str(path), self.type_name, confidence, path.suffix.lower(), data[:8].hex())
        return None

    def extract_length(self, data: bytes, offset: int) -> int | None:
        if offset + 8 > len(data) or not data.startswith(self.signature, offset):
            return None
        cursor = offset
        saw_chunk = False
        while cursor + 8 <= len(data):
            chunk_id = data[cursor : cursor + 4]
            if not chunk_id.isalpha():
                break
            chunk_size = struct.unpack_from("<I", data, cursor + 4)[0]
            next_cursor = cursor + 8 + chunk_size
            if next_cursor > len(data):
                return None
            saw_chunk = True
            cursor = next_cursor
        return cursor - offset if saw_chunk else None

    def find_embedded(self, data: bytes, source_file: str) -> list[EmbeddedCandidate]:
        candidates: list[EmbeddedCandidate] = []
        for offset in _find_all(data, self.signature):
            length = self.extract_length(data, offset)
            reason = "" if length is not None else "wwise_bank_chunks_untrusted"
            candidates.append(self.candidate(source_file, CandidateBounds(offset, length, 0.75, reason)))
        return candidates

    def validate(self, data: bytes) -> bool:
        return self.extract_length(data, 0) == len(data)


class FbxDetector(Detector):
    type_name = "fbx"
    extension = ".fbx"
    binary_signature = b"Kaydara FBX Binary  \x00\x1a\x00"

    def identify(self, data: bytes, path: Path) -> FileIdentification | None:
        suffix = path.suffix.lower()
        if data.startswith(self.binary_signature):
            confidence = 0.9 if self.validate(data) else 0.7
            return FileIdentification(str(path), self.type_name, confidence, suffix, data[:8].hex(), "fbx_binary_header")
        if suffix == ".fbx" and _is_text_decodable(data):
            text = data[:4096].decode("utf-8", errors="ignore")
            confidence = 0.85 if "; FBX" in text or "FBXHeaderExtension" in text else 0.75
            return FileIdentification(str(path), self.type_name, confidence, suffix, data[:8].hex(), "fbx_text")
        return None

    def validate(self, data: bytes) -> bool:
        if data.startswith(self.binary_signature):
            return len(data) >= len(self.binary_signature) + 4
        return _is_text_decodable(data)


class UnrealPackageDetector(Detector):
    type_name = "uasset"
    extension = ".uasset"
    signature = b"\xc1\x83\x2a\x9e"

    def identify(self, data: bytes, path: Path) -> FileIdentification | None:
        suffix = path.suffix.lower()
        if suffix not in {".uasset", ".umap"} and not data.startswith(self.signature):
            return None
        detected_type = "umap" if suffix == ".umap" else "uasset"
        if data.startswith(self.signature):
            confidence = 0.9 if self.validate(data) else 0.75
            return FileIdentification(str(path), detected_type, confidence, suffix, data[:8].hex(), "unreal_package_header")
        return FileIdentification(str(path), detected_type, 0.7, suffix, data[:8].hex(), "unreal_package_extension")

    def validate(self, data: bytes) -> bool:
        return len(data) >= 32 and data.startswith(self.signature)


class RpfDetector(Detector):
    type_name = "rpf"
    extension = ".rpf"
    signatures = (b"RPF0", b"RPF2", b"RPF3", b"RPF4", b"RPF6", b"RPF7")

    def identify(self, data: bytes, path: Path) -> FileIdentification | None:
        suffix = path.suffix.lower()
        if data[:4] in self.signatures:
            confidence = 0.9 if self.validate(data) else 0.7
            return FileIdentification(str(path), self.type_name, confidence, suffix, data[:8].hex(), "rpf_header")
        if suffix == ".rpf":
            return FileIdentification(str(path), self.type_name, 0.65, suffix, data[:8].hex(), "rpf_extension")
        return None

    def validate(self, data: bytes) -> bool:
        return len(data) >= 16 and data[:4] in self.signatures


class KtxDetector(Detector):
    type_name = "ktx"
    extension = ".ktx"
    signature = b"\xabKTX 11\xbb\r\n\x1a\n"

    def identify(self, data: bytes, path: Path) -> FileIdentification | None:
        if data.startswith(self.signature):
            confidence = 0.9 if self.validate(data) else 0.65
            return FileIdentification(str(path), self.type_name, confidence, path.suffix.lower(), data[:12].hex())
        return None

    def extract_length(self, data: bytes, offset: int) -> int | None:
        if offset + 64 > len(data) or not data.startswith(self.signature, offset):
            return None
        endianness = data[offset + 12 : offset + 16]
        endian = "<" if endianness == b"\x04\x03\x02\x01" else ">" if endianness == b"\x01\x02\x03\x04" else None
        if endian is None:
            return None
        values = struct.unpack_from(f"{endian}12I", data, offset + 16)
        number_of_faces = values[9] or 1
        number_of_mipmap_levels = values[10] or 1
        bytes_of_key_value_data = values[11]
        cursor = offset + 64 + bytes_of_key_value_data
        for _ in range(number_of_mipmap_levels):
            if cursor + 4 > len(data):
                return None
            image_size = struct.unpack_from(f"{endian}I", data, cursor)[0]
            cursor += 4
            face_size_padded = (image_size + 3) & ~3
            cursor += face_size_padded * number_of_faces
            if cursor > len(data):
                return None
        return cursor - offset

    def find_embedded(self, data: bytes, source_file: str) -> list[EmbeddedCandidate]:
        candidates: list[EmbeddedCandidate] = []
        start = 0
        while True:
            offset = data.find(self.signature, start)
            if offset == -1:
                break
            length = self.extract_length(data, offset)
            reason = "" if length is not None else "ktx_length_untrusted"
            candidates.append(self.candidate(source_file, CandidateBounds(offset, length, 0.85, reason)))
            start = offset + 1
        return candidates

    def validate(self, data: bytes) -> bool:
        return self.extract_length(data, 0) == len(data)


def _is_text_decodable(data: bytes) -> bool:
    for encoding in ("utf-8", "utf-16"):
        try:
            data.decode(encoding)
            return True
        except UnicodeDecodeError:
            continue
    return False


class ExtensionDetector(Detector):
    def __init__(self, spec: FormatSpec):
        self.spec = spec
        self.type_name = spec.type_name
        self.extension = spec.primary_extension

    def identify(self, data: bytes, path: Path) -> FileIdentification | None:
        suffix = path.suffix.lower()
        if suffix not in self.spec.extensions:
            return None
        if self.spec.text:
            text_valid = _is_text_decodable(data)
            confidence = 0.8 if text_valid else 0.6
            status = "extension_supported_text" if text_valid else "extension_supported_unverified_text"
        else:
            confidence = 0.7
            status = "extension_supported"
        return FileIdentification(str(path), self.type_name, confidence, suffix, data[:8].hex(), status)

    def validate(self, data: bytes) -> bool:
        return _is_text_decodable(data) if self.spec.text else False


class TextScriptDetector(Detector):
    type_name = "script_text"
    extension = ".txt"

    def __init__(self, text_extensions: Iterable[str] = TEXT_EXTENSIONS):
        self.script_extensions = frozenset(text_extensions) | {".js", ".py", ".as", ".rpy", ".bat", ".cmd", ".ps1", ".txt"}

    def identify(self, data: bytes, path: Path) -> FileIdentification | None:
        suffix = path.suffix.lower()
        if suffix not in self.script_extensions:
            return None
        if not _is_text_decodable(data):
            return None
        return FileIdentification(str(path), self.type_name, 0.75, suffix, data[:8].hex(), "recoverable_text")

    def find_embedded(self, data: bytes, source_file: str) -> list[EmbeddedCandidate]:
        candidates: list[EmbeddedCandidate] = []
        start: int | None = None
        for index, byte in enumerate(data):
            is_text = byte in (9, 10, 13) or 32 <= byte <= 126
            if is_text and start is None:
                start = index
            if (not is_text or index == len(data) - 1) and start is not None:
                end = index + 1 if is_text and index == len(data) - 1 else index
                length = end - start
                if length >= 128:
                    candidates.append(
                        self.candidate(
                            source_file,
                            CandidateBounds(start, length, 0.55, "clear_text_run"),
                        )
                    )
                start = None
        return candidates

    def extract_length(self, data: bytes, offset: int) -> int | None:
        return None

    def validate(self, data: bytes) -> bool:
        try:
            data.decode("utf-8")
            return True
        except UnicodeDecodeError:
            return False


def build_builtin_detectors(format_specs: Iterable[FormatSpec] = SUPPORTED_FORMATS) -> list[Detector]:
    specs = tuple(format_specs)
    text_extensions = frozenset(extension for spec in specs if spec.text for extension in spec.extensions)
    return [
        PngDetector(),
        GlbDetector(),
        WavDetector(),
        OggDetector(),
        ZipDetector(),
        JpegDetector(),
        DdsDetector(),
        TgaDetector(),
        FsbDetector(),
        MoDetector(),
        SfntDetector("ttf", ".ttf", (b"\x00\x01\x00\x00", b"true", b"typ1")),
        SfntDetector("otf", ".otf", (b"OTTO",)),
        WasmDetector(),
        ElfDetector(),
        PeDetector(),
        PdbDetector(),
        BankDetector(),
        FbxDetector(),
        UnrealPackageDetector(),
        RpfDetector(),
        KtxDetector(),
        *(ExtensionDetector(spec) for spec in specs),
        TextScriptDetector(text_extensions),
    ]


DETECTORS: list[Detector] = build_builtin_detectors(SUPPORTED_FORMATS)
