from __future__ import annotations

import struct

from .classification import classify_asset
from .models import EmbeddedCandidate, ScanOptions
from .resources import ByteSource

SIGNATURES: dict[str, bytes] = {
    "png": b"\x89PNG\r\n\x1a\n",
    "glb": b"glTF",
    "wav": b"RIFF",
    "ogg": b"OggS",
    "ktx": b"\xabKTX 11\xbb\r\n\x1a\n",
    "zip": b"PK\x03\x04",
    "jpg": b"\xff\xd8",
    "dds": b"DDS ",
    "fsb": b"FSB5",
    "mo": b"\xde\x12\x04\x95",
    "mo_be": b"\x95\x04\x12\xde",
    "ttf": b"\x00\x01\x00\x00",
    "otf": b"OTTO",
    "wasm": b"\0asm",
    "so": b"\x7fELF",
    "exe": b"MZ",
    "pdb": b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0",
    "bank": b"BKHD",
}


def _candidate(
    source_file: str,
    offset: int,
    length: int | None,
    confidence: float,
    detected_type: str,
    reason: str = "",
) -> EmbeddedCandidate:
    classification = classify_asset(f"asset.{detected_type}", detected_type)
    return EmbeddedCandidate(
        source_file=source_file,
        offset=offset,
        length=length,
        confidence=confidence,
        detected_type=detected_type,
        extractable=length is not None,
        reason=reason,
        category=classification["category"],
        decompile_value=classification["decompile_value"],
    )


def _png_length(source: ByteSource, offset: int) -> int | None:
    if source.read_at(offset, 8) != SIGNATURES["png"]:
        return None
    cursor = offset + 8
    while cursor + 12 <= source.size:
        header = source.read_at(cursor, 8)
        if len(header) != 8:
            return None
        chunk_len = int.from_bytes(header[:4], "big")
        chunk_type = header[4:8]
        if chunk_len < 0:
            return None
        next_cursor = cursor + 12 + chunk_len
        if next_cursor > source.size:
            return None
        cursor = next_cursor
        if chunk_type == b"IEND":
            return cursor - offset
    return None


def _glb_length(source: ByteSource, offset: int) -> int | None:
    header = source.read_at(offset, 12)
    if len(header) != 12 or not header.startswith(b"glTF"):
        return None
    version, total_length = struct.unpack_from("<II", header, 4)
    if version not in {1, 2} or total_length < 12:
        return None
    if offset + total_length > source.size:
        return None
    return total_length


def _wav_length(source: ByteSource, offset: int) -> int | None:
    header = source.read_at(offset, 12)
    if len(header) != 12 or not header.startswith(b"RIFF") or header[8:12] != b"WAVE":
        return None
    riff_size = struct.unpack_from("<I", header, 4)[0]
    total = riff_size + 8
    if total < 12 or offset + total > source.size:
        return None
    return total


def _ogg_page_length(source: ByteSource, offset: int) -> tuple[int, bool] | None:
    header = source.read_at(offset, 27)
    if len(header) != 27 or not header.startswith(b"OggS"):
        return None
    segment_count = header[26]
    table = source.read_at(offset + 27, segment_count)
    if len(table) != segment_count:
        return None
    body_size = sum(table)
    total = 27 + segment_count + body_size
    if offset + total > source.size:
        return None
    eos = bool(header[5] & 0x04)
    return total, eos


def _ogg_length(source: ByteSource, offset: int) -> int | None:
    cursor = offset
    saw_page = False
    for _ in range(100000):
        parsed = _ogg_page_length(source, cursor)
        if parsed is None:
            return None if not saw_page else cursor - offset
        page_len, eos = parsed
        saw_page = True
        cursor += page_len
        if eos:
            return cursor - offset
        if source.read_at(cursor, 4) != b"OggS":
            return cursor - offset
    return None


def _ktx_length(source: ByteSource, offset: int) -> int | None:
    header = source.read_at(offset, 64)
    if len(header) != 64 or not header.startswith(SIGNATURES["ktx"]):
        return None
    endianness = header[12:16]
    endian = "<" if endianness == b"\x04\x03\x02\x01" else ">" if endianness == b"\x01\x02\x03\x04" else None
    if endian is None:
        return None
    values = struct.unpack_from(f"{endian}12I", header, 16)
    number_of_faces = values[9] or 1
    number_of_mipmap_levels = values[10] or 1
    bytes_of_key_value_data = values[11]
    cursor = offset + 64 + bytes_of_key_value_data
    for _ in range(number_of_mipmap_levels):
        image_size_data = source.read_at(cursor, 4)
        if len(image_size_data) != 4:
            return None
        image_size = struct.unpack(f"{endian}I", image_size_data)[0]
        cursor += 4
        cursor += ((image_size + 3) & ~3) * number_of_faces
        if cursor > source.size:
            return None
    return cursor - offset


def _jpeg_length(source: ByteSource, offset: int) -> int | None:
    if source.read_at(offset, 2) != SIGNATURES["jpg"]:
        return None
    cursor = offset + 2
    while cursor < source.size:
        marker_start = source.read_at(cursor, 1)
        if marker_start != b"\xff":
            return None
        while source.read_at(cursor, 1) == b"\xff":
            cursor += 1
        marker = source.read_at(cursor, 1)
        if len(marker) != 1:
            return None
        marker_byte = marker[0]
        cursor += 1
        if marker_byte == 0xD9:
            return cursor - offset
        if marker_byte == 0xDA:
            raw_len = source.read_at(cursor, 2)
            if len(raw_len) != 2:
                return None
            segment_len = int.from_bytes(raw_len, "big")
            if segment_len < 2:
                return None
            cursor += segment_len
            overlap = b""
            while cursor < source.size:
                chunk = source.read_at(cursor, 65536)
                if not chunk:
                    return None
                found = (overlap + chunk).find(b"\xff\xd9")
                if found != -1:
                    return cursor - len(overlap) + found + 2 - offset
                overlap = chunk[-1:]
                cursor += len(chunk)
            return None
        if marker_byte == 0x00 or 0xD0 <= marker_byte <= 0xD8:
            continue
        raw_len = source.read_at(cursor, 2)
        if len(raw_len) != 2:
            return None
        segment_len = int.from_bytes(raw_len, "big")
        if segment_len < 2:
            return None
        cursor += segment_len
    return None


def _dds_length(source: ByteSource, offset: int) -> int | None:
    header = source.read_at(offset, 148)
    if len(header) < 128 or not header.startswith(b"DDS ") or header[4:8] != (124).to_bytes(4, "little"):
        return None
    height = struct.unpack_from("<I", header, 12)[0]
    width = struct.unpack_from("<I", header, 16)[0]
    depth = max(1, struct.unpack_from("<I", header, 24)[0])
    mipmaps = max(1, struct.unpack_from("<I", header, 28)[0])
    pixel_format_size = struct.unpack_from("<I", header, 76)[0]
    flags = struct.unpack_from("<I", header, 80)[0]
    fourcc = header[84:88]
    rgb_bits = struct.unpack_from("<I", header, 88)[0]
    caps2 = struct.unpack_from("<I", header, 112)[0]
    if width == 0 or height == 0 or pixel_format_size != 32:
        return None
    header_size = 128
    block_bytes: int | None = None
    if flags & 0x4:
        if fourcc == b"DX10":
            if len(header) < 148:
                return None
            header_size = 148
            block_bytes = {70: 8, 71: 8, 72: 8, 73: 16, 74: 16, 75: 16, 76: 16, 77: 16, 78: 16}.get(
                struct.unpack_from("<I", header, 128)[0]
            )
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
    elif not rgb_bits:
        return None
    faces = 1
    if caps2 & 0x200:
        faces = max(1, sum(1 for bit in (0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000) if caps2 & bit))
    total = 0
    for _face in range(faces):
        mip_width = width
        mip_height = height
        mip_depth = depth
        for _level in range(mipmaps):
            if flags & 0x4:
                total += max(1, (mip_width + 3) // 4) * max(1, (mip_height + 3) // 4) * int(block_bytes)
            else:
                total += (((mip_width * rgb_bits) + 7) // 8) * mip_height * mip_depth
            mip_width = max(1, mip_width // 2)
            mip_height = max(1, mip_height // 2)
            mip_depth = max(1, mip_depth // 2)
    length = header_size + total
    return length if offset + length <= source.size else None


def _fsb_length(source: ByteSource, offset: int) -> int | None:
    header = source.read_at(offset, 60)
    if len(header) != 60 or not header.startswith(b"FSB5"):
        return None
    version, sample_count, sample_headers_size, name_table_size, data_size, _mode = struct.unpack_from("<6I", header, 4)
    if version not in {0, 1} or sample_count > 1_000_000:
        return None
    total = 60 + sample_headers_size + name_table_size + data_size
    return total if offset + total <= source.size else None


def _mo_length(source: ByteSource, offset: int, endian: str) -> int | None:
    header = source.read_at(offset, 28)
    if len(header) != 28:
        return None
    _revision, count, original_offset, translated_offset, hash_size, hash_offset = struct.unpack_from(f"{endian}6I", header, 4)
    if count > 1_000_000:
        return None
    tables_end = offset + max(original_offset + count * 8, translated_offset + count * 8)
    if tables_end > source.size:
        return None
    max_end = tables_end
    for table_offset in (original_offset, translated_offset):
        table = source.read_at(offset + table_offset, count * 8)
        if len(table) != count * 8:
            return None
        for index in range(count):
            length, string_offset = struct.unpack_from(f"{endian}2I", table, index * 8)
            end = offset + string_offset + length
            if end > source.size:
                return None
            max_end = max(max_end, end)
    if hash_size:
        hash_end = offset + hash_offset + hash_size * 4
        if hash_end > source.size:
            return None
        max_end = max(max_end, hash_end)
    return max_end - offset


def _sfnt_length(source: ByteSource, offset: int, signature: bytes) -> int | None:
    header = source.read_at(offset, 12)
    if len(header) != 12 or not header.startswith(signature):
        return None
    table_count = struct.unpack_from(">H", header, 4)[0]
    if table_count == 0 or table_count > 4096:
        return None
    directory = source.read_at(offset + 12, table_count * 16)
    if len(directory) != table_count * 16:
        return None
    max_end = 12 + table_count * 16
    for index in range(table_count):
        cursor = index * 16
        table_offset = struct.unpack_from(">I", directory, cursor + 8)[0]
        table_length = struct.unpack_from(">I", directory, cursor + 12)[0]
        end = table_offset + table_length
        if offset + end > source.size:
            return None
        max_end = max(max_end, end)
    return max_end


def _read_uleb128_from_source(source: ByteSource, offset: int) -> tuple[int, int] | None:
    value = 0
    shift = 0
    cursor = offset
    for _ in range(5):
        raw = source.read_at(cursor, 1)
        if len(raw) != 1:
            return None
        byte = raw[0]
        cursor += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, cursor
        shift += 7
    return None


def _wasm_length(source: ByteSource, offset: int) -> int | None:
    header = source.read_at(offset, 8)
    if header != b"\0asm\x01\0\0\0":
        return None
    cursor = offset + 8
    while cursor < source.size:
        raw_id = source.read_at(cursor, 1)
        if len(raw_id) != 1:
            return None
        section_id = raw_id[0]
        if section_id > 12:
            return cursor - offset
        cursor += 1
        parsed = _read_uleb128_from_source(source, cursor)
        if parsed is None:
            return None
        payload_size, cursor = parsed
        cursor += payload_size
        if cursor > source.size:
            return None
    return cursor - offset


def _elf_length(source: ByteSource, offset: int) -> int | None:
    header = source.read_at(offset, 64)
    if len(header) < 16 or not header.startswith(b"\x7fELF"):
        return None
    elf_class = header[4]
    endian_marker = header[5]
    endian = "<" if endian_marker == 1 else ">" if endian_marker == 2 else ""
    if elf_class not in {1, 2} or not endian:
        return None
    if elf_class == 1:
        if len(header) < 52:
            return None
        e_phoff, e_shoff = struct.unpack_from(f"{endian}II", header, 28)
        e_phentsize, e_phnum, e_shentsize, e_shnum = struct.unpack_from(f"{endian}HHHH", header, 42)
        header_size = 52
    else:
        if len(header) < 64:
            return None
        e_phoff, e_shoff = struct.unpack_from(f"{endian}QQ", header, 32)
        e_phentsize, e_phnum, e_shentsize, e_shnum = struct.unpack_from(f"{endian}HHHH", header, 54)
        header_size = 64
    max_end = header_size
    if e_phoff:
        ph = source.read_at(offset + e_phoff, e_phentsize * e_phnum)
        if len(ph) != e_phentsize * e_phnum:
            return None
        max_end = max(max_end, e_phoff + e_phentsize * e_phnum)
        for index in range(e_phnum):
            cursor = index * e_phentsize
            if elf_class == 1:
                p_offset, p_filesz = struct.unpack_from(f"{endian}II", ph, cursor + 4)
            else:
                p_offset = struct.unpack_from(f"{endian}Q", ph, cursor + 8)[0]
                p_filesz = struct.unpack_from(f"{endian}Q", ph, cursor + 32)[0]
            max_end = max(max_end, p_offset + p_filesz)
    if e_shoff:
        sh = source.read_at(offset + e_shoff, e_shentsize * e_shnum)
        if len(sh) != e_shentsize * e_shnum:
            return None
        max_end = max(max_end, e_shoff + e_shentsize * e_shnum)
        for index in range(e_shnum):
            cursor = index * e_shentsize
            if elf_class == 1:
                sh_offset = struct.unpack_from(f"{endian}I", sh, cursor + 16)[0]
                sh_size = struct.unpack_from(f"{endian}I", sh, cursor + 20)[0]
            else:
                sh_offset = struct.unpack_from(f"{endian}Q", sh, cursor + 24)[0]
                sh_size = struct.unpack_from(f"{endian}Q", sh, cursor + 32)[0]
            max_end = max(max_end, sh_offset + sh_size)
    return max_end if offset + max_end <= source.size else None


def _pdb_length(source: ByteSource, offset: int) -> int | None:
    header = source.read_at(offset, 56)
    if len(header) != 56 or not header.startswith(SIGNATURES["pdb"]):
        return None
    block_size = struct.unpack_from("<I", header, 32)[0]
    block_count = struct.unpack_from("<I", header, 40)[0]
    if block_size not in {512, 1024, 2048, 4096} or block_count == 0:
        return None
    total = block_size * block_count
    return total if offset + total <= source.size else None


def _pe_length(source: ByteSource, offset: int) -> int | None:
    dos = source.read_at(offset, 0x40)
    if len(dos) != 0x40 or not dos.startswith(b"MZ"):
        return None
    pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
    pe_header = source.read_at(offset + pe_offset, 24)
    if len(pe_header) != 24 or pe_header[:4] != b"PE\0\0":
        return None
    section_count = struct.unpack_from("<H", pe_header, 6)[0]
    optional_size = struct.unpack_from("<H", pe_header, 20)[0]
    if section_count > 256:
        return None
    section_table_offset = offset + pe_offset + 24 + optional_size
    section_table = source.read_at(section_table_offset, section_count * 40)
    if len(section_table) != section_count * 40:
        return None
    max_end = pe_offset + 24 + optional_size + section_count * 40
    for index in range(section_count):
        cursor = index * 40
        raw_size = struct.unpack_from("<I", section_table, cursor + 16)[0]
        raw_pointer = struct.unpack_from("<I", section_table, cursor + 20)[0]
        if raw_size:
            max_end = max(max_end, raw_pointer + raw_size)
    return max_end if offset + max_end <= source.size else None


def _bank_length(source: ByteSource, offset: int) -> int | None:
    if source.read_at(offset, 4) != b"BKHD":
        return None
    cursor = offset
    saw_chunk = False
    while cursor + 8 <= source.size:
        header = source.read_at(cursor, 8)
        if len(header) != 8 or not header[:4].isalpha():
            break
        chunk_size = struct.unpack_from("<I", header, 4)[0]
        cursor += 8 + chunk_size
        if cursor > source.size:
            return None
        saw_chunk = True
    return cursor - offset if saw_chunk else None


def _length_for(source: ByteSource, offset: int, detected_type: str) -> tuple[int | None, str]:
    if detected_type == "png":
        length = _png_length(source, offset)
        return length, "" if length is not None else "png_iend_not_found_or_invalid"
    if detected_type == "glb":
        length = _glb_length(source, offset)
        return length, "" if length is not None else "glb_length_untrusted"
    if detected_type == "wav":
        length = _wav_length(source, offset)
        return length, "" if length is not None else "riff_size_untrusted"
    if detected_type == "ogg":
        length = _ogg_length(source, offset)
        return length, "" if length is not None else "ogg_pages_untrusted"
    if detected_type == "ktx":
        length = _ktx_length(source, offset)
        return length, "" if length is not None else "ktx_length_untrusted"
    if detected_type == "zip":
        return None, "zip_embedded_scan_limited_for_large_file"
    if detected_type == "jpg":
        length = _jpeg_length(source, offset)
        return length, "" if length is not None else "jpeg_eoi_not_found_or_segments_invalid"
    if detected_type == "dds":
        length = _dds_length(source, offset)
        return length, "" if length is not None else "dds_payload_length_untrusted"
    if detected_type == "fsb":
        length = _fsb_length(source, offset)
        return length, "" if length is not None else "fsb5_length_untrusted"
    if detected_type == "mo":
        length = _mo_length(source, offset, "<")
        return length, "" if length is not None else "mo_tables_untrusted"
    if detected_type == "mo_be":
        length = _mo_length(source, offset, ">")
        return length, "" if length is not None else "mo_tables_untrusted"
    if detected_type == "ttf":
        length = _sfnt_length(source, offset, SIGNATURES["ttf"])
        return length, "" if length is not None else "sfnt_tables_untrusted"
    if detected_type == "otf":
        length = _sfnt_length(source, offset, SIGNATURES["otf"])
        return length, "" if length is not None else "sfnt_tables_untrusted"
    if detected_type == "wasm":
        length = _wasm_length(source, offset)
        return length, "" if length is not None else "wasm_sections_untrusted"
    if detected_type == "so":
        length = _elf_length(source, offset)
        return length, "" if length is not None else "elf_headers_untrusted"
    if detected_type == "pdb":
        length = _pdb_length(source, offset)
        return length, "" if length is not None else "pdb_msf_superblock_untrusted"
    if detected_type == "exe":
        length = _pe_length(source, offset)
        return length, "" if length is not None else "pe_sections_untrusted"
    if detected_type == "bank":
        length = _bank_length(source, offset)
        return length, "" if length is not None else "wwise_bank_chunks_untrusted"
    return None, "unsupported_streaming_signature"


def scan_embedded_streaming(path: str, options: ScanOptions) -> list[EmbeddedCandidate]:
    source = ByteSource(path, options.stream_chunk_size)
    overlap_size = max(len(signature) for signature in SIGNATURES.values()) - 1
    candidates: list[EmbeddedCandidate] = []
    seen: set[tuple[str, int]] = set()
    overlap = b""

    for chunk_offset, chunk in source.iter_chunks():
        data = overlap + chunk
        base_offset = chunk_offset - len(overlap)
        for detected_type, signature in SIGNATURES.items():
            candidate_type = "mo" if detected_type == "mo_be" else detected_type
            start = 0
            while True:
                found = data.find(signature, start)
                if found == -1:
                    break
                absolute = base_offset + found
                key = (candidate_type, absolute)
                if absolute >= 0 and key not in seen:
                    seen.add(key)
                    length, reason = _length_for(source, absolute, detected_type)
                    confidence = 0.9 if length is not None else 0.55
                    candidates.append(_candidate(path, absolute, length, confidence, candidate_type, reason))
                start = found + 1
        overlap = data[-overlap_size:] if overlap_size else b""
    return candidates
