from __future__ import annotations


def decompress_lz4_block(data: bytes, expected_size: int | None = None) -> bytes:
    output = bytearray()
    cursor = 0
    data_len = len(data)
    while cursor < data_len:
        token = data[cursor]
        cursor += 1

        literal_len = token >> 4
        if literal_len == 15:
            while True:
                if cursor >= data_len:
                    raise ValueError("truncated lz4 literal length")
                value = data[cursor]
                cursor += 1
                literal_len += value
                if value != 255:
                    break
        if cursor + literal_len > data_len:
            raise ValueError("truncated lz4 literal payload")
        output.extend(data[cursor : cursor + literal_len])
        cursor += literal_len
        if cursor >= data_len:
            break

        if cursor + 2 > data_len:
            raise ValueError("truncated lz4 match offset")
        offset = data[cursor] | (data[cursor + 1] << 8)
        cursor += 2
        if offset == 0 or offset > len(output):
            raise ValueError("invalid lz4 match offset")

        match_len = token & 0x0F
        if match_len == 15:
            while True:
                if cursor >= data_len:
                    raise ValueError("truncated lz4 match length")
                value = data[cursor]
                cursor += 1
                match_len += value
                if value != 255:
                    break
        match_len += 4
        start = len(output) - offset
        for index in range(match_len):
            output.append(output[start + index])

    if expected_size is not None and len(output) != expected_size:
        raise ValueError(f"lz4 size mismatch: expected {expected_size}, got {len(output)}")
    return bytes(output)

