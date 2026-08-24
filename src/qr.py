"""
A QR code encoder, in the standard library and nothing else.

Written rather than depended on: this project takes a new runtime dependency
only when there is no alternative, and a QR encoder is a few hundred lines of
well-specified arithmetic (ISO/IEC 18004). A package that renders a join ticket
is not worth another name in the supply chain.

Scope is deliberately narrow — what a join ticket needs and no more:

* versions 1 to 10 (21×21 to 57×57 modules),
* error correction level M, and level L when a payload will not otherwise fit,
* alphanumeric mode, and byte mode for anything outside its 45-character set.

The smallest version that fits is chosen automatically. A join ticket is 34
uppercase base32 characters, which is alphanumeric mode and lands in version 2.

Numeric mode is deliberately absent: an all-digit payload encodes here in
alphanumeric mode instead, which is a few modules larger and reads back exactly
the same. Adding a fourth mode to save space on input this encoder never
receives would be code with no reader.

Verified against an independent encoder (identical matrices, module for module,
same version and mask) and against a real decoder — see `tests/test_qr.py`,
which runs those checks whenever the optional tooling is installed.
"""
from __future__ import annotations

_ALPHANUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
_ALPHANUM_INDEX = {char: index for index, char in enumerate(_ALPHANUM)}

# Data codewords available per version, for levels L and M.
_DATA_CODEWORDS = {
    #        L    M
    1:     (19,  16),
    2:     (34,  28),
    3:     (55,  44),
    4:     (80,  64),
    5:    (108,  86),
    6:    (136, 108),
    7:    (156, 124),
    8:    (194, 154),
    9:    (232, 182),
    10:   (274, 216),
}

# (ec codewords per block, blocks in group 1, blocks in group 2) per version.
# Group 2's blocks each hold one more data codeword than group 1's.
_EC_BLOCKS = {
    "L": {1: (7, 1, 0), 2: (10, 1, 0), 3: (15, 1, 0), 4: (20, 1, 0),
          5: (26, 1, 0), 6: (18, 2, 0), 7: (20, 2, 0), 8: (24, 2, 0),
          9: (30, 2, 0), 10: (18, 2, 2)},
    "M": {1: (10, 1, 0), 2: (16, 1, 0), 3: (26, 1, 0), 4: (18, 2, 0),
          5: (24, 2, 0), 6: (16, 4, 0), 7: (18, 4, 0), 8: (22, 2, 2),
          9: (22, 3, 2), 10: (26, 4, 1)},
}

_ALIGNMENT = {
    1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30],
    6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46],
    10: [6, 28, 50],
}

# Pre-computed BCH format strings: (level, mask) -> 15 bits.
_FORMAT_BITS = {}


class QRError(Exception):
    """A payload that will not fit, or cannot be encoded."""


# ---------------------------------------------------------------------------
# GF(256) arithmetic for Reed-Solomon
# ---------------------------------------------------------------------------

_EXP = [0] * 512
_LOG = [0] * 256


def _init_tables() -> None:
    value = 1
    for power in range(255):
        _EXP[power] = value
        _LOG[value] = power
        value <<= 1
        if value & 0x100:              # x^8 + x^4 + x^3 + x^2 + 1
            value ^= 0x11D
    for power in range(255, 512):
        _EXP[power] = _EXP[power - 255]


_init_tables()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _generator(degree: int) -> list:
    poly = [1]
    for index in range(degree):
        poly = _poly_mul(poly, [1, _EXP[index]])
    return poly


def _poly_mul(left: list, right: list) -> list:
    out = [0] * (len(left) + len(right) - 1)
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            out[i + j] ^= _gf_mul(a, b)
    return out


def _ec_codewords(data: list, count: int) -> list:
    generator = _generator(count)
    remainder = list(data) + [0] * count
    for index in range(len(data)):
        factor = remainder[index]
        if factor == 0:
            continue
        for offset, coefficient in enumerate(generator):
            remainder[index + offset] ^= _gf_mul(coefficient, factor)
    return remainder[len(data):]


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------

def _is_alphanumeric(text: str) -> bool:
    return all(char in _ALPHANUM_INDEX for char in text)


def _char_count_bits(mode: str, version: int) -> int:
    if mode == "alphanumeric":
        return 9 if version <= 9 else 11
    return 8 if version <= 9 else 16


def _encode_payload(text: str, mode: str, version: int) -> list:
    bits: list = []

    def push(value: int, length: int) -> None:
        for shift in range(length - 1, -1, -1):
            bits.append((value >> shift) & 1)

    if mode == "alphanumeric":
        push(0b0010, 4)
        push(len(text), _char_count_bits(mode, version))
        for index in range(0, len(text) - 1, 2):
            pair = (_ALPHANUM_INDEX[text[index]] * 45
                    + _ALPHANUM_INDEX[text[index + 1]])
            push(pair, 11)
        if len(text) % 2:
            push(_ALPHANUM_INDEX[text[-1]], 6)
    else:
        raw = text.encode("utf-8")
        push(0b0100, 4)
        push(len(raw), _char_count_bits(mode, version))
        for byte in raw:
            push(byte, 8)
    return bits


def _to_codewords(bits: list, capacity: int) -> list:
    bits = list(bits)
    # Terminator, then pad to a byte, then the specified alternating pad bytes.
    bits.extend([0] * min(4, capacity * 8 - len(bits)))
    while len(bits) % 8:
        bits.append(0)
    codewords = [int("".join(str(bit) for bit in bits[index:index + 8]), 2)
                 for index in range(0, len(bits), 8)]
    for index in range(capacity - len(codewords)):
        codewords.append(0xEC if index % 2 == 0 else 0x11)
    return codewords


def _interleave(codewords: list, version: int, level: str) -> list:
    ec_per_block, group1, group2 = _EC_BLOCKS[level][version]
    total = _DATA_CODEWORDS[version][0 if level == "L" else 1]
    per_block1 = total // (group1 + group2)
    blocks, offset = [], 0
    for _ in range(group1):
        blocks.append(codewords[offset:offset + per_block1])
        offset += per_block1
    for _ in range(group2):
        blocks.append(codewords[offset:offset + per_block1 + 1])
        offset += per_block1 + 1

    ec_blocks = [_ec_codewords(block, ec_per_block) for block in blocks]
    out: list = []
    for index in range(max(len(block) for block in blocks)):
        for block in blocks:
            if index < len(block):
                out.append(block[index])
    for index in range(ec_per_block):
        for block in ec_blocks:
            out.append(block[index])
    return out


# ---------------------------------------------------------------------------
# The matrix
# ---------------------------------------------------------------------------

def _new_matrix(size: int):
    return [[None] * size for _ in range(size)]


def _place_finders(matrix, size: int) -> None:
    for row, column in ((0, 0), (0, size - 7), (size - 7, 0)):
        for y in range(-1, 8):
            for x in range(-1, 8):
                if not (0 <= row + y < size and 0 <= column + x < size):
                    continue
                on = (0 <= y <= 6 and x in (0, 6)) or \
                     (0 <= x <= 6 and y in (0, 6)) or \
                     (2 <= x <= 4 and 2 <= y <= 4)
                matrix[row + y][column + x] = 1 if on else 0


def _place_alignment(matrix, version: int, size: int) -> None:
    centres = _ALIGNMENT[version]
    for row in centres:
        for column in centres:
            if matrix[row][column] is not None:
                continue                       # overlaps a finder pattern
            for y in range(-2, 3):
                for x in range(-2, 3):
                    on = max(abs(x), abs(y)) != 1
                    matrix[row + y][column + x] = 1 if on else 0


def _place_timing(matrix, size: int) -> None:
    for index in range(8, size - 8):
        bit = 1 if index % 2 == 0 else 0
        if matrix[6][index] is None:
            matrix[6][index] = bit
        if matrix[index][6] is None:
            matrix[index][6] = bit


def _reserve_format(matrix, size: int) -> None:
    for index in range(9):
        if matrix[8][index] is None:
            matrix[8][index] = 0
        if matrix[index][8] is None:
            matrix[index][8] = 0
    for index in range(8):
        if matrix[8][size - 1 - index] is None:
            matrix[8][size - 1 - index] = 0
        if matrix[size - 1 - index][8] is None:
            matrix[size - 1 - index][8] = 0
    matrix[size - 8][8] = 1                    # the always-dark module


def _place_data(matrix, size: int, codewords: list) -> None:
    bits = [(word >> shift) & 1
            for word in codewords for shift in range(7, -1, -1)]
    index = 0
    upward = True
    column = size - 1
    while column > 0:
        if column == 6:                        # skip the vertical timing column
            column -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for row in rows:
            for offset in (0, 1):
                x = column - offset
                if matrix[row][x] is None:
                    matrix[row][x] = bits[index] if index < len(bits) else 0
                    index += 1
        upward = not upward
        column -= 2


def _mask_condition(mask: int, row: int, column: int) -> bool:
    if mask == 0:
        return (row + column) % 2 == 0
    if mask == 1:
        return row % 2 == 0
    if mask == 2:
        return column % 3 == 0
    if mask == 3:
        return (row + column) % 3 == 0
    if mask == 4:
        return (row // 2 + column // 3) % 2 == 0
    if mask == 5:
        return (row * column) % 2 + (row * column) % 3 == 0
    if mask == 6:
        return ((row * column) % 2 + (row * column) % 3) % 2 == 0
    return ((row + column) % 2 + (row * column) % 3) % 2 == 0


def _function_map(version: int, size: int):
    """Which modules are structure rather than data — masking must skip them."""
    scratch = _new_matrix(size)
    _place_finders(scratch, size)
    _place_alignment(scratch, version, size)
    _place_timing(scratch, size)
    _reserve_format(scratch, size)
    return [[cell is not None for cell in row] for row in scratch]


def _format_bits(level: str, mask: int) -> list:
    key = (level, mask)
    if key not in _FORMAT_BITS:
        indicator = {"L": 0b01, "M": 0b00}[level]
        value = (indicator << 3) | mask
        remainder = value << 10
        for _ in range(5):
            if remainder >> (14 - _) & 1:
                pass
        # Long division by the BCH generator 0x537.
        remainder = value << 10
        while remainder.bit_length() > 10:
            remainder ^= 0x537 << (remainder.bit_length() - 11)
        bits_value = ((value << 10) | remainder) ^ 0b101010000010010
        _FORMAT_BITS[key] = [(bits_value >> shift) & 1
                             for shift in range(14, -1, -1)]
    return _FORMAT_BITS[key]


def _apply_format(matrix, size: int, level: str, mask: int) -> None:
    bits = _format_bits(level, mask)
    # Copy 1: around the top-left finder.
    positions = [(8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8),
                 (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8)]
    for bit, (row, column) in zip(bits, positions):
        matrix[row][column] = bit
    # Copy 2: split between the other two finders.
    for index in range(7):
        matrix[size - 1 - index][8] = bits[index]
    for index in range(8):
        matrix[8][size - 8 + index] = bits[7 + index]


def _penalty(matrix, size: int) -> int:
    """The specification's four penalty rules — lower is a more scannable code."""
    score = 0
    for line in list(matrix) + [list(column) for column in zip(*matrix)]:
        run, previous = 0, None
        for cell in line:
            if cell == previous:
                run += 1
            else:
                if run >= 5:
                    score += 3 + (run - 5)
                run, previous = 1, cell
        if run >= 5:
            score += 3 + (run - 5)
    for row in range(size - 1):
        for column in range(size - 1):
            block = (matrix[row][column], matrix[row][column + 1],
                     matrix[row + 1][column], matrix[row + 1][column + 1])
            if len(set(block)) == 1:
                score += 3
    pattern_a = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0]
    pattern_b = list(reversed(pattern_a))
    for line in list(matrix) + [list(column) for column in zip(*matrix)]:
        for index in range(size - 10):
            window = line[index:index + 11]
            if window == pattern_a or window == pattern_b:
                score += 40
    dark = sum(sum(row) for row in matrix)
    percent = dark * 100 // (size * size)
    score += 10 * min(abs(percent - 50) // 5, abs(percent - 50 + 4) // 5)
    return score


def _pick_version(text: str, mode: str):
    """The smallest version that fits, preferring level M's stronger recovery."""
    for level in ("M", "L"):
        for version in sorted(_DATA_CODEWORDS):
            capacity = _DATA_CODEWORDS[version][0 if level == "L" else 1]
            needed = len(_encode_payload(text, mode, version))
            if needed <= capacity * 8:
                return version, level
    raise QRError("too much data for a version-10 QR code")


def encode(text: str):
    """``text`` → a matrix of 0/1 rows. Raises ``QRError`` if it will not fit."""
    if not isinstance(text, str) or not text:
        raise QRError("nothing to encode")
    mode = "alphanumeric" if _is_alphanumeric(text) else "byte"
    version, level = _pick_version(text, mode)
    size = 17 + 4 * version

    capacity = _DATA_CODEWORDS[version][0 if level == "L" else 1]
    codewords = _interleave(
        _to_codewords(_encode_payload(text, mode, version), capacity),
        version, level)

    reserved = _function_map(version, size)
    base = _new_matrix(size)
    _place_finders(base, size)
    _place_alignment(base, version, size)
    _place_timing(base, size)
    _reserve_format(base, size)
    _place_data(base, size, codewords)

    best, best_score = None, None
    for mask in range(8):
        candidate = [list(row) for row in base]
        for row in range(size):
            for column in range(size):
                if not reserved[row][column] and _mask_condition(mask, row, column):
                    candidate[row][column] ^= 1
        _apply_format(candidate, size, level, mask)
        score = _penalty(candidate, size)
        if best_score is None or score < best_score:
            best, best_score = candidate, score
    return best


def to_svg(matrix, *, scale: int = 6, quiet: int = 4) -> str:
    """The matrix as an SVG string: crisp at any size, and no image encoder.

    The quiet zone is not decoration — a scanner needs it to find the symbol at
    all, and four modules is what the specification asks for."""
    size = len(matrix)
    total = (size + quiet * 2) * scale
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" '
        f'height="{total}" viewBox="0 0 {total} {total}" '
        f'shape-rendering="crispEdges" role="img" aria-label="Join ticket QR code">',
        f'<rect width="{total}" height="{total}" fill="#ffffff"/>',
    ]
    for row in range(size):
        for column in range(size):
            if matrix[row][column]:
                x = (column + quiet) * scale
                y = (row + quiet) * scale
                parts.append(f'<rect x="{x}" y="{y}" width="{scale}" '
                             f'height="{scale}" fill="#000000"/>')
    parts.append("</svg>")
    return "".join(parts)


def svg_for(text: str, *, scale: int = 6, quiet: int = 4) -> str:
    return to_svg(encode(text), scale=scale, quiet=quiet)
