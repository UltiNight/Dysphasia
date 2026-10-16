#!/usr/bin/env python3
"""
pixel_tone.py -- independent reimplementation of PixelTone.exe's observable
CLI behavior, reconstructed from static analysis of
artifacts/protected-p1p2p3/PixelTone.exe (a .NET IL-only, x86_64, single-file
console assembly, 6144 bytes, no source available).

See findings.md in this directory for the full analysis writeup, evidence
citations, and list of assumptions. Summary of the reconstructed contract:

    PixelTone --help
        -> prints two usage lines to stdout, exit code 0.

    PixelTone R G B brightness contrast preset
        R,G,B        : integers in [0,255]
        brightness   : integer in [-100,100]
        contrast     : integer in [0,200]
        preset       : one of "neutral" | "mono" | "warm"
        -> applies brightness/contrast to each channel, then the preset
           transform, then prints "r,g,b|HASH" (HASH = 8-digit uppercase hex
           FNV-1a32 over the final [r,g,b]) to stdout, exit code 0.

    Any other argument count / an unparsable or out-of-range numeric
    argument / an unrecognized preset -> prints "ERROR: <message>" to
    stderr, exit code 2.

Exact bytes matter: this script writes raw bytes (CRLF line endings, as the
original .NET Console.WriteLine on Windows emits) directly to stdout/stderr
rather than relying on the host platform's text-mode newline translation.
"""
import sys
import re

# ---------------------------------------------------------------------------
# Embedded string table.
#
# The original binary stores no `ldstr` string literals at all (confirmed:
# REA's user_strings.literals is empty for this assembly). Instead all
# human-readable text is XOR-obfuscated inside a single 235-byte blob that is
# embedded via a FieldRVA-backed static byte[] field (T84d29266f2.f_134b552a1f,
# initialized from a compiler-generated <PrivateImplementationDetails>-style
# nested struct, Tf9ec26c126, ClassLayout size=235). A helper method,
# T84d29266f2.m_5558f5ab53(int offset, int length, byte key), decodes a
# substring at runtime as:
#     chars[i] = blob[offset + i] ^ key      for i in [0, length)
#     return new string(chars)
#
# This blob and decode routine were recovered by parsing the PE/CLI metadata
# directly (section table -> CLI header -> metadata root -> #~ tables stream
# -> FieldRVA row -> file offset) and by decoding the method's raw CIL bytes
# with a small supplementary ECMA-335 opcode decoder (see cil_decoder.py /
# decode_all.py in this directory). All (offset,length,key) triples below are
# the literal operands pushed before each call to m_5558f5ab53 in the
# decompiled call sites (Teeef425ae1.m_ec38e2401a / Main, and
# T84d29266f2... / the style helper), so the decoded text is OBSERVED data,
# not guessed.
# ---------------------------------------------------------------------------

_BLOB = bytes.fromhex(
    "4b4948491402110e61667c6d6f6d7a28677d7c28676e287a69666f6d6a6a2f"
    "222b370f36273a330b30313a7f0d7f187f1d7f3d2d3638372b313a2c2c7f3c"
    "30312b2d3e2c2b7f2f2d3a2c3a2bbcc1a9c1acd4cedec0c0dcdbdbd5ce8c9c"
    "8789869a808b9d9dd4cec3dfdedec0c0dfdeded5ce8d81809a9c8f9d9ad4ce"
    "dec0c0dcdeded5ce9e9c8b9d8b9ad4ce808b9b9a9c8f82928381808192998f"
    "9c83706d6570766170713523357467726078707b61662e356066703538387d"
    "707965f9f2e2e3e5f6fb0e151015140c155b0b091e081e0f0f4409580f4509"
    "580f4609080f474e2c4c097b6c6c716c041e"
)


def _decode_string(offset: int, length: int, key: int) -> str:
    return "".join(chr(_BLOB[offset + i] ^ key) for i in range(length))


# Decoded once, at the exact (offset, length, key) triples observed at each
# call site in the decompiled Main / style-helper methods.
STR_HELP_FLAG = _decode_string(28, 6, 71)        # "--help"
STR_HELP_LINE1 = _decode_string(34, 42, 95)      # usage summary
STR_HELP_LINE2 = _decode_string(76, 81, 238)     # ranges/presets summary
STR_USAGE_ERROR = _decode_string(157, 32, 21)    # "expected 6 arguments; use --help"
STR_RANGE_ERROR = _decode_string(8, 20, 8)       # "integer out of range"
STR_PRESET_NEUTRAL = _decode_string(189, 7, 151)  # "neutral"
STR_PRESET_MONO = _decode_string(0, 4, 38)        # "mono"
STR_PRESET_WARM = _decode_string(4, 4, 99)        # "warm"
STR_PRESET_ERROR = _decode_string(196, 14, 123)   # "unknown preset"
STR_OUTPUT_FORMAT = _decode_string(210, 18, 116)  # "{0},{1},{2}|{3:X8}"
STR_STDERR_PREFIX = _decode_string(228, 7, 62)    # "ERROR: "


class PixelToneArgumentException(Exception):
    """Mirrors the single ArgumentException type the target throws/catches."""
    pass


# ---------------------------------------------------------------------------
# Numeric parsing: Main calls a helper (Teeef425ae1.m_22283830b7) that is
# System.Int32.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture,
# out value) followed by a [min,max] range check; both a parse failure and an
# out-of-range value raise the SAME message, STR_RANGE_ERROR. NumberStyles
# .Integer = AllowLeadingWhite|AllowTrailingWhite|AllowLeadingSign: optional
# surrounding whitespace, optional single leading '+'/'-', ASCII digits only
# (no thousands separators, no decimal point), and must fit in a 32-bit
# signed integer.
# ---------------------------------------------------------------------------
_INT_RE = re.compile(r"^[ \t\n\r\f\v]*([+-]?[0-9]+)[ \t\n\r\f\v]*$")
_INT32_MIN = -2147483648
_INT32_MAX = 2147483647


def _try_parse_int32(s: str):
    m = _INT_RE.match(s)
    if not m:
        return None
    value = int(m.group(1))
    if value < _INT32_MIN or value > _INT32_MAX:
        return None
    return value


def _parse_int_in_range(s: str, lo: int, hi: int) -> int:
    value = _try_parse_int32(s)
    if value is None or value < lo or value > hi:
        raise PixelToneArgumentException(STR_RANGE_ERROR)
    return value


# ---------------------------------------------------------------------------
# Core per-channel / per-pixel math, transcribed 1:1 from the decoded CIL of
# Teeef425ae1.m_4e09ee408f (Clamp255), m_b2ece2c34c (brightness/contrast),
# m_b3c4f3c803 (preset transform) and m_0481f84d57 (FNV-1a32 hash). All
# arithmetic below is plain 32-bit C#-style integer math; the only subtlety
# versus naive Python translation is C#'s `div`, which truncates toward zero
# (Python's `//` floors toward negative infinity), handled by _trunc_div.
# ---------------------------------------------------------------------------

def _clamp255(value: int) -> int:
    if value < 0:
        return 0
    if value > 255:
        return 255
    return value


def _trunc_div(a: int, b: int) -> int:
    q = abs(a) // abs(b)
    return -q if (a < 0) != (b < 0) else q


def _adjust_channel(channel: int, brightness: int, contrast: int) -> int:
    # Clamp255(((channel - 128) * contrast) / 100 + 128 + brightness)
    return _clamp255(_trunc_div((channel - 128) * contrast, 100) + 128 + brightness)


def _apply_preset(r: int, g: int, b: int, preset: str):
    if preset == STR_PRESET_MONO:
        luma = (77 * r + 150 * g + 29 * b + 128) >> 8
        return [luma, luma, luma]
    if preset == STR_PRESET_WARM:
        return [_clamp255(r + 12), _clamp255(g + 3), _clamp255(b - 9)]
    # "neutral" (and, defensively, anything else that reached this point)
    # passes the three channels through unchanged.
    return [r, g, b]


def _fnv1a32(values) -> int:
    h = 0x811C9DC5          # -2128831035 as i4 == FNV-1a 32-bit offset basis
    for v in values:
        h = (h ^ (v & 0xFFFFFFFF)) & 0xFFFFFFFF
        h = (h * 0x01000193) & 0xFFFFFFFF   # FNV-1a 32-bit prime, 16777619
    return h


# ---------------------------------------------------------------------------
# Entry point, transcribed from Teeef425ae1.m_ec38e2401a ("Main").
# ---------------------------------------------------------------------------

def _run(argv) -> int:
    out_lines = []
    if len(argv) == 1:
        if argv[0] == STR_HELP_FLAG:
            out_lines.append(STR_HELP_LINE1)
            out_lines.append(STR_HELP_LINE2)
            _write_stdout_lines(out_lines)
            return 0
        # falls through to the generic "expected 6 arguments" error below
    if len(argv) != 6:
        raise PixelToneArgumentException(STR_USAGE_ERROR)

    r = _parse_int_in_range(argv[0], 0, 255)
    g = _parse_int_in_range(argv[1], 0, 255)
    b = _parse_int_in_range(argv[2], 0, 255)
    brightness = _parse_int_in_range(argv[3], -100, 100)
    contrast = _parse_int_in_range(argv[4], 0, 200)
    preset = argv[5]

    if preset != STR_PRESET_NEUTRAL and preset != STR_PRESET_MONO and preset != STR_PRESET_WARM:
        raise PixelToneArgumentException(STR_PRESET_ERROR)

    new_r = _adjust_channel(r, brightness, contrast)
    new_g = _adjust_channel(g, brightness, contrast)
    new_b = _adjust_channel(b, brightness, contrast)

    toned = _apply_preset(new_r, new_g, new_b, preset)
    digest = _fnv1a32(toned)

    line = f"{toned[0]},{toned[1]},{toned[2]}|{digest:08X}"
    _write_stdout_lines([line])
    return 0


def _write_stdout_lines(lines):
    data = "".join(line + "\r\n" for line in lines)
    sys.stdout.buffer.write(data.encode("utf-8"))
    sys.stdout.buffer.flush()


def _write_stderr_line(line: str):
    data = (STR_STDERR_PREFIX + line + "\r\n")
    sys.stderr.buffer.write(data.encode("utf-8"))
    sys.stderr.buffer.flush()


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    try:
        return _run(argv)
    except PixelToneArgumentException as exc:
        _write_stderr_line(str(exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())
