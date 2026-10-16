#!/usr/bin/env python3
"""
Reimplementation of PixelTone.exe's observable CLI behavior.

Produced by independent static analysis (REA managed-metadata inspection +
a supplementary hand-written ECMA-335 CIL decoder over the raw method
bytes) of artifacts/protected-p1p2p3/PixelTone.exe, cross-checked against
8 live executions of the real binary. See findings.md in this directory
for the full evidence trail, the method-by-method mapping, and which
parts are observed vs. inferred vs. assumption.

Behavior summary (a tiny "pixel tone" CLI: brightness/contrast + preset):
    PixelTone.exe <R> <G> <B> <brightness> <contrast> <preset>
    PixelTone.exe --help

  - exactly 1 argument equal to the literal string "--help" (ordinal,
    case-sensitive) -> prints a 2-line usage message to stdout, exit 0.
  - any other argument count that isn't exactly 6 -> raises the
    "expected 6 arguments; use --help" error (caught, printed to stderr
    prefixed "ERROR: ", exit 2).
  - with exactly 6 arguments: R,G,B parsed as integers in [0,255],
    brightness in [-100,100], contrast in [0,200] (all via .NET
    Int32.TryParse(..., NumberStyles.Integer, CultureInfo.InvariantCulture)
    semantics, then inclusive-range checked); preset is the 6th argument,
    a string.
  - preset must be one of "neutral", "mono", "warm" or the program raises
    "unknown preset". ("neutral" and any value accepted-but-unhandled by
    the color-mode switch fall through to a no-op identity transform; only
    "neutral" is actually a *recognized* value besides "mono"/"warm".)
  - each parse/range failure or unknown-preset failure raises an
    ArgumentException that is caught by a single handler wrapping the
    whole 6-arg path: stderr gets "ERROR: " + message + CRLF, exit code 2.
  - on success: each channel is brightness/contrast-adjusted, then the
    preset transform is applied, then stdout gets
    "{r},{g},{b}|{hash:X8}\r\n" where hash is a 32-bit FNV-1a-style
    checksum of the final [r,g,b] array, exit code 0.

All line endings are CRLF ("\r\n"), confirmed byte-for-byte against the
real binary's stdout/stderr (reconstruction/pass06/probe_log.jsonl).
"""
import sys


# ---------------------------------------------------------------------------
# Decoded string-table literals.
#
# The real binary stores these as an XOR-obfuscated 235-byte blob (a
# FieldRVA-initialized byte[] on type T84d29266f2, decoded on demand by
# method m_5558f5ab53(offset, length, key) -> string, which XORs each byte
# with `key` and widens it straight to a UTF-16 code unit). We located the
# blob at file offset 2504 in the .exe, confirmed every (offset,length,key)
# triple used anywhere in the assembly decodes to clean printable ASCII,
# and verified the *decoded results* against the real program's actual
# stdout/stderr byte-for-byte (see findings.md). We hardcode the decoded
# plaintext here rather than re-implementing the byte-table + XOR step,
# since that mechanism is just an obfuscation detail with no observable
# effect once decoded -- the constants below are exactly what the target
# program decodes and uses at those call sites, nothing more.
# ---------------------------------------------------------------------------
STR_MODE_MONO = "mono"                 # DecodeString(0, 4, 38)
STR_MODE_WARM = "warm"                 # DecodeString(4, 4, 99)
STR_ERR_INT_RANGE = "integer out of range"          # DecodeString(8, 20, 8)
STR_HELP_FLAG = "--help"               # DecodeString(28, 6, 71)
STR_USAGE_1 = "PixelTone R G B brightness contrast preset"   # DecodeString(34, 42, 95)
STR_USAGE_2 = ("R/G/B: 0..255; brightness: -100..100; contrast: 0..200; "
               "preset: neutral|mono|warm")                 # DecodeString(76, 81, 238)
STR_ERR_ARGCOUNT = "expected 6 arguments; use --help"        # DecodeString(157, 32, 21)
STR_MODE_NEUTRAL = "neutral"           # DecodeString(189, 7, 151)
STR_ERR_UNKNOWN_PRESET = "unknown preset"                    # DecodeString(196, 14, 123)
STR_RESULT_FORMAT = "{0},{1},{2}|{3:X8}"                      # DecodeString(210, 18, 116)
STR_ERROR_PREFIX = "ERROR: "           # DecodeString(228, 7, 62)

NEWLINE = b"\r\n"  # Environment.NewLine as observed on the target (Windows CRLF).


class ArgumentException(Exception):
    """Mirrors the single exception type the target raises and catches."""


# ---------------------------------------------------------------------------
# m_4e09ee408f: Teeef425ae1.ClampByte(int v) -> int
#   Decoded directly from CIL (control-flow-flattened switch/state machine
#   in the original; collapsed here to its straight-line semantics, which
#   were verified against REA's anchors instruction-by-instruction):
#     return 0 if v < 0 else 255 if v > 255 else v
# ---------------------------------------------------------------------------
def clamp_byte(v: int) -> int:
    if v < 0:
        return 0
    if v > 255:
        return 255
    return v


def _trunc_div(a: int, b: int) -> int:
    """C#/CIL `div` on int32: integer division truncating toward zero
    (unlike Python's `//`, which floors). b is always 100 (positive) at
    the one call site that uses this (m_b2ece2c34c), but implemented
    generally for clarity/safety."""
    q = abs(a) // abs(b)
    if (a < 0) != (b < 0):
        q = -q
    return q


# ---------------------------------------------------------------------------
# m_b2ece2c34c: Teeef425ae1.AdjustChannel(int pixel, int brightness, int contrast) -> int
#   result = ClampByte( (pixel - 128) * contrast / 100 + 128 + brightness )
#   (CIL `div` -> truncating division, see _trunc_div.)
#   Verified byte-exact against the real binary for several (pixel,
#   brightness, contrast) triples via live probes (see findings.md).
# ---------------------------------------------------------------------------
def adjust_channel(pixel: int, brightness: int, contrast: int) -> int:
    return clamp_byte(_trunc_div((pixel - 128) * contrast, 100) + 128 + brightness)


# ---------------------------------------------------------------------------
# m_b3c4f3c803: Teeef425ae1.ApplyPreset(int r, int g, int b, string mode) -> int[3]
#   if mode == "mono": gray = (77*r + 150*g + 29*b + 128) >> 8; return [gray]*3
#   elif mode == "warm": return [Clamp(r+12), Clamp(g+3), Clamp(b-9)]
#   else: return [r, g, b]   (identity/passthrough -- this is what "neutral"
#                             and any other not-specially-handled string hits)
#   Verified byte-exact for mono and warm (incl. warm's clamp saturation at
#   both ends) via live probes.
# ---------------------------------------------------------------------------
def apply_preset(r: int, g: int, b: int, mode: str) -> list:
    if mode == STR_MODE_MONO:
        gray = ((77 * r + 150 * g + 29 * b + 128) >> 8)
        return [gray, gray, gray]
    elif mode == STR_MODE_WARM:
        return [clamp_byte(r + 12), clamp_byte(g + 3), clamp_byte(b - 9)]
    else:
        return [r, g, b]


# ---------------------------------------------------------------------------
# m_0481f84d57: Teeef425ae1.Fnv(int[] arr) -> uint
#   Classic FNV-1a, but XORing whole int32 array elements (not bytes):
#     hash = 0x811C9DC5 (2166136261)
#     for each v in arr: hash = (hash ^ (uint)v) * 16777619   (unchecked, 32-bit wraparound)
#   Verified byte-exact against the real binary's printed "{3:X8}" hash for
#   multiple inputs via live probes (e.g. Fnv([0,0,0]) == 0x4AB0F7B7).
# ---------------------------------------------------------------------------
def fnv(arr) -> int:
    h = 2166136261
    for v in arr:
        h = (h ^ (v & 0xFFFFFFFF)) & 0xFFFFFFFF
        h = (h * 16777619) & 0xFFFFFFFF
    return h


# ---------------------------------------------------------------------------
# m_22283830b7: Teeef425ae1.ParseIntInRange(string s, int lo, int hi) -> int
#   Calls the real System.Int32.TryParse(s, NumberStyles.Integer,
#   CultureInfo.InvariantCulture, out value); on failure, or if
#   value < lo, or if value > hi: throws ArgumentException("integer out of
#   range"). Otherwise returns value.
#
#   NumberStyles.Integer = AllowLeadingWhite | AllowTrailingWhite |
#   AllowLeadingSign. We reimplement .NET's actual whitespace-trim rule
#   here rather than guessing: live probe #8 (reconstruction/pass06/
#   probe_log.jsonl) fed a leading U+00A0 (NO-BREAK SPACE) before "100" as
#   R, with all other args valid/in-range, and the real binary REJECTED it
#   ("ERROR: integer out of range", exit 2) rather than accepting 100. That
#   confirms .NET's number-parser whitespace check here is the narrow,
#   ASCII-only one (matches ' ' and the control range U+0009..U+000D), NOT
#   a generic Unicode char.IsWhiteSpace-style check (which would have
#   accepted NBSP). We implement exactly that narrow set, both leading and
#   trailing.
# ---------------------------------------------------------------------------
_DOTNET_INTEGER_WHITESPACE = {0x20, 0x09, 0x0A, 0x0B, 0x0C, 0x0D}
_INT32_MIN = -2147483648
_INT32_MAX = 2147483647


def _dotnet_tryparse_int32_integer_style(s: str):
    """Returns (ok, value). Mirrors Int32.TryParse(s, NumberStyles.Integer,
    CultureInfo.InvariantCulture, out value): optional ASCII leading
    whitespace, optional single '+'/'-' sign, one or more ASCII digits
    '0'-'9', optional ASCII trailing whitespace; the parsed value must fit
    in a 32-bit signed integer. Nothing else is permitted (no decimal
    point, no thousands separators, no exponent, no non-ASCII digits)."""
    i = 0
    n = len(s)
    while i < n and ord(s[i]) in _DOTNET_INTEGER_WHITESPACE:
        i += 1
    j = n
    while j > i and ord(s[j - 1]) in _DOTNET_INTEGER_WHITESPACE:
        j -= 1
    if i >= j:
        return False, 0
    sign = 1
    if s[i] in "+-":
        if s[i] == "-":
            sign = -1
        i += 1
    if i >= j:
        return False, 0
    digits = s[i:j]
    if not digits.isascii() or not digits.isdigit():
        return False, 0
    # isdigit() on an ASCII-only string is equivalent to the "0".."9" check
    # we need, since we already excluded non-ASCII above.
    value = sign * int(digits)
    if value < _INT32_MIN or value > _INT32_MAX:
        return False, 0
    return True, value


def parse_int_in_range(s: str, lo: int, hi: int) -> int:
    ok, value = _dotnet_tryparse_int32_integer_style(s)
    if not ok or value < lo or value > hi:
        raise ArgumentException(STR_ERR_INT_RANGE)
    return value


# ---------------------------------------------------------------------------
# m_ec38e2401a: Teeef425ae1.Main(string[] args) -> int
#   Full control flow decoded from raw CIL (file offsets 1616.., fat header,
#   try/catch over the 6-arg path) and confirmed against all 8 live probes.
# ---------------------------------------------------------------------------
def _format_result(r: int, g: int, b: int, h: int) -> str:
    # STR_RESULT_FORMAT is "{0},{1},{2}|{3:X8}" -- a .NET composite format
    # string with a fixed, known shape; we just build it directly rather
    # than implementing a general .NET composite-formatter.
    return "{0},{1},{2}|{3:08X}".format(r, g, b, h)


def run(args) -> (int, bytes, bytes):
    """Executes PixelTone's Main logic. Returns (exit_code, stdout_bytes,
    stderr_bytes), matching the real process's observable output exactly."""
    stdout_parts = []
    stderr_parts = []

    def emit_out(line: str):
        stdout_parts.append(line.encode("utf-8") + NEWLINE)

    def emit_err(line: str):
        stderr_parts.append(line.encode("utf-8") + NEWLINE)

    # Single-argument "--help" fast path (checked before the try/catch that
    # guards everything else -- it cannot raise).
    if len(args) == 1:
        if args[0] == STR_HELP_FLAG:
            emit_out(STR_USAGE_1)
            emit_out(STR_USAGE_2)
            return 0, b"".join(stdout_parts), b"".join(stderr_parts)
        # else: falls through to the length check below, which will throw.

    try:
        if len(args) != 6:
            raise ArgumentException(STR_ERR_ARGCOUNT)

        r_in = parse_int_in_range(args[0], 0, 255)
        g_in = parse_int_in_range(args[1], 0, 255)
        b_in = parse_int_in_range(args[2], 0, 255)
        brightness = parse_int_in_range(args[3], -100, 100)
        contrast = parse_int_in_range(args[4], 0, 200)
        preset = args[5]

        if preset != STR_MODE_NEUTRAL and preset != STR_MODE_MONO and preset != STR_MODE_WARM:
            raise ArgumentException(STR_ERR_UNKNOWN_PRESET)

        new_r = adjust_channel(r_in, brightness, contrast)
        new_g = adjust_channel(g_in, brightness, contrast)
        new_b = adjust_channel(b_in, brightness, contrast)
        result = apply_preset(new_r, new_g, new_b, preset)
        h = fnv(result)

        emit_out(_format_result(result[0], result[1], result[2], h))
        return 0, b"".join(stdout_parts), b"".join(stderr_parts)
    except ArgumentException as ex:
        emit_err(STR_ERROR_PREFIX + str(ex))
        return 2, b"".join(stdout_parts), b"".join(stderr_parts)


def main(argv):
    exit_code, out, err = run(argv)
    sys.stdout.buffer.write(out)
    sys.stdout.buffer.flush()
    sys.stderr.buffer.write(err)
    sys.stderr.buffer.flush()
    return exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
