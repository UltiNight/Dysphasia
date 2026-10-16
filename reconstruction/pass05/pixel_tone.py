#!/usr/bin/env python3
"""
pixel_tone.py -- independent reimplementation of PixelTone.exe's observable
CLI behavior, produced purely from static analysis of the managed PE/CIL
(see findings.md for the full evidence trail).

Usage mirrors the original:
    pixel_tone.py --help
    pixel_tone.py R G B brightness contrast preset

This script writes bytes to stdout/stderr that are intended to match the
original .exe's output exactly (including Windows CRLF line endings, which
.NET's Console.WriteLine emits via Environment.NewLine on Windows), and
exits with the same process exit code the original returns from Main.

No third-party dependencies; standard library only.
"""

import re
import sys


# ---------------------------------------------------------------------------
# String literals.
#
# The original binary never uses `ldstr` (REA's user_strings.literals was
# empty, and the assembly has no #US heap at all). Every user-visible string
# is instead reconstructed at runtime from a 235-byte array embedded via a
# FieldRVA ("new byte[] {...}" pattern) and a helper method,
# T84d29266f2.m_5558f5ab53(start, length, key), that does:
#     chars[j] = (byte_blob[start + j] ^ key) as a UTF-16 code unit
# for j in [0, length). We recovered the 235-byte blob directly from the PE
# file (FieldRVA table row -> RVA -> file offset) and decoded every call
# site's (start, length, key) triplet; all eleven calls decode to clean
# printable ASCII (see findings.md). We inline the decoded text here rather
# than re-implementing the XOR scheme, since only observable behavior needs
# to match.
HELP_FLAG = "--help"
HELP_LINE_1 = "PixelTone R G B brightness contrast preset"
HELP_LINE_2 = (
    "R/G/B: 0..255; brightness: -100..100; contrast: 0..200; "
    "preset: neutral|mono|warm"
)
MSG_WRONG_ARGCOUNT = "expected 6 arguments; use --help"
MODE_NEUTRAL = "neutral"
MODE_MONO = "mono"
MODE_WARM = "warm"
MSG_UNKNOWN_PRESET = "unknown preset"
# Console.WriteLine composite format observed at the call site is the
# literal string "{0},{1},{2}|{3:X8}" (C#'s "X8" = uppercase hex, >=8 digits,
# zero-padded). Python's str.format mini-language spells the same
# padded-uppercase-hex spec "08X" (width before type), not "X8", so we build
# the line directly rather than reusing the C# spec string verbatim.
STDERR_PREFIX = "ERROR: "
MSG_OUT_OF_RANGE = "integer out of range"

NEWLINE = "\r\n"  # Environment.NewLine on Windows; .NET Console.WriteLine's terminator


class ArgError(Exception):
    """Mirrors the System.ArgumentException thrown throughout Main's logic.

    The original's Main wraps the entire 6-argument validation/processing
    path in a try/catch(ArgumentException) (CIL exception_regions on method
    token 0x06000006, class_token 0x01000007 = System.ArgumentException).
    Every intentional failure in that path (wrong arg count, unparsable or
    out-of-range numeric argument, unknown preset) raises this exception
    type and only this type is caught.
    """


def clamp_byte(v):
    """Teeef425ae1.m_4e09ee408f(int) -> int : clamp v into [0, 255].

    Decoded CIL (switch-based state machine) reduces exactly to:
        v < 0   -> 0
        v > 255 -> 255
        else    -> v
    """
    if v < 0:
        return 0
    if v > 255:
        return 255
    return v


def trunc_div(a, b):
    """CIL `div` on int32 operands: signed division truncated toward zero.

    Needed because (a - 128) can be negative and Python's `//` floors
    toward negative infinity, which differs from CIL/C# truncation for
    negative operands.
    """
    q = abs(a) // abs(b)
    if (a < 0) != (b < 0):
        q = -q
    return q


def adjust_channel(value, brightness, contrast):
    """Teeef425ae1.m_b2ece2c34c(int value, int brightness, int contrast) -> int.

    Decoded CIL:
        return Clamp( (value - 128) * contrast / 100 + 128 + brightness )
    (`div` truncates toward zero; `mul`/`add`/`sub` are plain int32 ops.)
    """
    return clamp_byte(trunc_div((value - 128) * contrast, 100) + 128 + brightness)


def apply_preset(r, g, b, mode):
    """Teeef425ae1.m_b3c4f3c803(int r, int g, int b, string mode) -> int[3].

    Decoded CIL (switch-based state machine) reduces to:
        mode == "mono": luma = (77*r + 150*g + 29*b + 128) >> 8 ; [luma]*3
        mode == "warm": [Clamp(r+12), Clamp(g+3), Clamp(b-9)]
        otherwise      : [r, g, b]   (the "neutral" / default path)
    """
    if mode == MODE_MONO:
        luma = (77 * r + 150 * g + 29 * b + 128) >> 8
        return [luma, luma, luma]
    if mode == MODE_WARM:
        return [clamp_byte(r + 12), clamp_byte(g + 3), clamp_byte(b - 9)]
    return [r, g, b]


def fnv1a32(values):
    """Teeef425ae1.m_0481f84d57(int[]) -> uint.

    Decoded CIL is the standard 32-bit FNV-1a hash:
        hash = 0x811C9DC5 (2166136261)
        for v in values: hash = ((hash ^ v) * 16777619) mod 2**32
        return hash
    """
    h = 2166136261  # 0x811C9DC5, i.e. (uint)-2128831035
    for v in values:
        h = (h ^ (v & 0xFFFFFFFF)) & 0xFFFFFFFF
        h = (h * 16777619) & 0xFFFFFFFF
    return h


# Matches System.Int32.TryParse(s, NumberStyles.Integer, InvariantCulture, out _).
# NumberStyles.Integer = AllowLeadingWhite | AllowTrailingWhite | AllowLeadingSign
# (the literal CIL operand observed at the call site is exactly 7, which is
# that flag combination) -- i.e. optional surrounding whitespace, an optional
# leading sign, then one or more ASCII decimal digits; no decimal point, no
# thousands separators, no exponent.
_INT_PATTERN = re.compile(r"^\s*([+-]?[0-9]+)\s*$")

_INT32_MIN = -2147483648
_INT32_MAX = 2147483647


def try_parse_int32_invariant(s):
    """Best-effort reimplementation of Int32.TryParse with NumberStyles.Integer
    and CultureInfo.InvariantCulture. Returns (True, value) or (False, None).
    """
    m = _INT_PATTERN.match(s)
    if not m:
        return False, None
    try:
        value = int(m.group(1))
    except ValueError:
        return False, None
    if value < _INT32_MIN or value > _INT32_MAX:
        return False, None
    return True, value


def parse_int_in_range(s, lo, hi):
    """Teeef425ae1.m_22283830b7(string s, int min, int max) -> int.

    Decoded CIL:
        ok, v = Int32.TryParse(s, NumberStyles.Integer, InvariantCulture)
        if not ok or v < min or v > max:
            throw new ArgumentException("integer out of range")
        return v

    Note: a parse failure and an out-of-range value raise the exact same
    message; the original binary does not distinguish them.
    """
    ok, value = try_parse_int32_invariant(s)
    if not ok or value < lo or value > hi:
        raise ArgError(MSG_OUT_OF_RANGE)
    return value


def run(args, stdout, stderr):
    """Teeef425ae1.m_ec38e2401a(string[] args) -> int : the Main method."""
    if len(args) == 1:
        if args[0] == HELP_FLAG:
            stdout.write(HELP_LINE_1 + NEWLINE)
            stdout.write(HELP_LINE_2 + NEWLINE)
            return 0
        # falls through to the general path below, which will fail the
        # "exactly 6 arguments" check and raise ArgError.

    try:
        if len(args) != 6:
            raise ArgError(MSG_WRONG_ARGCOUNT)

        r = parse_int_in_range(args[0], 0, 255)
        g = parse_int_in_range(args[1], 0, 255)
        b = parse_int_in_range(args[2], 0, 255)
        brightness = parse_int_in_range(args[3], -100, 100)
        contrast = parse_int_in_range(args[4], 0, 200)
        mode = args[5]

        if mode != MODE_NEUTRAL and mode != MODE_MONO and mode != MODE_WARM:
            raise ArgError(MSG_UNKNOWN_PRESET)

        adj_r = adjust_channel(r, brightness, contrast)
        adj_g = adjust_channel(g, brightness, contrast)
        adj_b = adjust_channel(b, brightness, contrast)

        result = apply_preset(adj_r, adj_g, adj_b, mode)
        digest = fnv1a32(result)

        line = "{0},{1},{2}|{3:08X}".format(result[0], result[1], result[2], digest)
        stdout.write(line + NEWLINE)
        return 0
    except ArgError as exc:
        stderr.write(STDERR_PREFIX + str(exc) + NEWLINE)
        return 2


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    # Write with explicit "\r\n" terminators and no further newline
    # translation, so output bytes match the original Windows .exe exactly
    # regardless of the host platform/console this script runs under.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(newline="")
        except (AttributeError, ValueError):
            pass

    return run(argv, sys.stdout, sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
