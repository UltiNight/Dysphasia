#!/usr/bin/env python3
"""
Standalone reimplementation of PixelTone.exe's observable CLI behavior.

Reconstructed purely from static analysis (REA inspect-managed-members output,
a supplementary hand-rolled ECMA-335 CIL decoder, and direct PE/CLI metadata
parsing to recover a FieldRVA-backed byte blob used for XOR-"encrypted" string
literals) plus a small number of confirmatory live-execution probes. See
findings.md in this directory for the full evidence trail.

Usage: python pixel_tone.py <R> <G> <B> <brightness> <contrast> <preset>
   or: python pixel_tone.py --help
"""
import sys


class ArgumentError(Exception):
    """Mirrors the target's System.ArgumentException(message) for this program:
    every validation failure in the original raises this exact .NET type, and
    Main's single catch(ArgumentException) handler prints "ERROR: " + message
    to stderr and returns exit code 2. No other exception type is reachable
    from any argv content in the decoded control flow, so no broader except
    clause is needed to match observed behavior."""
    def __init__(self, message):
        super().__init__(message)
        self.message = message


# ---------------------------------------------------------------------------
# Helpers that mirror specific .NET runtime primitives used by the target.
# ---------------------------------------------------------------------------

# .NET's internal number parser (System.Number) trims leading/trailing
# whitespace for NumberStyles.AllowLeadingWhite / AllowTrailingWhite using a
# narrow, ASCII-only definition -- NOT the general Unicode `char.IsWhiteSpace`
# check. The internal predicate is equivalent to:
#     ch == 0x20 || (0x09 <= ch <= 0x0D)
# which is U+0020 SPACE plus the five C0 control codes U+0009..U+000D (TAB,
# LF, VT, FF, CR). Notably this EXCLUDES U+00A0 NO-BREAK SPACE, even though
# `char.IsWhiteSpace(' ')` is true in .NET. We confirmed this empirically
# against the live target: a leading U+00A0 before the digits of an argument
# is NOT trimmed and makes Int32.TryParse fail (see probe 8 in probe_log.jsonl
# / findings.md), which surfaces as the same "integer out of range" error as
# any other unparsable value.
_DOTNET_NARROW_WHITESPACE = "\x09\x0a\x0b\x0c\x0d\x20"


def _dotnet_int32_tryparse(s):
    """Reimplements int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture).

    NumberStyles.Integer = AllowLeadingWhite | AllowTrailingWhite | AllowLeadingSign.
    Returns (True, value) on success, (False, None) on failure (never raises,
    matching TryParse semantics, including on Int32 overflow).
    """
    i = 0
    n = len(s)
    while i < n and s[i] in _DOTNET_NARROW_WHITESPACE:
        i += 1
    j = n
    while j > i and s[j - 1] in _DOTNET_NARROW_WHITESPACE:
        j -= 1
    core = s[i:j]
    if not core:
        return False, None
    sign = 1
    k = 0
    if core[0] in "+-":
        if core[0] == "-":
            sign = -1
        k = 1
    digits = core[k:]
    if not digits or not digits.isascii() or not digits.isdigit():
        return False, None
    value = sign * int(digits)
    if value < -2147483648 or value > 2147483647:
        return False, None
    return True, value


def _trunc_div(n, d):
    """C#/CIL `div` on signed 32-bit ints truncates toward zero, unlike
    Python's floor-dividing `//`. d is always a positive literal (100) at
    every call site in the target, but this stays correct for any sign."""
    q = abs(n) // abs(d)
    if (n < 0) != (d < 0):
        q = -q
    return q


def _fnv1a_like(values):
    """Reimplements Teeef425ae1.m_0481f84d57: a 32-bit FNV-1a-shaped hash,
    but XOR-folding whole 32-bit int elements (not individual bytes) of the
    3-element channel array. Offset basis 2166136261 (0x811c9dc5), prime
    16777619 (0x01000193) -- the standard FNV-1a 32-bit constants."""
    h = 2166136261
    for x in values:
        h = (h ^ (x & 0xFFFFFFFF)) & 0xFFFFFFFF
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def _clamp_byte(v):
    """Teeef425ae1.m_4e09ee408f: clamp an int to the inclusive range [0, 255]."""
    if v < 0:
        return 0
    if v > 255:
        return 255
    return v


def _adjust_channel(channel, brightness, contrast):
    """Teeef425ae1.m_b2ece2c34c(channel, brightness, contrast):
    clamp( ((channel - 128) * contrast) / 100 + 128 + brightness, 0, 255 ),
    using truncating integer division as CIL's `div` does."""
    return _clamp_byte(_trunc_div((channel - 128) * contrast, 100) + 128 + brightness)


def _apply_preset(r, g, b, preset):
    """Teeef425ae1.m_b3c4f3c803(r, g, b, preset) -> (r, g, b) triple.

    preset == "mono": standard BT.601-weighted luma, fixed-point (weights
      *256): (77*r + 150*g + 29*b + 128) >> 8, replicated into all 3 channels.
    preset == "warm": per-channel additive shift (+12, +3, -9), each clamped.
    anything else (in practice only "neutral", since Main validates preset
      against exactly {"neutral", "mono", "warm"} before this is reached):
      pass the three channels through unchanged.
    """
    if preset == "mono":
        luma = (77 * r + 150 * g + 29 * b + 128) >> 8
        return luma, luma, luma
    if preset == "warm":
        return _clamp_byte(r + 12), _clamp_byte(g + 3), _clamp_byte(b - 9)
    return r, g, b


# ---------------------------------------------------------------------------
# String literals recovered from the target's FieldRVA-backed byte blob
# (235 bytes) via XOR de-obfuscation: plaintext[k] = blob[start+k] ^ key.
# This matches T84d29266f2.m_5558f5ab53(start, length, key). See findings.md
# for the extraction method and the exact (start, length, key) tuple for each
# string, each confirmed against the live target's printed/thrown text.
# ---------------------------------------------------------------------------
_HELP_FLAG = "--help"
_HELP_LINE_1 = "PixelTone R G B brightness contrast preset"
_HELP_LINE_2 = "R/G/B: 0..255; brightness: -100..100; contrast: 0..200; preset: neutral|mono|warm"
_ERR_RANGE = "integer out of range"
_ERR_ARGC = "expected 6 arguments; use --help"
_ERR_PRESET = "unknown preset"
_ERR_PREFIX = "ERROR: "
_PRESET_NEUTRAL = "neutral"
_PRESET_MONO = "mono"
_PRESET_WARM = "warm"
_VALID_PRESETS = (_PRESET_NEUTRAL, _PRESET_MONO, _PRESET_WARM)
_OUTPUT_FORMAT = "{0},{1},{2}|{3:X8}"  # as used by the target's Console.WriteLine


def _parse_in_range(s, lo, hi):
    ok, value = _dotnet_int32_tryparse(s)
    if not ok or value < lo or value > hi:
        raise ArgumentError(_ERR_RANGE)
    return value


def _run(args):
    """Returns (stdout_text, stderr_text, exit_code). Text uses "\r\n" line
    endings throughout, matching Console.WriteLine's Environment.NewLine on
    the target's native Windows runtime."""
    if len(args) == 1 and args[0] == _HELP_FLAG:
        out = _HELP_LINE_1 + "\r\n" + _HELP_LINE_2 + "\r\n"
        return out, "", 0

    try:
        if len(args) != 6:
            raise ArgumentError(_ERR_ARGC)

        r = _parse_in_range(args[0], 0, 255)
        g = _parse_in_range(args[1], 0, 255)
        b = _parse_in_range(args[2], 0, 255)
        brightness = _parse_in_range(args[3], -100, 100)
        contrast = _parse_in_range(args[4], 0, 200)
        preset = args[5]

        if preset not in _VALID_PRESETS:
            raise ArgumentError(_ERR_PRESET)

        adj_r = _adjust_channel(r, brightness, contrast)
        adj_g = _adjust_channel(g, brightness, contrast)
        adj_b = _adjust_channel(b, brightness, contrast)

        out_r, out_g, out_b = _apply_preset(adj_r, adj_g, adj_b, preset)
        checksum = _fnv1a_like([out_r, out_g, out_b])

        line = "{0},{1},{2}|{3:08X}".format(out_r, out_g, out_b, checksum)
        return line + "\r\n", "", 0
    except ArgumentError as exc:
        return "", _ERR_PREFIX + exc.message + "\r\n", 2


def main(argv):
    stdout_text, stderr_text, exit_code = _run(argv)
    if stdout_text:
        sys.stdout.buffer.write(stdout_text.encode("utf-8"))
        sys.stdout.buffer.flush()
    if stderr_text:
        sys.stderr.buffer.write(stderr_text.encode("utf-8"))
        sys.stderr.buffer.flush()
    return exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
