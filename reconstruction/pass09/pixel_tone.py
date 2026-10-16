#!/usr/bin/env python3
"""
pixel_tone.py - Reimplementation of PixelTone.exe

PixelTone.exe is a heavily obfuscated .NET console utility that takes an RGB
color plus a brightness/contrast adjustment and a tone "preset", and prints
the adjusted color together with a checksum.

Usage (from --help, observed verbatim):
    PixelTone R G B brightness contrast preset
    R/G/B: 0..255; brightness: -100..100; contrast: 0..200; preset: neutral|mono|warm

See findings.md in this directory for the full reverse-engineering writeup,
including which parts of this implementation are empirically confirmed vs.
inferred vs. guessed.
"""

import sys

HELP_TEXT = (
    "PixelTone R G B brightness contrast preset\n"
    "R/G/B: 0..255; brightness: -100..100; contrast: 0..200; preset: neutral|mono|warm"
)

ERR_ARGCOUNT = "ERROR: expected 6 arguments; use --help"
ERR_RANGE = "ERROR: integer out of range"
# NOT empirically observed - best-effort guess, see findings.md.
ERR_PRESET = "ERROR: unknown preset; use --help"

PRESETS = ("neutral", "mono", "warm")

# (min, max) inclusive bounds for args[0..4]: R, G, B, brightness, contrast
BOUNDS = [
    (0, 255),
    (0, 255),
    (0, 255),
    (-100, 100),
    (0, 200),
]


class PixelToneError(Exception):
    """Mirrors the single ArgumentException thrown by the real program's
    argument-validation path (RegisterCallback / mode check)."""


def _strict_parse_int(s):
    """Hand-rolled integer parser.

    The real binary's argument parser (RegisterCallback) is NOT a call to
    the .NET Int32.TryParse BCL method (no such member reference exists in
    the assembly's metadata) - it is a small hand-written routine. We could
    not recover its exact grammar from the obfuscated IL, so this is a
    reasonable strict guess: optional leading '-', then one or more ASCII
    digits, nothing else (no leading '+', no whitespace, no underscores,
    no hex). See findings.md for confidence notes.
    """
    if s is None or s == "":
        raise ValueError("empty")
    neg = False
    i = 0
    if s[0] == "-":
        neg = True
        i = 1
    if i >= len(s):
        raise ValueError("no digits")
    digits = s[i:]
    if not digits.isdigit():
        raise ValueError("not a plain integer")
    value = int(digits)
    if neg:
        value = -value
    # Reject values that wouldn't fit a 32-bit signed int, matching the
    # real program's presumed use of `int` throughout.
    if value < -2147483648 or value > 2147483647:
        raise ValueError("overflow")
    return value


def _parse_and_validate(raw, bounds):
    lo, hi = bounds
    try:
        value = _strict_parse_int(raw)
    except ValueError:
        raise PixelToneError(ERR_RANGE)
    if value < lo or value > hi:
        raise PixelToneError(ERR_RANGE)
    return value


def _trunc_div(a, b):
    """Integer division truncating toward zero (C#/`int` semantics),
    rather than Python's floor-based `//`."""
    q = abs(a) // abs(b)
    if (a < 0) != (b < 0):
        q = -q
    return q


def _clamp(v, lo=0, hi=255):
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v


def _adjust_channel(channel, brightness, contrast):
    """Per-channel brightness/contrast adjustment.

    Empirically confirmed via black-box probing:
      - contrast is applied to the ORIGINAL channel value first, centered
        on 128: contrasted = (channel - 128) * contrast / 100 + 128
      - brightness is then ADDED (not scaled) on top of that.
      - the result is clamped to [0, 255].

    Confirmed data points (channel, brightness, contrast -> result):
      (128, 0,  100) -> 128   (identity baseline)
      (128, 20, 100) -> 148   (pure brightness: +20)
      (150, 0,  150) -> 161   (pure contrast: (150-128)*1.5+128=161)
      (128, 20, 150) -> 148   (contrast-then-brightness: (0)*1.5+128+20=148;
                               rules out brightness-then-contrast, which
                               would give 158)

    Integer truncation direction for the contrast division was NOT
    empirically distinguishable (all tested cases divided evenly); this
    uses C#-style truncation toward zero as the most likely intent given
    the whole program appears to use plain `int` arithmetic throughout.
    """
    contrasted = _trunc_div((channel - 128) * contrast, 100) + 128
    result = contrasted + brightness
    return _clamp(result)


def _apply_preset(r, g, b, preset):
    """Combine the three per-channel-adjusted values according to preset.

    - "neutral": pass the three adjusted channels through unchanged.
      Empirically confirmed (baseline test: 128,128,128,0,100,neutral ->
      128,128,128).
    - "mono": convert to grayscale using what empirically matches the
      standard ITU-R BT.601 luma weights (299/587/114 over 1000, integer
      truncated), applied to the already brightness/contrast-adjusted
      channels. Confirmed via (200,100,50,0,100,mono) -> 124,124,124:
      (200*299 + 100*587 + 50*114) / 1000 = 124200/1000 = 124 (exact
      integer truncation vs. rounding could not be distinguished since
      this case has no .5 boundary, but truncation is used here as the
      more common implementation choice for integer-only code).
    - "warm": NOT empirically tested - the execution budget was exhausted
      before this could be probed, and static analysis of RefreshToken's
      flattened/obfuscated IL could not be resolved to a confident
      formula (hidden operand-less opcodes made the real per-case
      arithmetic unrecoverable; see findings.md). The formula below is a
      PLACEHOLDER guess (shift red up / blue down by a fixed amount) and
      should be treated as UNVERIFIED and likely wrong in its exact
      magnitude.
    """
    if preset == "neutral":
        return r, g, b
    if preset == "mono":
        y = _trunc_div(r * 299 + g * 587 + b * 114, 1000)
        y = _clamp(y)
        return y, y, y
    if preset == "warm":
        # UNVERIFIED GUESS - see docstring above and findings.md.
        warm_shift = 16
        return _clamp(r + warm_shift), g, _clamp(b - warm_shift)
    raise PixelToneError(ERR_PRESET)


def _fnv1a32(data):
    """32-bit FNV-1a hash. Empirically confirmed EXACTLY (all 4 observed
    (R,G,B)->hash pairs match) as the algorithm behind the trailing
    checksum field, applied to the 3 raw output bytes [R, G, B]."""
    h = 0x811C9DC5  # 2166136261
    for byte in data:
        h ^= byte
        h = (h * 0x01000193) & 0xFFFFFFFF  # 16777619
    return h


def run(argv):
    """Runs the program; returns (stdout_text_or_None, stderr_text_or_None, exit_code)."""
    if len(argv) == 1 and argv[0] == "--help":
        return HELP_TEXT, None, 0

    if len(argv) != 6:
        return None, ERR_ARGCOUNT, 2

    try:
        r = _parse_and_validate(argv[0], BOUNDS[0])
        g = _parse_and_validate(argv[1], BOUNDS[1])
        b = _parse_and_validate(argv[2], BOUNDS[2])
        brightness = _parse_and_validate(argv[3], BOUNDS[3])
        contrast = _parse_and_validate(argv[4], BOUNDS[4])
        preset = argv[5]
        if preset not in PRESETS:
            raise PixelToneError(ERR_PRESET)

        adj_r = _adjust_channel(r, brightness, contrast)
        adj_g = _adjust_channel(g, brightness, contrast)
        adj_b = _adjust_channel(b, brightness, contrast)

        final_r, final_g, final_b = _apply_preset(adj_r, adj_g, adj_b, preset)

        checksum = _fnv1a32(bytes([final_r & 0xFF, final_g & 0xFF, final_b & 0xFF]))
        stdout_line = "{0},{1},{2}|{3:08X}".format(final_r, final_g, final_b, checksum)
        return stdout_line, None, 0
    except PixelToneError as e:
        return None, str(e), 2


def main():
    argv = sys.argv[1:]
    out, err, code = run(argv)
    if out is not None:
        print(out)
    if err is not None:
        print(err, file=sys.stderr)
    sys.exit(code)


if __name__ == "__main__":
    main()
