#!/usr/bin/env python3
"""
Faithful Python reimplementation of PixelTone.exe, reverse engineered by
static analysis (REA inspect-managed-members on the obfuscated .NET IL)
plus 8 black-box executions of the real binary.

See findings.md in the same directory for the full reasoning, the evidence
for each piece of behavior, and an honest confidence assessment. In short:

    PixelTone R G B brightness contrast preset

take three 0..255 colour channels, a brightness offset (-100..100), a
contrast percentage (0..200) and a preset name (neutral|mono|warm);
apply brightness/contrast per channel, then the preset transform; print
"R,G,B|HHHHHHHH" (the result triple and an 8-hex-digit FNV-1a-32 checksum
of the three result bytes) to stdout and exit 0. Usage/argument errors
are printed to stderr prefixed with "ERROR: " and exit 2.

Confidence notes (see findings.md for detail):
  - --help text, arg-count check, numeric range/parse error text, the
    brightness formula, the contrast formula and the checksum algorithm
    were all confirmed exactly against the real binary's output.
  - The "mono" preset formula is the standard integer BT.601 luma formula
    and matched the one sample tested exactly.
  - The "warm" preset formula and the "invalid preset" error message are
    best-effort reconstructions fitted to limited/no direct evidence -
    flagged as uncertain.
  - Two internal anti-debugging/integrity checks in the real binary
    (Debugger.IsAttached and a second unidentified check) are NOT
    reproduced here: under ordinary, non-instrumented execution (the only
    way this program was ever run during recon) they never fire.
"""
import re
import sys

HELP_TEXT = (
    "PixelTone R G B brightness contrast preset\n"
    "R/G/B: 0..255; brightness: -100..100; contrast: 0..200; preset: neutral|mono|warm"
)

ARG_COUNT_ERROR = "expected 6 arguments; use --help"
RANGE_ERROR = "integer out of range"
# UNVERIFIED best guess - the real binary's exact text was never observed
# (no execution budget was left to probe an invalid preset). See findings.md.
INVALID_PRESET_ERROR = "invalid preset; use neutral, mono, or warm"

INT32_MIN = -2147483648
INT32_MAX = 2147483647

# Approximates .NET's int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out _)
# NumberStyles.Integer (confirmed from the IL constant 7) = AllowLeadingWhite |
# AllowTrailingWhite | AllowLeadingSign: optional surrounding whitespace, an
# optional single leading +/- sign, ASCII digits only, no decimal point, no
# thousands separators, no hex. Also fails (like TryParse) on Int32 overflow.
_INT_RE = re.compile(r'^[ \t\r\n\f\v]*([+-]?)([0-9]+)[ \t\r\n\f\v]*$')


def try_parse_int32(s):
    m = _INT_RE.match(s)
    if not m:
        return None
    sign, digits = m.groups()
    val = int(digits)
    if sign == '-':
        val = -val
    if val < INT32_MIN or val > INT32_MAX:
        return None
    return val


class PixelToneError(Exception):
    """Mirrors the single ArgumentException/catch-all path in the real binary."""


def parse_ranged_arg(s, lo, hi):
    v = try_parse_int32(s)
    if v is None or v < lo or v > hi:
        # The real binary throws the SAME generic message for a parse failure,
        # a below-minimum value, or an above-maximum value - there is no
        # per-field wording (confirmed: the shared helper method has no way
        # to embed the field name or bounds in the message; no ToString/
        # string-formatting call exists anywhere in the assembly).
        raise PixelToneError(RANGE_ERROR)
    return v


def clamp_byte(v):
    if v < 0:
        return 0
    if v > 255:
        return 255
    return v


def _trunc_div(numerator, denominator):
    """C#/.NET int division: truncates toward zero (not Python's floor //)."""
    q = abs(numerator) // abs(denominator)
    if (numerator < 0) != (denominator < 0):
        q = -q
    return q


def apply_brightness_contrast(value, brightness, contrast):
    """
    Confirmed by direct testing:
      - contrast=100 (unity), brightness=+30: channel 10 -> 40 (plain add,
        not a percentage scale) and channel 240 -> 255 (clamped), proving a
        simple additive brightness term with 0..255 clamping.
      - brightness=0, contrast=133 on channels at distance +75/+50/-50 from
        128 produced exactly the truncating-integer-division result
        (128 + (value-128)*contrast/100, dropping any fractional remainder
        toward zero), ruling out round-half-up and round-half-even.
    The combined formula (and which of brightness/contrast is "really"
    applied first) was inferred from the call graph (both are funnelled
    through one helper call per channel before the preset step) - the two
    tests above never varied both at once, so the exact order when BOTH
    are non-default simultaneously is an assumption, not a direct
    observation. Contrast-around-128 then add brightness then clamp once
    is the conventional order and is what's implemented here.
    """
    diff = value - 128
    scaled = _trunc_div(diff * contrast, 100)
    return clamp_byte(128 + scaled + brightness)


def apply_preset(r, g, b, preset):
    if preset == "neutral":
        # Confirmed: brightness=0, contrast=100, preset=neutral is a pure passthrough.
        return r, g, b
    if preset == "mono":
        # Confirmed against one sample: (200,100,50) -> (124,124,124), which is
        # exactly the standard integer ITU-R BT.601 luma formula
        # floor((299*R + 587*G + 114*B) / 1000) replicated into all 3 channels.
        y = clamp_byte(_trunc_div(299 * r + 587 * g + 114 * b, 1000))
        return y, y, y
    if preset == "warm":
        # UNCERTAIN: fitted to a single sample (200,100,50) -> (212,103,41),
        # which is consistent with R*106/100, G*103/100, B*82/100 (integer,
        # truncating division) - but that sample divides evenly by 100, so
        # the true denominator/rounding rule (e.g. /1000 with different
        # numerators, or a different rounding mode) cannot be distinguished
        # from this one data point. Treat this preset's exact numbers with
        # low confidence; only the qualitative direction (warmer: R up,
        # G slightly up, B down) is well supported.
        r2 = clamp_byte(_trunc_div(r * 106, 100))
        g2 = clamp_byte(_trunc_div(g * 103, 100))
        b2 = clamp_byte(_trunc_div(b * 82, 100))
        return r2, g2, b2
    # UNVERIFIED: real wording of this message was never observed.
    raise PixelToneError(INVALID_PRESET_ERROR)


def fnv1a32(byte_values):
    """
    Confirmed EXACTLY against 5 independent (R,G,B)->checksum samples
    gathered from real runs: standard 32-bit FNV-1a (offset basis
    2166136261, prime 16777619) over the three result bytes in R,G,B
    order. All 5 samples matched bit-for-bit; this is about as close to
    certain as black-box testing gets.
    """
    h = 2166136261
    for b in byte_values:
        h = (h ^ (b & 0xFF)) & 0xFFFFFFFF
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def run(argv):
    """Returns (exit_code, stdout_text_or_None, stderr_text_or_None)."""
    if argv == ["--help"]:
        return 0, HELP_TEXT + "\n", None

    if len(argv) != 6:
        return 2, None, "ERROR: " + ARG_COUNT_ERROR + "\n"

    try:
        r = parse_ranged_arg(argv[0], 0, 255)
        g = parse_ranged_arg(argv[1], 0, 255)
        b = parse_ranged_arg(argv[2], 0, 255)
        brightness = parse_ranged_arg(argv[3], -100, 100)
        contrast = parse_ranged_arg(argv[4], 0, 200)
        preset = argv[5]

        r2 = apply_brightness_contrast(r, brightness, contrast)
        g2 = apply_brightness_contrast(g, brightness, contrast)
        b2 = apply_brightness_contrast(b, brightness, contrast)

        r3, g3, b3 = apply_preset(r2, g2, b2, preset)

        checksum = fnv1a32([r3, g3, b3])
        out = f"{r3},{g3},{b3}|{checksum:08X}\n"
        return 0, out, None
    except PixelToneError as ex:
        return 2, None, f"ERROR: {ex}\n"


def main():
    exit_code, out, err = run(sys.argv[1:])
    if out is not None:
        sys.stdout.write(out)
    if err is not None:
        sys.stderr.write(err)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
