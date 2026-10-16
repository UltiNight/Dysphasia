#!/usr/bin/env python3
"""
Python reimplementation of PixelTone.exe, reverse engineered by static
analysis (REA inspect-managed-artifact / inspect-managed-members) plus eight
direct executions of the original binary.

See findings.md in the same directory for the full writeup, evidence trail,
and an explicit confidence assessment. In short:

  - The CLI contract, argument validation, --help text, error messages,
    exit codes, and the "neutral" preset color-transform formula are all
    verified against the real binary and are HIGH confidence.
  - The "mono" preset's grayscale formula is a best-effort fit to a single
    observed sample (MEDIUM confidence: it exactly reproduces that one
    sample using standard ITU-R BT.601 luma weights, but was not cross
    checked against a second input).
  - The "warm" preset's transform was never exercised against the real
    binary (we ran out of the 8-execution budget before testing it). The
    implementation below is a GUESS (LOW confidence) at a plausible "shift
    toward orange" effect; it is almost certainly not byte-exact.
  - The trailing "|XXXXXXXX" 8-hex-digit field in the success output is
    produced by SHA-256-based logic inside the real binary (confirmed via
    static analysis: System.Security.Cryptography.SHA256.Create() and
    ComputeHash() are called twice from the method that builds it) that
    could not be recovered from only two observed samples -- a
    cryptographic hash is not interpolable from a couple of input/output
    pairs. The value produced here is a PLACEHOLDER that reproduces the
    *format* (8 uppercase hex chars) but will NOT match the real binary's
    checksum except by chance. This is the one part of the contract this
    reimplementation cannot faithfully reproduce.
"""

import sys
import hashlib

EXIT_OK = 0
EXIT_ERROR = 2

USAGE_LINE_1 = "PixelTone R G B brightness contrast preset"
USAGE_LINE_2 = (
    "R/G/B: 0..255; brightness: -100..100; contrast: 0..200; "
    "preset: neutral|mono|warm"
)

PRESETS = ("neutral", "mono", "warm")

R_MIN, R_MAX = 0, 255
BRIGHTNESS_MIN, BRIGHTNESS_MAX = -100, 100
CONTRAST_MIN, CONTRAST_MAX = 0, 200


class PixelToneError(Exception):
    """Mirrors the single generic ArgumentException-based error path
    observed in the real binary: every validation failure is caught by one
    handler that prints "ERROR: {message}" to stderr and exits with
    EXIT_ERROR (2)."""


def _trunc_div(numerator: int, denominator: int) -> int:
    """C#/CIL integer division truncates toward zero (unlike Python's
    floor-division //, which truncates toward negative infinity). This
    matters because contrast scaling multiplies a possibly-negative
    (old-128) term before dividing by 100."""
    q = abs(numerator) // abs(denominator)
    if (numerator < 0) != (denominator < 0):
        q = -q
    return q


def _ceil_div_nonneg(numerator: int, denominator: int) -> int:
    """Ceiling division for non-negative numerator/denominator, used by the
    (unverified) mono-preset luma formula below."""
    return -((-numerator) // denominator)


def _parse_bounded_int(raw: str, lo: int, hi: int) -> int:
    """Reproduces the behavior observed for all five numeric arguments
    (R, G, B, brightness, contrast): a value that fails to parse as an
    integer, OR parses but falls outside [lo, hi], both produce the exact
    same generic message "integer out of range" (confirmed: a literal
    'abc' and a literal '300' with R's range of 0..255 both printed
    "ERROR: integer out of range" with exit code 2 -- there is no separate
    "could not parse" message)."""
    try:
        value = int(raw.strip())
    except (ValueError, OverflowError):
        raise PixelToneError("integer out of range")
    if value < lo or value > hi:
        raise PixelToneError("integer out of range")
    return value


def _transform_channel(old: int, brightness: int, contrast: int) -> int:
    """Verified formula (reverse engineered from
    128,64,32,10,120,neutral -> 138,62,23):

        new = clamp(((old - 128) * contrast) / 100 + 128 + brightness, 0, 255)

    using C#-style truncating integer division.
    """
    value = _trunc_div((old - 128) * contrast, 100) + 128 + brightness
    return max(0, min(255, value))


def _apply_preset(r: int, g: int, b: int, brightness: int, contrast: int, preset: str):
    """Applies the per-channel brightness/contrast transform, then applies
    any preset-specific post-processing.

    neutral: verified HIGH confidence (plain per-channel transform).

    mono: MEDIUM confidence. Observed sample:
        255,0,128,-50,200,mono -> 86,86,86
      The per-channel transform (clamped) of (255,0,128) with
      brightness=-50, contrast=200 is (255, 0, 78). Standard ITU-R BT.601
      integer luma weights (299, 587, 114)/1000 applied to that clamped
      triple with a ceiling (round-up) division reproduce 86 exactly:
          ceil((255*299 + 0*587 + 78*114) / 1000) = ceil(85.137) = 86
      This was verified against exactly one sample; a different rounding
      convention or weight set could coincidentally match that single
      sample too, so treat this as a plausible-but-unconfirmed guess for
      any other input.

    warm: LOW confidence / UNVERIFIED. Never exercised against the real
      binary. Implemented here as a speculative "shift toward orange"
      (push red up, blue down by a fixed amount after the normal
      transform). This is a guess, not a reverse-engineered fact.
    """
    rc = _transform_channel(r, brightness, contrast)
    gc = _transform_channel(g, brightness, contrast)
    bc = _transform_channel(b, brightness, contrast)

    if preset == "neutral":
        return rc, gc, bc

    if preset == "mono":
        luma_num = rc * 299 + gc * 587 + bc * 114
        gray = _ceil_div_nonneg(luma_num, 1000)
        gray = max(0, min(255, gray))
        return gray, gray, gray

    if preset == "warm":
        # SPECULATIVE -- not reverse engineered, see docstring above.
        warm_shift = 10
        rc2 = max(0, min(255, rc + warm_shift))
        bc2 = max(0, min(255, bc - warm_shift))
        return rc2, gc, bc2

    # Should be unreachable: preset is validated before this is called.
    raise PixelToneError("unknown preset")


def _placeholder_checksum(rc: int, gc: int, bc: int) -> str:
    """UNRECOVERED. The real binary derives its trailing 8-hex-digit field
    using SHA-256 (System.Security.Cryptography.SHA256.Create() /
    ComputeHash(), called twice, per static analysis of the
    InitializeCache-named method) over some byte encoding of the computed
    color (and very possibly an embedded secret salt/string baked into the
    binary, which static analysis could not recover either). Two observed
    input/output pairs are nowhere near enough to invert a cryptographic
    hash, and no simple byte-layout guess (raw bytes, decimal strings,
    little/big-endian 32-bit ints, with or without the preset name, single
    or double SHA-256, truncated from the front/back or XOR-folded) matched
    either observed sample.

    This function therefore only reproduces the *shape* of the field (8
    uppercase hex characters) using an arbitrary SHA-256-based computation.
    It will NOT match the real binary's output except by chance. Treat any
    caller-visible checksum value from this script as cosmetic only.
    """
    digest = hashlib.sha256(f"{rc},{gc},{bc}".encode("ascii")).digest()
    return digest[:4].hex().upper()


def run(argv) -> int:
    # --help special case: observed to require exactly one argument equal
    # to "--help" (verified). Behavior with "--help" mixed among other
    # arguments was never tested; inferred to NOT trigger help (falls
    # through to the "expected 6 arguments" / normal 6-arg parsing path)
    # based on the overall control-flow shape seen via static analysis.
    if len(argv) == 1 and argv[0] == "--help":
        print(USAGE_LINE_1)
        print(USAGE_LINE_2)
        return EXIT_OK

    try:
        if len(argv) != 6:
            raise PixelToneError("expected 6 arguments; use --help")

        r = _parse_bounded_int(argv[0], R_MIN, R_MAX)
        g = _parse_bounded_int(argv[1], R_MIN, R_MAX)
        b = _parse_bounded_int(argv[2], R_MIN, R_MAX)
        brightness = _parse_bounded_int(argv[3], BRIGHTNESS_MIN, BRIGHTNESS_MAX)
        contrast = _parse_bounded_int(argv[4], CONTRAST_MIN, CONTRAST_MAX)

        preset = argv[5]
        if preset not in PRESETS:
            raise PixelToneError("unknown preset")

        rc, gc, bc = _apply_preset(r, g, b, brightness, contrast, preset)
        checksum = _placeholder_checksum(rc, gc, bc)
        print(f"{rc},{gc},{bc}|{checksum}")
        return EXIT_OK

    except PixelToneError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_ERROR


def main() -> None:
    sys.exit(run(sys.argv[1:]))


if __name__ == "__main__":
    main()
