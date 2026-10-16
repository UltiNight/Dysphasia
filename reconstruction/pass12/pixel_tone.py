#!/usr/bin/env python3
"""
pixel_tone.py -- Python reimplementation of PixelTone.exe

Reconstructed via closed-box reverse engineering (static .NET metadata
analysis with REA + 8 direct executions of the original binary).  See
findings.md in the same directory for the full writeup, including an
honest list of what is VERIFIED by direct observation vs. GUESSED from
structural inference.

-----------------------------------------------------------------------
CONFIRMED BY DIRECT EXECUTION (high confidence):
  * Usage line (exact text, from `PixelTone.exe --help`):
        PixelTone R G B brightness contrast preset
        R/G/B: 0..255; brightness: -100..100; contrast: 0..200; preset: neutral|mono|warm
  * Exactly 6 positional arguments are required; any other count (and
    this was tested with 0 args) produces:
        stderr: "ERROR: expected 6 arguments; use --help"
        exit code: 2
        stdout: empty
  * `--help` as args[0] (tested as the sole argument) prints the two
    usage lines to stdout and exits 0, and this check happens BEFORE
    the 6-argument-count check (confirmed by the metadata call-graph
    order: the string compared against args[0] is decoded and checked
    with op_Equality before the "expected 6 arguments" exception is
    even constructed).
  * Successful output format: "R,G,B|HHHHHHHH\r\n" on stdout, exit 0,
    where HHHHHHHH is 8 uppercase hex digits (confirmed by an exact
    output containing a letter: "B0871470"). Windows CRLF line endings
    were confirmed by inspecting raw captured bytes.
  * "neutral" preset + brightness/contrast formula, confirmed exactly
    by two independent test vectors:
        (R,G,B,br,ct)=(128,128,128,0,100) -> 128,128,128
        (R,G,B,br,ct)=(10,100,250,20,150) -> 0,106,255
    which exactly matches:
        factor = contrast / 100.0
        out    = clamp(round((value - 128) * factor + 128) + brightness, 0, 255)
  * "mono" preset, confirmed exactly by:
        (R,G,B)=(200,100,50) with br=0,ct=100 -> 124,124,124
    which matches luma = 0.299*R + 0.587*G + 0.114*B (ITU-R BT.601),
    applied identically to all three output channels, run through the
    same brightness/contrast formula above.
  * "warm" preset, confirmed exactly by:
        (R,G,B)=(200,100,50) with br=0,ct=100 -> 212,103,41
    which matches R*1.06, G*1.03, B*0.82 (each run through the same
    brightness/contrast formula above).
  * Changing the preset string while holding R,G,B,brightness,contrast
    fixed (128,128,128,0,100, "neutral" vs "mono") produced the exact
    SAME hash (56195437) even though these are different presets. This
    proves the trailing hash does NOT depend on the preset string, and
    (given the metadata call graph: the hash routine takes a single
    int[] argument that is almost certainly the already-computed
    output RGB array) most likely depends only on the final output
    RGB triple.

NOT RECOVERED (explicitly flagged low confidence -- see findings.md):
  * The exact byte encoding fed into the two chained SHA-256 calls that
    produce the trailing 8-hex-digit "checksum", and therefore the
    EXACT hash value this program would print on a successful run.
    This was extensively brute-forced offline against byte/string
    encodings of the output RGB triple and did not reproduce either of
    the two observed hash values (56195437 for 128,128,128 and
    B0871470 for 0,106,255). The hash logic below is a structurally
    plausible placeholder (double SHA-256 of the 3 output bytes) and
    is almost certainly NOT bit-exact to the real binary. Everything
    else in this file (argument parsing, validation, color math, error
    text for the one verified error, exit codes) is intended to be
    exact.
  * The exact wording of error messages for: invalid/out-of-range
    numeric arguments, and invalid preset strings. Only the
    "expected 6 arguments; use --help" message was directly observed.
    Placeholders are used for the others (see ERR_* constants below)
    and are marked as guesses.
  * Whether all validation errors share exit code 2 (only confirmed
    for the argument-count case) -- assumed uniform based on the
    call-graph showing all of these throws funnel into one shared
    catch block that is textually identical to the one that produced
    the confirmed "expected 6 arguments" / exit-2 case.
  * Exact NumberStyles used for integer parsing (assumed standard
    "Integer" style: optional leading/trailing whitespace, optional
    leading +/- sign, digits only, no thousands separators, no decimal
    point) and exact rounding mode (assumed round-half-away-from-zero;
    none of the verified test vectors had a genuine .5 tie to
    disambiguate round-half-to-even vs round-half-away-from-zero).
"""

import sys
import hashlib
import re

PROG_NAME = "PixelTone"

USAGE_LINE_1 = "PixelTone R G B brightness contrast preset"
USAGE_LINE_2 = ("R/G/B: 0..255; brightness: -100..100; contrast: 0..200; "
                "preset: neutral|mono|warm")

ERR_ARGCOUNT = "expected 6 arguments; use --help"
# GUESS (unverified): exact wording for these two error types is unknown.
ERR_INVALID_NUMBER = "invalid numeric argument"
ERR_INVALID_PRESET = "invalid preset"

EXIT_OK = 0
EXIT_ERROR = 2  # assumed uniform for all validation-type errors

PRESETS = ("neutral", "mono", "warm")

_INT_RE = re.compile(r'^[ \t\r\n]*([+-]?\d+)[ \t\r\n]*$')

INT32_MIN = -2147483648
INT32_MAX = 2147483647


class PixelToneError(Exception):
    """Mirrors the ArgumentException thrown internally by the original
    program; its .Message is what gets printed after 'ERROR: '."""
    pass


def _try_parse_int32(s):
    """Emulates int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out result).

    Returns the parsed int, or None if parsing fails (including on
    Int32 overflow)."""
    m = _INT_RE.match(s)
    if not m:
        return None
    try:
        value = int(m.group(1))
    except ValueError:
        return None
    if value < INT32_MIN or value > INT32_MAX:
        return None
    return value


def _round_half_away_from_zero(x):
    if x >= 0:
        return int(x + 0.5)
    else:
        return -int(-x + 0.5)


def _clamp(v, lo, hi):
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v


def register_callback(raw_value, min_v, max_v):
    """Parses raw_value as an Int32 and validates it falls within
    [min_v, max_v] inclusive. Raises PixelToneError on any failure,
    matching the single shared throw-site observed in the metadata
    call graph for this helper."""
    parsed = _try_parse_int32(raw_value)
    if parsed is None or parsed < min_v or parsed > max_v:
        raise PixelToneError(ERR_INVALID_NUMBER)
    return parsed


def apply_preset(r, g, b, preset):
    """Returns (valueR, valueG, valueB) as floats, pre brightness/contrast,
    for the given preset. 'neutral' passes the channels through
    unchanged; 'mono' replaces all three with the BT.601 luma; 'warm'
    scales each channel independently."""
    if preset == "neutral":
        return float(r), float(g), float(b)
    elif preset == "mono":
        luma = 0.299 * r + 0.587 * g + 0.114 * b
        return luma, luma, luma
    elif preset == "warm":
        return r * 1.06, g * 1.03, b * 0.82
    else:
        raise PixelToneError(ERR_INVALID_PRESET)


def tone_channel(value, brightness, contrast):
    factor = contrast / 100.0
    scaled = (value - 128.0) * factor + 128.0 + brightness
    return _clamp(_round_half_away_from_zero(scaled), 0, 255)


def compute_checksum(out_rgb):
    """BEST-EFFORT PLACEHOLDER -- NOT verified to match PixelTone.exe.

    Structurally informed by the metadata (two chained SHA-256 calls
    over a single int[] argument, i.e. almost certainly the output RGB
    triple), but the exact byte encoding could not be recovered from
    black-box testing. Extensive offline brute-forcing of plausible
    byte/string encodings of the output triple did not reproduce either
    of the two observed hash values. This function will NOT produce
    byte-identical hashes to the real binary; everything else in this
    module is intended to be exact. See findings.md."""
    data = bytes(out_rgb)
    h1 = hashlib.sha256(data).digest()
    h2 = hashlib.sha256(h1).digest()
    return int.from_bytes(h2[0:4], "big")


def _write_stdout(line):
    sys.stdout.write(line + "\r\n")
    sys.stdout.flush()


def _write_stderr(line):
    sys.stderr.write(line + "\r\n")
    sys.stderr.flush()


def run(argv):
    """argv is the list of arguments AFTER the program name (i.e. what
    Main(string[] args) receives in .NET), matching sys.argv[1:]."""

    # --help bypasses the 6-argument-count check entirely, and is only
    # checked against args[0] (verified: tested with "--help" as the
    # sole argument). Whether trailing extra arguments after "--help"
    # are tolerated was not tested; this implementation assumes they
    # are (matches the simplest reading of the metadata call order).
    if len(argv) >= 1 and argv[0] == "--help":
        _write_stdout(USAGE_LINE_1)
        _write_stdout(USAGE_LINE_2)
        return EXIT_OK

    try:
        if len(argv) != 6:
            raise PixelToneError(ERR_ARGCOUNT)

        r_raw, g_raw, b_raw, br_raw, ct_raw, preset = argv

        r = register_callback(r_raw, 0, 255)
        g = register_callback(g_raw, 0, 255)
        b = register_callback(b_raw, 0, 255)
        brightness = register_callback(br_raw, -100, 100)
        contrast = register_callback(ct_raw, 0, 200)

        if preset not in PRESETS:
            raise PixelToneError(ERR_INVALID_PRESET)

        vr, vg, vb = apply_preset(r, g, b, preset)

        outR = tone_channel(vr, brightness, contrast)
        outG = tone_channel(vg, brightness, contrast)
        outB = tone_channel(vb, brightness, contrast)

        checksum = compute_checksum((outR, outG, outB))

        _write_stdout("{0},{1},{2}|{3:08X}".format(outR, outG, outB, checksum))
        return EXIT_OK

    except PixelToneError as ex:
        _write_stderr("ERROR: " + str(ex))
        return EXIT_ERROR


def main():
    exit_code = run(sys.argv[1:])
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
