#!/usr/bin/env python3
"""
Faithful Python reimplementation of PixelTone.exe (a .NET console program),
reverse engineered via static analysis (REA + manual CIL disassembly).

CLI contract:
    PixelTone.exe R G B brightness contrast preset
        R, G, B        integers in [0, 255]
        brightness     integer in [-100, 100]
        contrast       integer in [0, 200]
        preset         one of: neutral | mono | warm   (case sensitive)

    PixelTone.exe --help
        prints usage information, exit code 0

Behavior:
    - exactly 1 argument equal to "--help"  -> print usage, exit 0
    - exactly 6 arguments                   -> validate & process, exit 0 on success
    - anything else (0, 2-5, or 7+ args,
      or 1 argument that isn't "--help")    -> "ERROR: expected 6 arguments; use --help", exit 2

Processing (6-argument form):
    1. Parse R, G, B as integers in [0,255]; brightness in [-100,100]; contrast in [0,200].
       Any parse failure or out-of-range value -> "ERROR: integer out of range", exit 2.
    2. preset (6th argument) must be exactly "neutral", "mono" or "warm";
       otherwise -> "ERROR: unknown preset", exit 2.
    3. Apply brightness/contrast adjustment to each of R, G, B independently:
           adjusted = clamp( (component - 128) * contrast // 100 [C-style trunc] + 128 + brightness, 0, 255 )
    4. Apply the preset transform to (adjR, adjG, adjB):
           neutral -> (adjR, adjG, adjB) unchanged
           mono    -> (gray, gray, gray)  where gray = (77*adjR + 150*adjG + 29*adjB + 128) >> 8
           warm    -> (clamp(adjR+12), clamp(adjG+3), clamp(adjB-9))   each clamped to [0,255]
    5. Compute a 32-bit checksum over the resulting 3 values using an FNV-1a-style mix:
           h = 0x811C9DC5 (2166136261)
           for v in (r2, g2, b2): h = ((h ^ v) * 0x01000193) & 0xFFFFFFFF   # 16777619
    6. Print "{r2},{g2},{b2}|{h:X8}" to stdout, exit 0.

All error messages are printed to stderr as "ERROR: <message>" and the process exits with code 2.
Line endings match the original Windows console program's Console.WriteLine (\r\n).

See findings.md in the same directory for the full reverse-engineering methodology,
including how each piece of this logic was recovered and the confidence level for each part.
"""

import sys


EOL = "\r\n"


class PtArgumentError(Exception):
    """Mirrors the single System.ArgumentException type used throughout the
    original program for all user-facing validation failures."""
    pass


def _dotnet_trunc_div(a: int, b: int) -> int:
    """Integer division truncating toward zero, matching C#/.NET's `/` operator
    for signed integers (Python's `//` floors toward negative infinity instead)."""
    q = abs(a) // abs(b)
    if (a < 0) != (b < 0):
        q = -q
    return q


def _clamp_byte(v: int) -> int:
    if v < 0:
        return 0
    if v > 255:
        return 255
    return v


def _try_parse_int32(s: str):
    """Reimplementation of .NET's int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture).

    NumberStyles.Integer permits: optional leading whitespace, an optional single
    leading '+' or '-' sign, one or more ASCII digits, optional trailing whitespace.
    No decimal point, no thousands separators, no exponent. Values outside the
    Int32 range fail (TryParse never throws on overflow).

    Returns (True, value) on success, (False, None) on failure.
    """
    if s is None:
        return False, None
    stripped = s.strip()
    if not stripped:
        return False, None
    sign = 1
    i = 0
    if stripped[0] in "+-":
        if stripped[0] == "-":
            sign = -1
        i = 1
    digits = stripped[i:]
    if not digits or not digits.isdigit():
        return False, None
    # isdigit() in Python also accepts some non-ASCII digit characters; guard
    # against that to stay faithful to InvariantCulture's ASCII-only digits.
    if not all(ch in "0123456789" for ch in digits):
        return False, None
    value = sign * int(digits)
    if value < -2147483648 or value > 2147483647:
        return False, None
    return True, value


def register_callback(raw: str, min_value: int, max_value: int) -> int:
    """Parses `raw` as an Int32 and validates it lies within [min_value, max_value].
    Both failure modes (unparsable, or out of range) raise the exact same error,
    matching the original binary's single shared error message."""
    ok, value = _try_parse_int32(raw)
    if not ok or value < min_value or value > max_value:
        raise PtArgumentError("integer out of range")
    return value


def authenticate_session(component: int, brightness: int, contrast: int) -> int:
    """Per-channel brightness/contrast adjustment, clamped to the byte range."""
    val = _dotnet_trunc_div((component - 128) * contrast, 100) + 128 + brightness
    return _clamp_byte(val)


def refresh_token(r: int, g: int, b: int, preset: str):
    """Applies the preset color transform. Caller must have already validated
    that `preset` is one of "neutral", "mono", "warm"."""
    if preset == "mono":
        gray = (77 * r + 150 * g + 29 * b + 128) >> 8
        return [gray, gray, gray]
    elif preset == "warm":
        return [_clamp_byte(r + 12), _clamp_byte(g + 3), _clamp_byte(b - 9)]
    else:
        return [r, g, b]


def initialize_cache(arr) -> int:
    """32-bit FNV-1a-style mixing checksum over the 3 result values."""
    h = 2166136261  # FNV-1a 32-bit offset basis
    for v in arr:
        h = ((h ^ v) * 16777619) & 0xFFFFFFFF  # FNV-1a 32-bit prime
    return h


def print_help(out) -> int:
    out.write("PixelTone R G B brightness contrast preset" + EOL)
    out.write("R/G/B: 0..255; brightness: -100..100; contrast: 0..200; preset: neutral|mono|warm" + EOL)
    return 0


def run(args, stdout, stderr) -> int:
    # Anti-debug / self-integrity checks from the original binary are always
    # true/false respectively under normal execution (no attached debugger,
    # unmodified algorithm) and are intentionally not reproduced here -- see
    # findings.md for details.

    if len(args) == 1 and args[0] == "--help":
        return print_help(stdout)

    try:
        if len(args) != 6:
            raise PtArgumentError("expected 6 arguments; use --help")

        r = register_callback(args[0], 0, 255)
        g = register_callback(args[1], 0, 255)
        b = register_callback(args[2], 0, 255)
        brightness = register_callback(args[3], -100, 100)
        contrast = register_callback(args[4], 0, 200)
        preset = args[5]

        if preset not in ("neutral", "mono", "warm"):
            raise PtArgumentError("unknown preset")

        adj_r = authenticate_session(r, brightness, contrast)
        adj_g = authenticate_session(g, brightness, contrast)
        adj_b = authenticate_session(b, brightness, contrast)

        result = refresh_token(adj_r, adj_g, adj_b, preset)
        checksum = initialize_cache(result)

        stdout.write("{0},{1},{2}|{3:08X}".format(result[0], result[1], result[2], checksum) + EOL)
        return 0
    except PtArgumentError as ex:
        stderr.write("ERROR: " + str(ex) + EOL)
        return 2


def main():
    # Force exact "\r\n" line endings (matching Console.WriteLine on Windows)
    # regardless of platform or Python's default newline translation, which
    # would otherwise mangle an explicit "\r\n" written to a text-mode stream
    # whose line separator is already "\r\n" (producing "\r\r\n").
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(newline="")
        except Exception:
            pass
    exit_code = run(sys.argv[1:], sys.stdout, sys.stderr)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
