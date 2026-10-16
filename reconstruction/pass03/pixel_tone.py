#!/usr/bin/env python3
"""
pixel_tone.py -- independent reimplementation of PixelTone.exe's observable
CLI behavior (artifacts/protected-p1p2p3/PixelTone.exe), reconstructed purely
from static analysis (REA managed-metadata/CIL inspection + a supplementary
hand-written CIL decoder) plus a small number of confirmatory live probes.

See findings.md in this directory for full evidence and reasoning.

No third-party dependencies. Python 3.

Usage mirrors the target exactly:
    pixel_tone.py --help
    pixel_tone.py R G B brightness contrast preset
"""
import sys


class ArgError(Exception):
    """Mirrors the target's use of System.ArgumentException for all
    user-facing validation failures. Only the .Message text matters for
    observable behavior (stdout/stderr bytes), so this is a plain str-bearing
    exception."""
    pass


# ---------------------------------------------------------------------------
# Int32.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out v)
# emulation. NumberStyles.Integer = AllowLeadingWhite | AllowTrailingWhite |
# AllowLeadingSign (0x1 | 0x2 | 0x4 == 7), which is exactly the constant the
# target pushes before calling CultureInfo.get_InvariantCulture() and
# Int32.TryParse (REA call_edges 0x06000005 -> 0x0a000002/0x0a000003).
# ---------------------------------------------------------------------------
_ASCII_DIGITS = set("0123456789")
INT32_MIN = -2147483648
INT32_MAX = 2147483647


def _try_parse_int32(s):
    """Returns an int on success, or None on failure (mirrors TryParse's
    bool return without using the out-parameter)."""
    if s is None:
        return None
    n = len(s)
    i = 0
    while i < n and s[i].isspace():
        i += 1
    j = n
    while j > i and s[j - 1].isspace():
        j -= 1
    core = s[i:j]
    if core == "":
        return None
    sign = 1
    k = 0
    if core[0] == "+":
        k = 1
    elif core[0] == "-":
        sign = -1
        k = 1
    digits = core[k:]
    if digits == "" or any(ch not in _ASCII_DIGITS for ch in digits):
        return None
    value = sign * int(digits)
    if value < INT32_MIN or value > INT32_MAX:
        return None
    return value


# ---------------------------------------------------------------------------
# Decoded MethodDef 0x06000005 ("m_22283830b7"): ParseIntRange(string,int,int)
# -> int. CIL trace (IL_0000-IL_01c4 of PixelTone.exe, file offset 1496):
#   state4: TryParse(s, Integer, InvariantCulture) -> fail => state2 (error)
#   state1 (parse ok): value < min => state2 (error)
#   state0 (value>=min): value > max => state2 (error); else state3 (ok)
#   state2: throw ArgumentException("integer out of range")   [ldstr-less;
#           decoded from XOR byte array, key 181, bytes starting IL_00b6]
#   state3: return value
# All three failure causes (unparsable, below min, above max) share the
# single literal message "integer out of range" -- confirmed by the
# control-flow merge: every failing branch sets the dispatch var to 2 and
# falls into the same throw site.
# ---------------------------------------------------------------------------
def parse_int_range(s, lo, hi):
    v = _try_parse_int32(s)
    if v is None:
        raise ArgError("integer out of range")
    if v < lo:
        raise ArgError("integer out of range")
    if v > hi:
        raise ArgError("integer out of range")
    return v


# ---------------------------------------------------------------------------
# Decoded MethodDef 0x06000001 ("m_4e09ee408f"): int Classify(int) -> a byte
# clamp: returns 255 if x>255, 0 if x<0, else x unchanged. (The name/number
# is build-local; this is just Clamp(x, 0, 255).)
# ---------------------------------------------------------------------------
def clamp_byte(x):
    if x > 255:
        return 255
    if x < 0:
        return 0
    return x


def _trunc_div(a, b):
    """C#/CIL 'div' truncates toward zero; Python's // floors. b is always
    the positive literal 100 at the one call site that uses this."""
    q = abs(a) // abs(b)
    if (a < 0) != (b < 0):
        q = -q
    return q


# ---------------------------------------------------------------------------
# Decoded MethodDef 0x06000002 ("m_b2ece2c34c"): int Tone(int,int,int).
# CIL: ((p0-128)*p2)/100 + 128 + p1, then Clamp to [0,255] via a call to
# Classify (0x06000001). Call sites in Main pass (channelValue, brightness,
# contrast), i.e. p0=channel, p1=brightness, p2=contrast -- a standard
# brightness/contrast transform.
# ---------------------------------------------------------------------------
def tone(channel, brightness, contrast):
    v = _trunc_div((channel - 128) * contrast, 100) + 128 + brightness
    return clamp_byte(v)


# ---------------------------------------------------------------------------
# Decoded MethodDef 0x06000003 ("m_b3c4f3c803"): int[] BuildTriplet(int,int,
# int,string). Dispatches on the decoded mode string (XOR-decoded literals
# "mono" key=90, "warm" key=141 -- REA call_edges to 0x06000007 + String
# op_Equality 0x0a000001):
#   mode == "mono": luma = (77*r + 150*g + 29*b + 128) >> 8 (standard
#                   luma/grayscale weights scaled by 256); returns
#                   [luma, luma, luma]
#   mode == "warm": returns [Clamp(r+12), Clamp(g+3), Clamp(b-9)]
#   otherwise (including "neutral", the only other value Main allows):
#                   returns [r, g, b] unchanged
# ---------------------------------------------------------------------------
def build_triplet(r, g, b, mode):
    if mode == "mono":
        luma = ((77 * r + 150 * g + 29 * b + 128) >> 8) & 0xFFFFFFFF
        # r,g,b are always in [0,255] by construction (post-Tone clamp), so
        # the sum is always non-negative and the plain Python >> matches
        # CIL's signed 'shr' here; the mask above is defensive only.
        if luma > 0x7FFFFFFF:
            luma -= 0x100000000
        return [luma, luma, luma]
    if mode == "warm":
        return [clamp_byte(r + 12), clamp_byte(g + 3), clamp_byte(b - 9)]
    return [r, g, b]


# ---------------------------------------------------------------------------
# Decoded MethodDef 0x06000004 ("m_0481f84d57"): uint Hash(int[]) -> a
# textbook 32-bit FNV-1a: offset basis 2166136261 (seen as the int32 literal
# -2128831035 == 0x811C9DC5), prime 16777619, folding each array element
# (always 0..255 in practice) as if it were one byte.
# ---------------------------------------------------------------------------
def fnv1a_hash(values):
    h = 0x811C9DC5
    for v in values:
        h = (h ^ (v & 0xFFFFFFFF)) & 0xFFFFFFFF
        h = (h * 16777619) & 0xFFFFFFFF
    return h


# ---------------------------------------------------------------------------
# Decoded strings (all XOR-decoded via MethodDef 0x06000007, "m_5558f5ab53":
# string XorDecode(byte[] data, byte key) => new string(data.Select(b =>
# (char)(b ^ key)).ToArray())). Reproduced here as plain literals since the
# obfuscation only hides them from static string scanners, not from a CIL
# decoder; the decoded text is what matters for byte-exact output.
# ---------------------------------------------------------------------------
HELP_LINE_1 = "PixelTone R G B brightness contrast preset"
HELP_LINE_2 = "R/G/B: 0..255; brightness: -100..100; contrast: 0..200; preset: neutral|mono|warm"
MSG_EXPECTED_6 = "expected 6 arguments; use --help"
MSG_UNKNOWN_PRESET = "unknown preset"
ERROR_PREFIX = "ERROR: "
HELP_FLAG = "--help"
PRESET_NEUTRAL = "neutral"
PRESET_MONO = "mono"
PRESET_WARM = "warm"


def _write_line(stream, text):
    """Writes text + CRLF directly as bytes, bypassing any platform/
    text-layer newline translation, to match System.Console.WriteLine's
    Environment.NewLine ("\\r\\n" on Windows, confirmed by live probe)."""
    stream.buffer.write(text.encode("utf-8"))
    stream.buffer.write(b"\r\n")
    stream.flush()


def run(argv):
    """Mirrors MethodDef 0x06000006 ("m_ec38e2401a"), the CLI entry point
    (Main(string[]) -> int), decoded CIL offset-by-offset from file offset
    1964 (3308 bytes of IL). Structure:

        if argv.Length == 1 and argv[0] == "--help":
            print usage (2 lines), return 0
        try:
            if argv.Length != 6: raise ArgError("expected 6 arguments; use --help")
            r, g, b = ParseIntRange(argv[0..2], 0, 255)
            brightness = ParseIntRange(argv[3], -100, 100)
            contrast   = ParseIntRange(argv[4], 0, 200)
            preset = argv[5]
            if preset not in ("neutral","mono","warm"): raise ArgError("unknown preset")
            triplet = BuildTriplet(Tone(r,...), Tone(g,...), Tone(b,...), preset)
            h = FNV1a(triplet)
            print(f"{triplet[0]},{triplet[1]},{triplet[2]}|{h:X8}")
            return 0
        except ArgError as ex:        # catches ONLY ArgumentException
                                       # (EH clause classtok resolves to
                                       # System.ArgumentException, confirmed
                                       # via the method's fat EH section)
            eprint("ERROR: " + ex.Message)
            return 2
    """
    if len(argv) == 1 and argv[0] == HELP_FLAG:
        _write_line(sys.stdout, HELP_LINE_1)
        _write_line(sys.stdout, HELP_LINE_2)
        return 0

    try:
        if len(argv) != 6:
            raise ArgError(MSG_EXPECTED_6)
        r = parse_int_range(argv[0], 0, 255)
        g = parse_int_range(argv[1], 0, 255)
        b = parse_int_range(argv[2], 0, 255)
        brightness = parse_int_range(argv[3], -100, 100)
        contrast = parse_int_range(argv[4], 0, 200)
        preset = argv[5]
        if preset != PRESET_NEUTRAL and preset != PRESET_MONO and preset != PRESET_WARM:
            raise ArgError(MSG_UNKNOWN_PRESET)

        tr = tone(r, brightness, contrast)
        tg = tone(g, brightness, contrast)
        tb = tone(b, brightness, contrast)
        triplet = build_triplet(tr, tg, tb, preset)
        h = fnv1a_hash(triplet)

        # Composite format "{0},{1},{2}|{3:X8}" (decoded literal, key=49)
        # applied to (r, g, b, hash); {3:X8} is upper-case hex, zero-padded
        # to 8 digits.
        line = "{0},{1},{2}|{3}".format(triplet[0], triplet[1], triplet[2], format(h, "08X"))
        _write_line(sys.stdout, line)
        return 0
    except ArgError as ex:
        _write_line(sys.stderr, ERROR_PREFIX + str(ex))
        return 2


def main():
    sys.exit(run(sys.argv[1:]))


if __name__ == "__main__":
    main()
