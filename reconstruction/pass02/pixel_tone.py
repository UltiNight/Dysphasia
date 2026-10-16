"""Independent behavioral reconstruction from admitted PE/CIL evidence.

This is a new Python implementation, not recovered original source.
"""
import re
import sys

INTEGER = re.compile(r"[\x09-\x0d ]*([+-]?)([0-9]+)[\x09-\x0d ]*\Z")


def read_int(text, minimum, maximum):
    match = INTEGER.fullmatch(text)
    if match is None:
        raise ValueError("integer out of range")
    magnitude = match.group(2).lstrip("0") or "0"
    if len(magnitude) > 10:
        raise ValueError("integer out of range")
    number = int(magnitude) * (-1 if match.group(1) == "-" else 1)
    if number < minimum or number > maximum:
        raise ValueError("integer out of range")
    return number


def clamp_byte(value):
    return max(0, min(255, value))


def adjust_channel(channel, brightness, contrast):
    product = (channel - 128) * contrast
    quotient = abs(product) // 100
    if product < 0:
        quotient = -quotient
    return clamp_byte(quotient + 128 + brightness)


def apply_preset(rgb, preset):
    red, green, blue = rgb
    if preset == "mono":
        gray = (77 * red + 150 * green + 29 * blue + 128) >> 8
        return [gray, gray, gray]
    if preset == "warm":
        return [clamp_byte(red + 12), clamp_byte(green + 3), clamp_byte(blue - 9)]
    return list(rgb)


def fingerprint(rgb):
    value = 2166136261
    for channel in rgb:
        value = ((value ^ channel) * 16777619) & 0xffffffff
    return value


def main(args=None):
    args = sys.argv[1:] if args is None else args
    if args == ["--help"]:
        print("PixelTone R G B brightness contrast preset")
        print("R/G/B: 0..255; brightness: -100..100; contrast: 0..200; preset: neutral|mono|warm")
        return 0
    try:
        if len(args) != 6:
            raise ValueError("expected 6 arguments; use --help")
        rgb = [read_int(arg, 0, 255) for arg in args[:3]]
        brightness = read_int(args[3], -100, 100)
        contrast = read_int(args[4], 0, 200)
        preset = args[5]
        if preset not in ("neutral", "mono", "warm"):
            raise ValueError("unknown preset")
        rgb = apply_preset([adjust_channel(c, brightness, contrast) for c in rgb], preset)
        print(f"{rgb[0]},{rgb[1]},{rgb[2]}|{fingerprint(rgb):08X}")
        return 0
    except ValueError as error:
        print("ERROR: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
