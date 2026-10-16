"""Behavioral reconstruction from REA metadata plus separately decoded CIL.

This is an independent implementation, not recovered original source.
Only Python's standard library is required.
"""
import re
import sys


def clamp_byte(value):
    return max(0, min(255, value))


def adjust_channel(channel, brightness, contrast):
    # CIL div truncates toward zero; Python // alone rounds negative values down.
    numerator = (channel - 128) * contrast
    scaled = abs(numerator) // 100
    if numerator < 0:
        scaled = -scaled
    return clamp_byte(scaled + 128 + brightness)


def apply_preset(red, green, blue, preset):
    if preset == 'mono':
        grey = (77 * red + 150 * green + 29 * blue + 128) >> 8
        return [grey, grey, grey]
    if preset == 'warm':
        return [clamp_byte(red + 12), clamp_byte(green + 3), clamp_byte(blue - 9)]
    return [red, green, blue]


def fingerprint(channels):
    value = 2166136261
    for channel in channels:
        value = ((value ^ channel) * 16777619) & 0xffffffff
    return value


def read_int(text, lower, upper):
    # InvariantCulture + NumberStyles.Integer (7): ASCII sign/digits and
    # leading/trailing space, TAB, LF, VT, FF, CR. No separators or exponents.
    if not re.fullmatch(r'[\x09-\x0d ]*[+-]?[0-9]+[\x09-\x0d ]*', text):
        raise ValueError('integer out of range')
    # Remove leading zeros before int() to avoid Python's long-string limit.
    token = text.strip('\x09\x0a\x0b\x0c\x0d ')
    negative = token.startswith('-')
    digits = token.lstrip('+-').lstrip('0') or '0'
    if len(digits) > 10:
        raise ValueError('integer out of range')
    value = int(digits) * (-1 if negative else 1)
    if value < -2147483648 or value > 2147483647 or not lower <= value <= upper:
        raise ValueError('integer out of range')
    return value


def run(argv):
    """Return (exit code, stdout text, stderr text), with Windows line endings."""
    if argv == ['--help']:
        return 0, ('PixelTone R G B brightness contrast preset\r\n'
                   'R/G/B: 0..255; brightness: -100..100; contrast: 0..200; '
                   'preset: neutral|mono|warm\r\n'), ''
    try:
        if len(argv) != 6:
            raise ValueError('expected 6 arguments; use --help')
        red = read_int(argv[0], 0, 255)
        green = read_int(argv[1], 0, 255)
        blue = read_int(argv[2], 0, 255)
        brightness = read_int(argv[3], -100, 100)
        contrast = read_int(argv[4], 0, 200)
        preset = argv[5]
        if preset not in ('neutral', 'mono', 'warm'):
            raise ValueError('unknown preset')
        channels = apply_preset(
            adjust_channel(red, brightness, contrast),
            adjust_channel(green, brightness, contrast),
            adjust_channel(blue, brightness, contrast), preset)
        return 0, f'{channels[0]},{channels[1]},{channels[2]}|{fingerprint(channels):08X}\r\n', ''
    except ValueError as exc:
        return 2, '', f'ERROR: {exc}\r\n'


def main():
    code, stdout, stderr = run(sys.argv[1:])
    sys.stdout.buffer.write(stdout.encode('ascii'))
    sys.stderr.buffer.write(stderr.encode('ascii'))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
