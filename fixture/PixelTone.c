// PixelTone -- native C reimplementation of fixture/PixelTone.cs, same CLI contract,
// for the "native Windows track" baseline (obfuscator-plan.draft.md step 5). Compiled
// with MSVC to a real x64 PE so a native-code analysis tool (IDA Pro here) can be
// measured against the exact same algorithm already measured in managed form.
//
// Uses wmain/wchar_t so non-ASCII argv (full-width digits, NBSP, etc. from the shared
// evaluation corpus) arrive as actual Unicode code units instead of being mangled by
// an ANSI codepage round-trip -- the parser below then deliberately rejects anything
// that is not an ASCII digit/sign/ASCII-whitespace, mirroring the real .NET
// NumberStyles.Integer behavior the original fixture relies on (see
// reconstruction/pass01/pixel_tone.py's read_int for the same ASCII-only policy, and
// reports/pass03-blind-reconstruction.draft.md for what happens when that choice is
// loosened to a general Unicode whitespace test).
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>

static int clamp_byte(int value) {
    if (value < 0) return 0;
    if (value > 255) return 255;
    return value;
}

static int adjust_channel(int value, int brightness, int contrast) {
    // C's integer division already truncates toward zero, same as CIL `div`.
    int numerator = (value - 128) * contrast;
    int scaled = numerator / 100;
    return clamp_byte(scaled + 128 + brightness);
}

static void apply_preset(int r, int g, int b, const wchar_t *preset, int out[3]) {
    if (wcscmp(preset, L"mono") == 0) {
        int y = (77 * r + 150 * g + 29 * b + 128) >> 8;
        out[0] = y; out[1] = y; out[2] = y;
        return;
    }
    if (wcscmp(preset, L"warm") == 0) {
        out[0] = clamp_byte(r + 12);
        out[1] = clamp_byte(g + 3);
        out[2] = clamp_byte(b - 9);
        return;
    }
    out[0] = r; out[1] = g; out[2] = b;
}

static unsigned int fingerprint(const int channels[3]) {
    unsigned int h = 2166136261u;
    for (int i = 0; i < 3; i++) {
        h = (h ^ (unsigned int)channels[i]) * 16777619u;
    }
    return h;
}

// Returns 1 on success (value written to *out), 0 on failure. Mirrors
// Int32.TryParse(s, NumberStyles.Integer, InvariantCulture, out v) + range check:
// ASCII leading/trailing whitespace (\t\n\v\f\r and space), optional ASCII sign,
// one or more ASCII digits, no separators/exponents, no non-ASCII digit forms.
static int read_int(const wchar_t *text, long long minimum, long long maximum, long long *out) {
    size_t n = wcslen(text);
    size_t i = 0, j = n;
    while (i < j && (text[i] == L'\t' || text[i] == L'\n' || text[i] == L'\v' ||
                      text[i] == L'\f' || text[i] == L'\r' || text[i] == L' ')) i++;
    while (j > i && (text[j - 1] == L'\t' || text[j - 1] == L'\n' || text[j - 1] == L'\v' ||
                      text[j - 1] == L'\f' || text[j - 1] == L'\r' || text[j - 1] == L' ')) j--;
    if (i >= j) return 0;

    int negative = 0;
    size_t k = i;
    if (text[k] == L'+' ) { k++; }
    else if (text[k] == L'-') { negative = 1; k++; }
    if (k >= j) return 0;

    long long value = 0;
    for (; k < j; k++) {
        wchar_t c = text[k];
        if (c < L'0' || c > L'9') return 0; // rejects full-width/Arabic-indic digits, etc.
        value = value * 10 + (c - L'0');
        if (value > 4294967296LL) return 0; // guard against absurd overflow before sign
    }
    if (negative) value = -value;
    if (value < -2147483648LL || value > 2147483647LL) return 0;
    if (value < minimum || value > maximum) return 0;
    *out = value;
    return 1;
}

static void print_usage(void) {
    wprintf(L"PixelTone R G B brightness contrast preset\n");
    wprintf(L"R/G/B: 0..255; brightness: -100..100; contrast: 0..200; preset: neutral|mono|warm\n");
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 2 && wcscmp(argv[1], L"--help") == 0) {
        print_usage();
        return 0;
    }

    if (argc != 7) {
        fwprintf(stderr, L"ERROR: expected 6 arguments; use --help\n");
        return 2;
    }

    long long r, g, b, brightness, contrast;
    const wchar_t *preset = argv[6];

    if (!read_int(argv[1], 0, 255, &r) ||
        !read_int(argv[2], 0, 255, &g) ||
        !read_int(argv[3], 0, 255, &b) ||
        !read_int(argv[4], -100, 100, &brightness) ||
        !read_int(argv[5], 0, 200, &contrast)) {
        fwprintf(stderr, L"ERROR: integer out of range\n");
        return 2;
    }

    if (wcscmp(preset, L"neutral") != 0 && wcscmp(preset, L"mono") != 0 && wcscmp(preset, L"warm") != 0) {
        fwprintf(stderr, L"ERROR: unknown preset\n");
        return 2;
    }

    int adjusted[3];
    adjusted[0] = adjust_channel((int)r, (int)brightness, (int)contrast);
    adjusted[1] = adjust_channel((int)g, (int)brightness, (int)contrast);
    adjusted[2] = adjust_channel((int)b, (int)brightness, (int)contrast);

    int result[3];
    apply_preset(adjusted[0], adjusted[1], adjusted[2], preset, result);

    unsigned int hash = fingerprint(result);
    wprintf(L"%d,%d,%d|%08X\n", result[0], result[1], result[2], hash);
    return 0;
}
