// PixelTone (protected) -- native string-obfuscation pass applied at source level.
//
// dysob (tools/obfuscator) only edits .NET IL via Mono.Cecil; it cannot rewrite x86-64
// machine code, so there is no binary-rewriting equivalent of P1/P2/P3 for native PEs
// yet. This file is the native analogue of P2 (obfuscator-plan.draft.md): every wide
// string literal is XOR-encoded at build time (by hand here; a real tool would do this
// at compile time via a macro/preprocessing pass) and decoded into a fixed buffer once,
// at startup, instead of appearing as a plaintext wchar_t literal in .rdata.
//
// Scope and honesty notes (see reports/native-track-baseline.draft.md):
// - The XOR key (0x5A) is not a cryptographic secret, same caveat as the .NET P2 pass.
// - This does NOT hide the strings from a human reading Hex-Rays pseudocode of
//   init_strings() itself -- it hides them from .rdata / a raw strings scan and from
//   REA's IDA adapter, which (per the native-track report) cannot even enumerate
//   function-referenced strings through that adapter regardless of encoding.
// - Function names are not a protection target here: static functions already have no
//   exported names in the baseline build (confirmed in the native-track report), so
//   there is nothing equivalent to .NET's P1 to add on top.
//
// Behavioral contract is identical to fixture/PixelTone.c; see
// scripts/evaluate-native-protected.py for the verification that it stays that way.
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
    int numerator = (value - 128) * contrast;
    int scaled = numerator / 100;
    return clamp_byte(scaled + 128 + brightness);
}

// --- string obfuscation: encoded tables + decode + the decoded buffers themselves ---

static void decode(const unsigned char *data, size_t len, unsigned char key, wchar_t *out) {
    for (size_t i = 0; i < len; i++) out[i] = (wchar_t)(data[i] ^ key);
    out[len] = L'\0';
}

static const unsigned char STR_DASH_HELP_ENC[] = { 0x77, 0x77, 0x32, 0x3f, 0x36, 0x2a };
static const unsigned char STR_ERR_ARGC_ENC[] = { 0x1f, 0x08, 0x08, 0x15, 0x08, 0x60, 0x7a, 0x3f, 0x22, 0x2a, 0x3f, 0x39, 0x2e, 0x3f, 0x3e, 0x7a, 0x6c, 0x7a, 0x3b, 0x28, 0x3d, 0x2f, 0x37, 0x3f, 0x34, 0x2e, 0x29, 0x61, 0x7a, 0x2f, 0x29, 0x3f, 0x7a, 0x77, 0x77, 0x32, 0x3f, 0x36, 0x2a, 0x50 };
static const unsigned char STR_ERR_RANGE_ENC[] = { 0x1f, 0x08, 0x08, 0x15, 0x08, 0x60, 0x7a, 0x33, 0x34, 0x2e, 0x3f, 0x3d, 0x3f, 0x28, 0x7a, 0x35, 0x2f, 0x2e, 0x7a, 0x35, 0x3c, 0x7a, 0x28, 0x3b, 0x34, 0x3d, 0x3f, 0x50 };
static const unsigned char STR_ERR_PRESET_ENC[] = { 0x1f, 0x08, 0x08, 0x15, 0x08, 0x60, 0x7a, 0x2f, 0x34, 0x31, 0x34, 0x35, 0x2d, 0x34, 0x7a, 0x2a, 0x28, 0x3f, 0x29, 0x3f, 0x2e, 0x50 };
static const unsigned char STR_NEUTRAL_ENC[] = { 0x34, 0x3f, 0x2f, 0x2e, 0x28, 0x3b, 0x36 };
static const unsigned char STR_MONO_ENC[] = { 0x37, 0x35, 0x34, 0x35 };
static const unsigned char STR_WARM_ENC[] = { 0x2d, 0x3b, 0x28, 0x37 };
static const unsigned char STR_USAGE1_ENC[] = { 0x0a, 0x33, 0x22, 0x3f, 0x36, 0x0e, 0x35, 0x34, 0x3f, 0x7a, 0x08, 0x7a, 0x1d, 0x7a, 0x18, 0x7a, 0x38, 0x28, 0x33, 0x3d, 0x32, 0x2e, 0x34, 0x3f, 0x29, 0x29, 0x7a, 0x39, 0x35, 0x34, 0x2e, 0x28, 0x3b, 0x29, 0x2e, 0x7a, 0x2a, 0x28, 0x3f, 0x29, 0x3f, 0x2e, 0x50 };
static const unsigned char STR_USAGE2_ENC[] = { 0x08, 0x75, 0x1d, 0x75, 0x18, 0x60, 0x7a, 0x6a, 0x74, 0x74, 0x68, 0x6f, 0x6f, 0x61, 0x7a, 0x38, 0x28, 0x33, 0x3d, 0x32, 0x2e, 0x34, 0x3f, 0x29, 0x29, 0x60, 0x7a, 0x77, 0x6b, 0x6a, 0x6a, 0x74, 0x74, 0x6b, 0x6a, 0x6a, 0x61, 0x7a, 0x39, 0x35, 0x34, 0x2e, 0x28, 0x3b, 0x29, 0x2e, 0x60, 0x7a, 0x6a, 0x74, 0x74, 0x68, 0x6a, 0x6a, 0x61, 0x7a, 0x2a, 0x28, 0x3f, 0x29, 0x3f, 0x2e, 0x60, 0x7a, 0x34, 0x3f, 0x2f, 0x2e, 0x28, 0x3b, 0x36, 0x26, 0x37, 0x35, 0x34, 0x35, 0x26, 0x2d, 0x3b, 0x28, 0x37, 0x50 };
static const unsigned char STR_FMT_ENC[] = { 0x7f, 0x3e, 0x76, 0x7f, 0x3e, 0x76, 0x7f, 0x3e, 0x26, 0x7f, 0x6a, 0x62, 0x02, 0x50 };

static wchar_t STR_DASH_HELP[7];
static wchar_t STR_ERR_ARGC[41];
static wchar_t STR_ERR_RANGE[29];
static wchar_t STR_ERR_PRESET[23];
static wchar_t STR_NEUTRAL[8];
static wchar_t STR_MONO[5];
static wchar_t STR_WARM[5];
static wchar_t STR_USAGE1[44];
static wchar_t STR_USAGE2[83];
static wchar_t STR_FMT[15];

static void init_strings(void) {
    decode(STR_DASH_HELP_ENC, 6, 0x5A, STR_DASH_HELP);
    decode(STR_ERR_ARGC_ENC, 40, 0x5A, STR_ERR_ARGC);
    decode(STR_ERR_RANGE_ENC, 28, 0x5A, STR_ERR_RANGE);
    decode(STR_ERR_PRESET_ENC, 22, 0x5A, STR_ERR_PRESET);
    decode(STR_NEUTRAL_ENC, 7, 0x5A, STR_NEUTRAL);
    decode(STR_MONO_ENC, 4, 0x5A, STR_MONO);
    decode(STR_WARM_ENC, 4, 0x5A, STR_WARM);
    decode(STR_USAGE1_ENC, 43, 0x5A, STR_USAGE1);
    decode(STR_USAGE2_ENC, 82, 0x5A, STR_USAGE2);
    decode(STR_FMT_ENC, 14, 0x5A, STR_FMT);
}

// --- rest of the program, now referencing the decoded buffers instead of literals ---

static void apply_preset(int r, int g, int b, const wchar_t *preset, int out[3]) {
    if (wcscmp(preset, STR_MONO) == 0) {
        int y = (77 * r + 150 * g + 29 * b + 128) >> 8;
        out[0] = y; out[1] = y; out[2] = y;
        return;
    }
    if (wcscmp(preset, STR_WARM) == 0) {
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
    if (text[k] == L'+') { k++; }
    else if (text[k] == L'-') { negative = 1; k++; }
    if (k >= j) return 0;

    long long value = 0;
    for (; k < j; k++) {
        wchar_t c = text[k];
        if (c < L'0' || c > L'9') return 0;
        value = value * 10 + (c - L'0');
        if (value > 4294967296LL) return 0;
    }
    if (negative) value = -value;
    if (value < -2147483648LL || value > 2147483647LL) return 0;
    if (value < minimum || value > maximum) return 0;
    *out = value;
    return 1;
}

static void print_usage(void) {
    wprintf(L"%ls", STR_USAGE1);
    wprintf(L"%ls", STR_USAGE2);
}

int wmain(int argc, wchar_t **argv) {
    init_strings();

    if (argc == 2 && wcscmp(argv[1], STR_DASH_HELP) == 0) {
        print_usage();
        return 0;
    }

    if (argc != 7) {
        fwprintf(stderr, L"%ls", STR_ERR_ARGC);
        return 2;
    }

    long long r, g, b, brightness, contrast;
    const wchar_t *preset = argv[6];

    if (!read_int(argv[1], 0, 255, &r) ||
        !read_int(argv[2], 0, 255, &g) ||
        !read_int(argv[3], 0, 255, &b) ||
        !read_int(argv[4], -100, 100, &brightness) ||
        !read_int(argv[5], 0, 200, &contrast)) {
        fwprintf(stderr, L"%ls", STR_ERR_RANGE);
        return 2;
    }

    if (wcscmp(preset, STR_NEUTRAL) != 0 && wcscmp(preset, STR_MONO) != 0 && wcscmp(preset, STR_WARM) != 0) {
        fwprintf(stderr, L"%ls", STR_ERR_PRESET);
        return 2;
    }

    int adjusted[3];
    adjusted[0] = adjust_channel((int)r, (int)brightness, (int)contrast);
    adjusted[1] = adjust_channel((int)g, (int)brightness, (int)contrast);
    adjusted[2] = adjust_channel((int)b, (int)brightness, (int)contrast);

    int result[3];
    apply_preset(adjusted[0], adjusted[1], adjusted[2], preset, result);

    unsigned int hash = fingerprint(result);
    wprintf(STR_FMT, result[0], result[1], result[2], hash);
    return 0;
}
