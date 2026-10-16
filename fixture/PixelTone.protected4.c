// PixelTone (protected, P2+P3+native-extras+exception-routing) -- builds on
// PixelTone.protected3.c (loop unrolling + pointer aliasing) and adds one more
// source-level technique: exception-based control flow routing.
//
// - Exception-based routing (wmain's preset validation): instead of a plain
//   `if (!valid) { report error; return 2; }`, this computes `preset_valid` as before
//   but then deliberately divides by zero when it's false, inside `__try`/`__except`
//   (MSVC structured exception handling) -- the error path is reached by *catching a
//   hardware fault*, not by a visible conditional branch. Scoped to an integer
//   divide-by-zero specifically because it's a well-defined, memory-safe CPU trap
//   (#DE on x86, always EXCEPTION_INT_DIVIDE_BY_ZERO under SEH) -- never a null-pointer
//   write or other memory-unsafe trick. `volatile` on both the divisor and the result
//   stops /O2 from proving the division "unused" and deleting it outright.
//
// See reports/native-exception-routing.draft.md for what was measured and why a
// memory-unsafe variant (e.g. a deliberate null-pointer write) was deliberately not
// used -- divide-by-zero gets the same control-flow effect without ever touching an
// invalid address.
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>
#include <windows.h>

// --- P3: clamp_byte, flattened (unchanged from PixelTone.protected3.c) ---
static int clamp_byte(int value) {
    int state = 7;
    int result = 0;
    for (;;) {
        switch (state) {
        case 7:
            state = (value < 0) ? 9 : 3;
            continue;
        case 3:
            state = (value > 255) ? 1 : 5;
            continue;
        case 9:
            result = 0;
            state = 2;
            continue;
        case 1:
            result = 255;
            state = 2;
            continue;
        case 5:
            result = value;
            state = 2;
            continue;
        case 2:
            return result;
        }
    }
}

// --- not flattened: single basic block, same reason .NET's P3 skipped AdjustChannel ---
static int adjust_channel(int value, int brightness, int contrast) {
    int numerator = (value - 128) * contrast;
    int scaled = numerator / 100;
    return clamp_byte(scaled + 128 + brightness);
}

// --- P2: string obfuscation (unchanged from PixelTone.protected.c) ---

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

// --- P3: apply_preset, flattened (unchanged from PixelTone.protected2.c) ---
static void apply_preset(int r, int g, int b, const wchar_t *preset, int out[3]) {
    int state = 11;
    for (;;) {
        switch (state) {
        case 11:
            state = (wcscmp(preset, STR_MONO) == 0) ? 4 : 8;
            continue;
        case 8:
            state = (wcscmp(preset, STR_WARM) == 0) ? 6 : 14;
            continue;
        case 4: {
            int y = (77 * r + 150 * g + 29 * b + 128) >> 8;
            out[0] = y; out[1] = y; out[2] = y;
            return;
        }
        case 6:
            out[0] = clamp_byte(r + 12);
            out[1] = clamp_byte(g + 3);
            out[2] = clamp_byte(b - 9);
            return;
        case 14:
            out[0] = r; out[1] = g; out[2] = b;
            return;
        }
    }
}

// --- loop unrolling: channels is always exactly 3 elements in this program (unchanged
// from PixelTone.protected3.c) ---
static unsigned int fingerprint(const int channels[3]) {
    unsigned int h = 2166136261u;
    int state = 6;
    for (;;) {
        switch (state) {
        case 6:
            h = (h ^ (unsigned int)channels[0]) * 16777619u;
            state = 2;
            continue;
        case 2:
            h = (h ^ (unsigned int)channels[1]) * 16777619u;
            state = 9;
            continue;
        case 9:
            h = (h ^ (unsigned int)channels[2]) * 16777619u;
            state = 4;
            continue;
        case 4:
            return h;
        }
    }
}

// --- P3 + pointer aliasing (unchanged from PixelTone.protected3.c) ---
static int read_int(const wchar_t *text, long long minimum, long long maximum, long long *out) {
    size_t n = wcslen(text);
    size_t i = 0, j = n;
    int negative = 0;
    long long value_storage = 0;
    long long *value_p = &value_storage;
    long long **value_pp = &value_p;
    wchar_t c = 0; // always assigned in case 33 before any use in case 35; silences C4701
    int state = 21;
    for (;;) {
        switch (state) {
        case 21: // trim leading whitespace
            state = (i < j && (text[i] == L'\t' || text[i] == L'\n' || text[i] == L'\v' ||
                                text[i] == L'\f' || text[i] == L'\r' || text[i] == L' '))
                ? 17 : 23;
            continue;
        case 17:
            i++;
            state = 21;
            continue;
        case 23: // trim trailing whitespace
            state = (j > i && (text[j - 1] == L'\t' || text[j - 1] == L'\n' || text[j - 1] == L'\v' ||
                                text[j - 1] == L'\f' || text[j - 1] == L'\r' || text[j - 1] == L' '))
                ? 19 : 25;
            continue;
        case 19:
            j--;
            state = 23;
            continue;
        case 25:
            state = (i >= j) ? 27 : 29;
            continue;
        case 27:
            return 0;
        case 29: // optional sign
            if (text[i] == L'+') { i++; }
            else if (text[i] == L'-') { negative = 1; i++; }
            state = 31;
            continue;
        case 31:
            state = (i >= j) ? 27 : 33;
            continue;
        case 33: // digit loop
            c = text[i];
            state = (c < L'0' || c > L'9') ? 27 : 35;
            continue;
        case 35:
            **value_pp = **value_pp * 10 + (c - L'0');
            state = (**value_pp > 4294967296LL) ? 27 : 37;
            continue;
        case 37:
            i++;
            state = (i < j) ? 33 : 39;
            continue;
        case 39: // finalize sign + range checks
            if (negative) **value_pp = -(**value_pp);
            state = (**value_pp < -2147483648LL || **value_pp > 2147483647LL) ? 27 : 41;
            continue;
        case 41:
            state = (**value_pp < minimum || **value_pp > maximum) ? 27 : 43;
            continue;
        case 43:
            *out = **value_pp;
            return 1;
        }
    }
}

static void print_usage(void) {
    wprintf(L"%ls", STR_USAGE1);
    wprintf(L"%ls", STR_USAGE2);
}

// --- exception-based routing: preset validity is reached through a caught hardware
// fault instead of a visible `if`. Returns 1 if preset is one of the three known
// values, 0 otherwise -- from the *outside* this looks like any other predicate
// function; nothing about its signature reveals how it decides. ---
static int preset_is_valid(const wchar_t *preset) {
    int valid = (wcscmp(preset, STR_NEUTRAL) == 0 || wcscmp(preset, STR_MONO) == 0 ||
                 wcscmp(preset, STR_WARM) == 0) ? 1 : 0;
    int ok = 1;
    __try {
        volatile int denom = valid;      // 1 if valid, 0 if not
        volatile int probe = 100 / denom; // #DE / EXCEPTION_INT_DIVIDE_BY_ZERO iff denom==0
        (void)probe;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = 0; // only reached by *catching* the fault, not by testing `valid` directly
    }
    return ok;
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

    if (!preset_is_valid(preset)) {
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
