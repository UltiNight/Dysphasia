# PixelTone.exe -- Reverse Engineering Findings

## Summary

`PixelTone.exe` is a small .NET (IL-only, x64, mscorlib-only, no P/Invoke)
console program named "PixelTone". It is an obfuscated program: every
type and member name has been renamed to meaningless hashes (with
Unicode-confusable characters mixed into some identifiers, e.g.
`TransаctionBrokеr`), and every user-visible string is stored
as an encrypted/encoded byte blob (`FieldRVA` + `RuntimeHelpers.InitializeArray`)
decoded at runtime by a small helper method, rather than as ordinary
`ldstr` string literals (confirmed: the `#US` user-strings heap is
empty). None of this obfuscation changes *external* behavior, which is
what this reimplementation targets.

Functionally, it is a tiny RGB "color grading" CLI tool:

```
PixelTone R G B brightness contrast preset
R/G/B: 0..255; brightness: -100..100; contrast: 0..200; preset: neutral|mono|warm
```

It parses 6 positional arguments, applies one of three color presets
plus a brightness/contrast adjustment, prints the resulting RGB triple
plus an 8-hex-digit checksum, and exits 0. Various failure modes print
`ERROR: <message>` to stderr and exit 2.

## Method / Tooling

- Static analysis via `rea.mjs inspect-managed-artifact`,
  `inspect-managed-members`, and `inspect-managed-native-boundaries`
  against `PixelTone.exe`.
- 8 direct executions of the binary (the full budget allowed), each
  chosen to resolve the highest-value remaining uncertainty.
- Offline brute-force search (no further executions) attempting to
  reverse the trailing checksum's exact byte encoding from the two
  hash values observed during the 8 executions.

## What REA's static analysis showed

`inspect-managed-artifact`: PE32+/x64, CLI header present, IL-only,
not strong-name signed, no ReadyToRun. Metadata: 27 TypeDefs, 43
MethodDefs, 8 Fields, single AssemblyRef (`mscorlib 4.0.0.0`). This is
a plain, small .NET Framework-style console app with no native/mixed
code (`inspect-managed-native-boundaries` confirmed zero P/Invoke
imports, zero module refs, zero native implementations).

`inspect-managed-members` gave the full type/method/field list, the
call graph (`call_edges`), field read/write sites (`field_accesses`),
and member refs (external API calls). Key findings from this:

- The entry point (metadata token `0x06000006`) is a method on type
  `TransаctionBrokеr` (`<Module>`'s main class) with signature
  `string[] -> i4` -- i.e. `static int Main(string[] args)`, matching
  the CLI metadata token recorded for the assembly's entry point.
- Member refs used: `System.Security.Cryptography.SHA256.Create` +
  `HashAlgorithm.ComputeHash`, `CultureInfo.InvariantCulture`,
  `String.Concat`/`op_Equality`, `ArgumentException..ctor`,
  `Debugger.get_IsAttached`, `Environment.FailFast`,
  `Console.WriteLine`/`Console.Error`, `Exception.get_Message`,
  `RuntimeHelpers.InitializeArray` (static byte-blob init), and
  `Type.GetTypeFromHandle` + `Type.InvokeMember` (reflection -- used by
  a helper that looks exactly like a reflection-indirected
  `int.TryParse(string, NumberStyles, IFormatProvider, out int)` call,
  presumably another obfuscation trick to hide a direct call).
- Walking the entry point's call-edge list in order (this tool records
  call/callvirt/newobj sites as they appear in the method body, which
  let me reconstruct the control flow almost exactly) gave this shape:
  1. `if (Debugger.IsAttached) Environment.FailFast(msg);` (anti-debug)
  2. `if (!SelfIntegrityCheck()) Environment.FailFast(msg);` (an
     internal check that calls a tiny `i4->i4` helper 5 times --
     almost certainly an anti-tamper/checksum-of-self check; not
     relevant to a Python port since we aren't running under a
     debugger and aren't a tampered copy of the real binary)
  3. `if (args.Length > 0 && args[0] == "--help") { PrintHelp(); return 0; }`
  4. `if (args.Length != 6) throw new ArgumentException("expected 6 arguments; use --help");`
  5. Parse args[0..4] via a helper `RegisterCallback(string, min, max) -> int`
     called 5 times (R, G, B, brightness, contrast) -- this helper
     itself does the reflection-based `TryParse` + range check + a
     single shared `throw new ArgumentException(...)` on failure.
  6. Validate `preset` against 3 decoded string constants (3
     `op_Equality` comparisons) with a shared `ArgumentException` for
     "none matched".
  7. A 3-int `AuthenticateSession(int,int,int) -> int` helper, called
     once per matched preset branch, feeds into a
     `RefreshToken(int,int,int,string) -> int[]` call that produces
     the final RGB array (confirmed empirically -- see below).
  8. `InitializeCache(int[]) -> uint` is called with that result array
     and does the `SHA256.ComputeHash` work (called twice) to produce
     the trailing checksum.
  9. Everything from step 5 onward appears to be wrapped in a
     try/catch that funnels any `ArgumentException` into one shared
     handler: `Console.Error.WriteLine("ERROR: " + ex.Message)`.

REA does not disassemble IL arithmetic/branches (no opcode-level
decompilation was available among the allowed commands), so the exact
math inside `AuthenticateSession`/`RefreshToken`/`InitializeCache`
(the actual color formulas and checksum) had to be determined by
direct execution, not static analysis.

## Execution probes (all 8 used)

| # | Command | Result |
|---|---|---|
| 1 | `PixelTone.exe` | stderr: `ERROR: expected 6 arguments; use --help`, exit 2 |
| 2 | `PixelTone.exe` (stdout/stderr captured separately) | confirms: stdout empty, stderr has the message, exit 2 |
| 3 | `PixelTone.exe --help` | stdout: the 2-line usage text (reproduced verbatim above), exit 0 |
| 4 | `PixelTone.exe 128 128 128 0 100 neutral` | stdout: `128,128,128\|56195437`, exit 0 |
| 5 | `PixelTone.exe 10 100 250 20 150 neutral` | stdout: `0,106,255\|B0871470`, exit 0 |
| 6 | `PixelTone.exe 128 128 128 0 100 mono` | stdout: `128,128,128\|56195437`, exit 0 (**same hash as #4**, despite a different preset) |
| 7 | `PixelTone.exe 200 100 50 0 100 mono` | stdout: `124,124,124\|13FE3A3B`, exit 0 |
| 8 | `PixelTone.exe 200 100 50 0 100 warm` | stdout: `212,103,41\|4F2DD6DF`, exit 0 |

From these:

- **Argument contract**: exactly 6 positional args (`R G B brightness
  contrast preset`), or exactly `--help` as args[0] (verified with
  it as the sole argument; not verified with trailing extra args, but
  the call-graph order -- `--help` check strictly precedes the
  `args.Length != 6` check -- strongly suggests the `--help` check
  does not itself require `args.Length == 1`, so extra trailing args
  after `--help` are assumed to still trigger help).
- **Error exit code**: 2, confirmed for the "wrong argument count"
  case. Assumed (not separately confirmed) to be uniform across all
  other validation failures (bad number, out-of-range number, bad
  preset), based on the call-graph showing a single shared catch
  handler for all of these `ArgumentException` throws.
- **Line endings**: confirmed CRLF (`\r\n`) by inspecting the raw
  captured bytes of stdout (`128,128,128|56195437\r\n`), as expected
  for `Console.WriteLine` on Windows.
- **"neutral" formula** -- solved exactly from probes #4 and #5:
  `factor = contrast / 100.0`
  `out = clamp(round((value - 128) * factor + 128) + brightness, 0, 255)`
  Verified: `(10-128)*1.5+128+20 = -29 -> clamp 0`; `(100-128)*1.5+128+20 = 106`;
  `(250-128)*1.5+128+20 = 331 -> clamp 255`. Matches `0,106,255` exactly.
- **"mono" formula** -- solved exactly from probe #7 (brightness=0,
  contrast=100 isolates the preset's own math): luma =
  `0.299*200 + 0.587*100 + 0.114*50 = 124.2 -> round -> 124`, applied
  to all 3 output channels. This is the standard ITU-R BT.601 luma
  weighting and matches `124,124,124` exactly.
- **"warm" formula** -- solved exactly from probe #8: `200*1.06=212`,
  `100*1.03=103`, `50*0.82=41`, all exact integers, matching
  `212,103,41` exactly.
- **Checksum independent of preset string**: probe #4 vs #6 have
  identical inputs except the preset name (`neutral` vs `mono`), both
  producing output RGB `128,128,128`, and both producing the *exact
  same* hash `56195437`. SHA-256's avalanche property makes it
  essentially impossible for the hash to depend on the preset string
  (or on anything that differs between those two runs) and still come
  out identical by chance, so the checksum is a function of the final
  output RGB triple only (consistent with the static finding that the
  checksum helper takes a single `int[]` argument, which the call
  graph places right after the call that produces the output array).

## What I could NOT recover: the checksum algorithm

I spent a large, deliberate offline effort (no further executions,
purely local Python computation against the two confirmed
`(outputRGB, hash)` pairs: `((128,128,128), 0x56195437)` and
`((0,106,255), 0xB0871470)`) trying to brute-force the exact byte
encoding fed to the (confirmed, from member-refs) double-SHA-256
computation: raw bytes (1 byte/channel and 4-byte-int/channel, both
byte orders), decimal/hex string forms with and without separators,
UTF-8 and UTF-16 encodings, single vs. double vs. triple SHA-256
chaining, every 4-byte window of the resulting digest in both
endiannesses, and combinations with plausible salts (`"PixelTone"`,
etc.). None of these reproduced either observed hash value. Since
SHA-256 is one-way, and I have exhausted my execution budget (8/8
used) to get further data points, I cannot pin this down further.

**Honesty note**: the `compute_checksum()` function in `pixel_tone.py`
is a structurally-motivated placeholder (double SHA-256 of the 3
output bytes) that reproduces the right *format* (8 uppercase hex
digits) but is almost certainly **not** bit-exact to the real binary's
checksum. This is the one part of the reimplementation I cannot
validate.

## What I had to guess (explicitly flagged in code comments too)

- Exact wording of the error messages for invalid/out-of-range numeric
  arguments and for an invalid preset string. Only the "expected 6
  arguments; use --help" message was directly observed; the others
  are generic placeholders (`"invalid numeric argument"`,
  `"invalid preset"`).
- Whether the exit code for those other error types is also 2 (assumed
  yes, from the shared-catch-handler structure, but not independently
  executed/confirmed).
- Exact `NumberStyles` used for parsing R/G/B/brightness/contrast.
  Assumed standard `NumberStyles.Integer` (optional surrounding
  whitespace, optional leading sign, digits only, no decimal point, no
  thousands separator). The use of the 4-argument `TryParse` overload
  (with explicit `NumberStyles` + `CultureInfo.InvariantCulture`,
  accessed via reflection) hints the author deliberately picked a
  specific style, but which one is invisible to static analysis and
  wasn't probed directly (I prioritized the color-math and hash
  questions with my limited execution budget).
- Rounding mode for the brightness/contrast formula and the luma
  calculation: assumed round-half-away-from-zero. None of my 5 "real"
  test vectors contained a genuine `.5` tie (the mono case's
  intermediate `124.2` isn't a tie), so round-half-away-from-zero vs.
  .NET's default round-half-to-even (`Math.Round` banker's rounding)
  remains unresolved. This only matters for the small fraction of
  inputs that land exactly on `x.5`.
- Whether range bounds (`0..255`, `-100..100`, `0..200`) are inclusive
  on both ends. Assumed yes (standard reading of `A..B`, and the only
  values I tested were comfortably inside the range, so boundary
  values were never actually probed).
- Whether clamping happens once at the very end of the whole pipeline
  (what I implemented) vs. also between the preset stage and the
  brightness/contrast stage. All of my preset-isolation tests used
  brightness=0, contrast=100 (an identity transform for that stage),
  so this ordering question was never actually exercised by a case
  where it would matter (i.e. where the preset stage alone pushes a
  channel out of `[0,255]`).
- Preset string matching is assumed case-sensitive, exact match against
  `"neutral"`, `"mono"`, `"warm"` lowercase, matching the help text's
  casing; this was not independently tested (e.g. `"Mono"` or `"MONO"`
  were not tried).
- The anti-debugger (`Debugger.IsAttached`) and self-integrity checks
  are real behaviors in the original binary (confirmed via member refs
  / call graph) but are intentionally **not** reproduced in the Python
  port, since they are anti-tamper mechanisms tied to the original
  native binary's own bytes and the .NET debugging APIs, not part of
  the program's documented/intended CLI behavior, and have no
  meaningful Python analog. Under normal use (no debugger attached,
  unmodified original binary) these checks always pass silently, which
  is the behavior the Python port assumes unconditionally.

## Confidence assessment (no padding)

- **High confidence**: CLI argument contract (6 positional args or
  `--help`), the exact usage text, the "expected 6 arguments" error
  text + exit code 2, the neutral/mono/warm color formulas, output
  format (`R,G,B|HHHHHHHH` with CRLF), and that the checksum does not
  depend on the preset string. All of this is directly confirmed by
  executions, several with exact multi-channel numeric matches that
  are very unlikely to be coincidental.
- **Medium confidence**: that all validation-error paths share exit
  code 2, that `--help` works regardless of trailing extra arguments,
  that range bounds are inclusive, and the general shape of the
  parsing/validation control flow (built from the metadata call graph,
  which is a strong but not 100%-certain signal since it doesn't show
  branch conditions directly, only call-site order).
- **Low confidence / acknowledged guesses**: exact wording of the two
  unobserved error messages, exact rounding mode, and whether clamping
  happens mid-pipeline as well as at the end.
- **Known gap, not guessed away**: the trailing checksum's exact
  algorithm. I could not recover it and the shipped
  `compute_checksum()` will not match the real binary's output on the
  success path. Everything else on the success path (the RGB triple)
  should be exact.
