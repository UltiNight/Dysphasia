# PixelTone.exe — reverse engineering findings

## 0. Summary

`PixelTone.exe` is a tiny (13,824 byte) heavily-obfuscated .NET console
executable (CIL 2.5, x86-64, no PE resources, no native code). It is a
command-line color brightness/contrast adjustment tool:

```
PixelTone R G B brightness contrast preset
```

- `R`,`G`,`B`: integers in `0..255`
- `brightness`: integer in `-100..100`
- `contrast`: integer in `0..200`
- `preset`: one of `neutral`, `mono`, `warm`

On success it prints one line to stdout: `R,G,B|XXXXXXXX` (transformed
color, then a `|`, then an 8-hex-digit checksum) and exits 0. On any
validation failure it prints `ERROR: <message>` to **stderr** and exits
with code **2**. `--help` (and only that, as the sole argument) prints a
2-line usage message to stdout and exits 0.

The binary is run through an obfuscator (ConfuserEx-style): type/method
names are replaced either with meaningless hash-like names (`T84d29266f2`,
`m_5558f5ab53`, ...) or, for a handful of "public-facing" names, with
near-identical homoglyph spellings that substitute Cyrillic lookalike
characters for Latin ones (`TransаctionBrokеr`, `RеsоlveDеpendеncy`,
`АuthenticаteSession`, etc. — the `а`, `е`, `о`, `с` etc. in those are
Cyrillic, not Latin). All string literals are hidden: the `#US` metadata
heap is empty, and every observable text (help text, error messages) is
reconstructed at runtime from two embedded byte-array blobs via helper
methods `T84d29266f2.m_5558f5ab53(start,len,key)` and
`Tdea51d152f.m_a1d9b6d377(start,len,key)`. Every integer literal in the
IL (including those `start`/`len`/`key` triples) is additionally masked
by opaque-predicate junk arithmetic (repeated `ldc.i4`/`xor`/`and`/
`mul`/`add` sequences whose net effect is a fixed, input-independent
constant), and most methods are flattened into `switch`-based state
machines. None of this changes behavior; it only defeats naive static
string/constant extraction.

## 1. Tooling and process

- `rea.mjs inspect-managed-artifact` confirmed: pure IL (`il-only` CLI
  flag), x86-64, mscorlib 4.0.0.0 reference only, assembly name
  `PixelTone`, 27 TypeDefs, 43 MethodDefs, no PE resources, no P/Invoke
  (the CLI header il-only flag combined with zero native-header RVA
  already rules out mixed-mode/native code; the member-ref list contains
  nothing but managed BCL calls).
- `rea.mjs inspect-managed-members --json` gave: full TypeDef/MethodDef/
  FieldDef tables, per-method opcode histograms and a sparse set of
  anchor instructions (branches, calls, loaded constants, NOT a full
  disassembly), a complete `call_edges` list (108 edges, every
  `call`/`callvirt`/`newobj` in the module with caller and resolved
  target), a complete `field_accesses` list, resolved `member_refs`
  (so every call to mscorlib is named, e.g.
  System.Security.Cryptography.SHA256.Create,
  System.Diagnostics.Debugger.get_IsAttached,
  System.Environment.FailFast, System.Console.WriteLine,
  System.String.op_Equality, System.Type.InvokeMember, etc.), and
  confirmation that `user_strings.literals` is empty (no ldstr anywhere
  at all — all text is blob plus runtime reconstruction, as above).
- This tool is static only and cannot evaluate the opaque-predicate
  arithmetic or dump a full instruction stream (by design: the command
  description itself says "CIL anchors", not full disassembly, and the
  task instructions scope me to exactly `inspect-managed-artifact`,
  `inspect-managed-members`, `inspect-managed-native-boundaries`), so the
  exact embedded string bytes and the exact checksum algorithm could not
  be read out of the metadata directly.
- I was given a budget of 8 direct executions of the real binary.
  I used all 8, documented in order below. Every execution exact
  stdout, stderr, and exit code was captured.

## 2. Static analysis: reconstructing the call graph

The entry point (CLI header entry_point token 0x06000006) is
`TransаctionBrokеr.RеsоlveDеpendеncy(string[]) : i4` — i.e. this is
`Main(string[] args)`, just renamed. Its complete, in-order call_edges
list (108 total edges in the module, this method accounts for roughly
52 of them) reads, in groups:

1. `Debugger.get_IsAttached` then (build a message from the string blob)
   then `Environment.FailFast` — an anti-debugging check. (This never
   fired in any of my runs, i.e. no debugger was attached, which is the
   expected/normal case.)
2. a call to a boolean self-check helper (`m_24cbf24160`, which itself
   only calls `SynсMеtadаtа` five times) then another blob message then
   `Environment.FailFast` — looks like a secondary anti-tamper/self-check.
   Also never fired.
3. A string blob is built and compared with `String.op_Equality` against
   almost certainly `args[0]`, gated on some `args.Length` check that
   does not show up in call_edges (array-length comparisons are inline
   ldlen/ceq, not calls) — this is the `--help` detection. On match,
   it calls `m_883d8c15fd` (0 params, returns i4), whose own
   call_edges are exactly two (blob, blob, Concat, Console.WriteLine)
   groups — i.e. it prints exactly two lines. This matches the observed
   `--help` output exactly (two lines, exit 0).
4. If that does not match, another blob message is built and thrown as
   `new ArgumentException(msg)` — this is the wrong-argument-count
   path. (No direct Console.WriteLine appears for this message inside
   Main, which is explained by point 8 below: it is not printed inline,
   it is thrown and later caught.)
5. Five calls to `RеgisterCаllbасk(string, i4, i4) : i4`. Looking at
   that method own call graph: get_InvariantCulture, a custom parse
   helper `Tdea51d152f.m_2f5130fe51(string, ..., out i4)` returning
   bool, then (on failure) a blob message + Concat + newobj
   ArgumentException. Its own anchor instructions show
   `ldloc<parsed>, ldarg<min>, blt -> fail` and `ldloc<parsed>, ldarg<max>,
   ble -> ok` — i.e. this is a generic
   `int ParseAndValidateRange(string s, int min, int max)` that throws on
   parse failure or out-of-range. Five calls map to five validated
   integers: R, G, B, brightness, contrast, each presumably with its own
   (min,max) pair matching the --help text (0..255 times 3, -100..100,
   0..200).
6. Three `String.op_Equality` comparisons (against blob-built strings),
   interspersed with calls to a few more m_5558f5ab53 blob-string
   lookups, ending in a blob message + newobj ArgumentException on the
   else path — this is the `preset is one of {neutral, mono, warm}`
   check (3 names, 3 comparisons, exactly the 3 presets in the --help
   text).
7. Three calls to `АuthenticаteSession(i4,i4,i4):i4` (which itself just
   forwards to m_86cad6b8ca with its 2nd/3rd args swapped), one call to
   `RefrеshToken(i4,i4,i4,string):i4[]`, then `InitializеСасhe(i4[]):u4`
   (whose own call graph is exactly SHA256.Create() plus
   HashAlgorithm.ComputeHash() called twice), then
   Console.WriteLine — this is the success path: compute the
   transformed color, hash it into a u4 checksum, print the result.
8. The whole thing is wrapped in a try/catch: the catch block uses
   Console.Error (not Console.Out), builds a blob prefix, reads
   Exception.get_Message, concatenates, and calls
   TextWriter.WriteLine — i.e. every thrown ArgumentException
   from steps 4/5/6 is caught centrally and printed as a single line to
   stderr, prefixed with something (confirmed below to be
   "ERROR: "), and the method then returns a fixed exit code.

This static picture, on its own, already predicts almost the entire
observable contract. The 8 executions were used to pin down the exact
text/formatting and to reverse the one real numeric formula (the color
transform), since that cannot come from opaque-predicate-masked constants
without a lot more tooling than was available.

## 3. The eight executions, in order

| # | Command | stdout | stderr | exit |
|---|---------|--------|--------|------|
| 1 | PixelTone.exe (no args) | (empty) | ERROR: expected 6 arguments; use --help | 2 |
| 2 | PixelTone.exe --help | PixelTone R G B brightness contrast preset / R/G/B: 0..255; brightness: -100..100; contrast: 0..200; preset: neutral mono warm | (empty) | 0 |
| 3 | PixelTone.exe 128 64 32 10 120 neutral | 138,62,23 pipe 2569204A | (empty) | 0 |
| 4 | PixelTone.exe (no args, streams split) | (empty) | ERROR: expected 6 arguments; use --help | 2 |
| 5 | PixelTone.exe 300 0 0 0 100 neutral | (empty) | ERROR: integer out of range | 2 |
| 6 | PixelTone.exe 0 0 0 0 100 foo | (empty) | ERROR: unknown preset | 2 |
| 7 | PixelTone.exe abc 0 0 0 100 neutral | (empty) | ERROR: integer out of range | 2 |
| 8 | PixelTone.exe 255 0 128 -50 200 mono | 86,86,86 pipe 133A58A1 | (empty) | 0 |

(The literal stdout format is `R,G,B` then a pipe character `|` then the
8-hex checksum, e.g. literally `138,62,23|2569204A`; the pipe character is
written out as the word "pipe" above only to keep this table simple to
read.)

Run 1 was repeated as run 4 (with stdout/stderr captured into separate
files) specifically because run 1 had stdout and stderr merged in the
shell capture and I wanted to be certain the error text goes to stderr,
not stdout — confirmed.

Key conclusions from these runs:

- Argument count: exactly 6 positional args required, or exactly 1
  arg equal to `--help`. Anything else produces
  `expected 6 arguments; use --help` on stderr, exit 2. (Run 1/4.)
- `--help` exit code is 0, printed to stdout, exactly 2 lines,
  verbatim as shown above. (Run 2.)
- Numeric validation is a single undifferentiated check: a
  non-numeric string (`abc`, run 7) and a numeric-but-out-of-range value
  (`300` for R, whose stated range is 0..255, run 5) produce the
  identical message `ERROR: integer out of range`. There is no separate
  "could not parse" vs "out of range" wording, and the message never
  names which argument or what the valid range was — it is fully
  generic. This matches the static picture of a single
  ParseAndValidateRange helper used for all five numeric fields.
- Preset validation is a separate, later check: `ERROR: unknown
  preset` (run 6), independent wording from the numeric error, also exit
  2, also stderr-only.
- Negative numbers parse fine (brightness=-50 in run 8) — the
  argument parser is not confused by a leading minus sign (i.e. it is not
  naively treating leading-dash tokens as flags).
- Success format is `R,G,B|XXXXXXXX` on stdout, exit 0, where `R,G,B`
  is the transformed color (not the raw input) and `XXXXXXXX` is an
  8-character uppercase hex checksum.

### 3.1 Reverse engineering the color transform (HIGH confidence)

From run 3: inputs R=128,G=64,B=32, brightness=10, contrast=120,
preset=neutral, output color 138,62,23.

Testing the hypothesis "classic brightness/contrast formula with a 128
pivot, contrast expressed as a percentage, applied per channel, clamped
to [0,255], using C# truncate-toward-zero integer division":

```
new = clamp( trunc((old - 128) * contrast / 100) + 128 + brightness, 0, 255 )
```

- R: (128-128)*120/100 = 0, then 0+128+10 = 138, matches.
- G: (64-128)*120/100 = -64*120/100 = -7680/100 = -76 (truncated toward
  zero, not -77), then -76+128+10 = 62, matches.
- B: (32-128)*120/100 = -96*120/100 = -11520/100 = -115 (truncated),
  then -115+128+10 = 23, matches.

All three channels match exactly using truncating (not flooring)
integer division — this distinction matters in Python, where `//` floors
negative results, so the Python reimplementation has an explicit
`_trunc_div` helper. Run 8 (255,0,128,-50,200,mono, which also exercises
R-channel clamping to 255 and G-channel clamping to 0 inside the mono
averaging, see below) is consistent with the same per-channel formula
feeding into the mono step. I am highly confident this formula is exact
for the neutral preset, since two independent channels (G, B) with two
different signs of (old-128) both matched a non-trivial integer-division
computation exactly, with no tunable slack left.

### 3.2 The mono preset (MEDIUM confidence)

Run 8: R=255,G=0,B=128, brightness=-50, contrast=200, preset=mono,
output 86,86,86.

Per-channel transform (same formula as above) clamped to [0,255] gives
intermediate (255, 0, 78) (R clamps up from 332, G clamps down from
-178, B is 78 unclamped). I then brute-forced, in plain Python (not
against the real binary, no executions spent), candidate ways to reduce
(255,0,78) to a single gray value equal to the observed 86. The
standard ITU-R BT.601 integer luma weights (299, 587, 114)/1000 (an
extremely common grayscale-conversion constant in image-processing code)
reproduce 86 exactly, provided the division rounds up (ceiling) rather
than truncating or rounding-to-nearest:

```
ceil((255*299 + 0*587 + 78*114) / 1000) = ceil(85137/1000) = ceil(85.137) = 86
```

I implemented this (per-channel transform, clamp, then ceiling BT.601
luma, clamp again, replicate to all 3 channels). I flag this as medium
rather than high confidence: it is reverse-fit to a single sample, the
ceiling rounding is a slightly unusual choice (most real code either
truncates or rounds-to-nearest with a +500 bias before dividing by
1000, neither of which matches here), and no second mono sample was
available to cross-check. A different weight set or rounding rule could
coincidentally reproduce this one data point too.

### 3.3 The warm preset (LOW confidence, effectively a guess)

I never got an execution slot to actually test preset=warm against the
real binary (the 8-execution budget was prioritized toward nailing the
CLI contract, error paths, and the neutral/mono formulas, which seemed
more valuable and more tractable to pin down exactly). The
`pixel_tone.py` implementation applies a speculative "push red up, blue
down by a fixed amount after the normal transform" effect, clearly
commented as unverified. This is the single biggest known gap: the
Python script output for preset=warm is not reverse engineered, it is
invented, and should not be trusted to match the real binary.

### 3.4 The trailing checksum (UNRECOVERED, essentially a placeholder)

Both successful runs produced an 8-hex-digit suffix (2569204A,
133A58A1). Static analysis shows this comes from a method
(InitializеСасhe) that calls SHA256.Create() and
ComputeHash() twice. I tried, by local computation only (no
executions spent), dozens of plausible byte-serializations of the
transformed color (and various combinations with the original inputs,
the preset name, little/big-endian 32-bit ints, ASCII decimal strings,
single vs double SHA-256, and truncating the digest from the front,
back, or via XOR-folding) against both observed input/output pairs.
None matched. This is expected: two known plaintext/digest pairs are
nowhere near enough information to invert or reconstruct an unknown
SHA-256-based construction, especially since the binary almost certainly
mixes in one of its two hidden byte-blob secrets as a salt (recall: all
string literals are stored in exactly two such blobs, and nothing rules
out them being reused as hash input rather than only as display text).

The Python reimplementation checksum field is explicitly a placeholder
(documented in its own docstring) that produces the right shape (8
uppercase hex chars, derived via SHA-256 of the computed color) but will
not match the real binary value except by coincidence. Faithfully
reproducing this one field was, as far as I can tell, not achievable
within the static-analysis tooling and 8-execution budget given to me
for this task.

## 4. Confidence summary (explicit, not inflated)

- Argument count / --help detection / usage text: HIGH. Directly
  observed, byte-exact, twice-reproduced for the no-args case.
- stdout vs stderr split, exit codes (0 success/help, 2 any error):
  HIGH. Directly observed across 6 of the 8 runs.
- Numeric parsing plus range validation funnels to one generic
  "integer out of range" message regardless of cause: HIGH. Directly
  observed (both a non-numeric and an out-of-range input produce
  identical text).
- Preset enum validation (neutral/mono/warm) and its distinct
  "unknown preset" message: HIGH for the message text and the three
  valid names (from --help text, and neutral/mono both directly
  exercised successfully). Case-sensitivity of preset matching was never
  tested; I assumed case-sensitive lowercase-only based on the --help
  text casing — this is an assumption, not a verified fact.
- neutral color transform formula: HIGH. Exact integer formula
  confirmed via two independently-signed channels with non-trivial
  truncating division.
- mono grayscale formula: MEDIUM. Matches its one available sample
  exactly using a very standard, plausible formula, but unconfirmed
  against a second case.
- warm formula: LOW. Not tested at all; implementation is a labeled
  guess.
- 8-hex checksum: essentially UNRECOVERED. The implementation is a
  cosmetic placeholder only, explicitly documented as such in code.
- Anti-debug / self-check / FailFast paths: not reproduced in
  pixel_tone.py at all (a Python script has no equivalent of "is a
  native debugger attached to this CLR process", and both checks passed
  silently in every real run I made, so there was nothing observable to
  replicate here; their existence is noted for completeness but they
  have no effect on normal usage).
- Whether --help is recognized anywhere other than as the sole argument
  (e.g. mixed in with 6 other args) was not tested; the Python
  implementation only recognizes the sole-argument form, based on the
  static control-flow shape rather than direct observation.

## 5. Files

- `pixel_tone.py` — the reimplementation. Every uncertain piece (mono
  weights/rounding, warm transform, checksum) is called out in a
  docstring at its point of use, in addition to this document.
