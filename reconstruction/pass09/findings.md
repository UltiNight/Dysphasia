# PixelTone.exe - Reverse Engineering Findings

## Overview

PixelTone.exe is a small .NET (CIL) console executable (13,824 bytes, x86_64,
IL-only, assembly name PixelTone, v0.0.0.0, no strong name). It is heavily
obfuscated:

- All type and method names are either meaningless hashes (T84d29266f2,
  m_5558f5ab53, ...) or homoglyph-spoofed English words using Cyrillic
  look-alike characters (TransactionBroker-like, AuthenticateSession-like,
  RefreshToken-like, RegisterCallback-like, ResolveDependency-like names -
  several Latin letters in the actual binary are really Cyrillic a/e/o/c/k/p
  look-alikes). These names are deliberately misleading auth/session
  vocabulary; the actual logic is unrelated (color/pixel math).
- Zero ldstr string literals exist anywhere in the assembly
  (inspect-managed-members reports user_strings.literals: []). All
  user-visible text (help text, error messages) is reconstructed at runtime
  from an encrypted byte blob (a 274-byte FieldRVA-backed array) via decode
  routines and assembled with new String(char[]) plus String.Concat. This
  made static string recovery impossible; all exact message text in this
  report was recovered by actually running the program, not by decoding
  the blob.
- Every integer literal in the IL is disguised as a 4-value sequence
  "ldc.i4 A; ldc.i4 B; ldc.i4 A; ldc.i4 B" followed by "xor; and; ldc.i4.2;
  mul; add". This is simply a bit-identity obfuscation of ordinary addition:
  A + B equals (A xor B) + 2*(A and B) for any fixed-width integers. Once
  this was recognized, every such junk-arithmetic block could be collapsed
  back to its real literal value by computing A+B directly (verified
  against the known array-length literal 8 and other recovered constants).
- The entry method (TransactionBroker-like type, ResolveDependency-like
  method, taking string[] and returning int, metadata token 0x06000006) is
  confirmed as the CLI entry point via the PE CLI header's entry_point
  field (metadata-token 0x06000006).
- Several methods use classic control-flow flattening (a switch on a state
  variable inside a dispatch loop). Combined with the fact that REA's
  inspect-managed-members "anchors" list only includes instructions that
  carry an explicit operand (branches, calls, field/type tokens, ldc.i4,
  ldarg/ldloc/stloc indices) and silently omits every operand-less opcode
  (ret, pop, dup, ldlen, conv.i4, ldelem.*, stelem.*, ceq, arithmetic or
  bitwise ops outside the recognized 5-op literal-decode idiom, etc.),
  large methods (the 750-instruction Main, a 410-instruction helper, and
  parts of the 151-instruction RefreshToken-like method) could NOT be
  fully and reliably hand-simulated from static evidence alone - there is
  real arithmetic hidden between visible anchors that cannot be
  positionally recovered. This is an honest, confirmed limitation (see
  "What I could NOT verify" below), not a guess being papered over.
- There are 20 trivial single-method classes, each just a constructor
  calling its base constructor, forming a linear inheritance chain. None
  of them are ever instantiated anywhere in the 108 recorded call edges -
  they appear to be pure decoys/padding and were ignored.
- The binary references System.Security.Cryptography.SHA256,
  HashAlgorithm.ComputeHash, System.Diagnostics.Debugger.get_IsAttached,
  and System.Environment.FailFast - i.e. there is an anti-debugging check
  (if Debugger.IsAttached, call Environment.FailFast with a decoded
  message) and what looks like a second integrity/self-check (a method
  returning bool; if false, also FailFast). Neither of these fires during
  normal use (confirmed: none of my 8 normal runs crashed), so they are
  not modeled in the Python port; they are simply noted as existing.
- Type.GetTypeFromHandle and Type.InvokeMember are referenced but never
  appear on the path exercised by any of my test runs; likely used only in
  the anti-tamper/anti-debug paths. Not modeled.

## Tool limitation note

"rea decompile" / "rea instructions" / "rea function" all fail for this
target with provider_unavailable (Ghidra/Hopper/IDA are either not
configured or explicitly refuse managed PE targets: Windows Ghidra P0
accepts native PE applications and DLLs; managed or unclassified PE
targets are unsupported). So all static analysis had to go through
inspect-managed-artifact and inspect-managed-members (JSON), which was
parsed with a small local Python script. There is no way, with the tools
available in this sandbox, to get a full/faithful decompilation of this
specific obfuscated managed binary.

## CLI contract (confirmed via --help and direct testing)

    PixelTone R G B brightness contrast preset
    R/G/B: 0..255; brightness: -100..100; contrast: 0..200; preset: neutral|mono|warm

- Exactly 6 positional arguments are required for normal operation.
- argv equal to exactly one argument, the literal string "--help", prints
  the two-line usage text above to stdout and exits 0. (Confirmed by
  direct execution.)
- Any other argument count (including 0, and including 1 argument that
  is not exactly "--help") prints "ERROR: expected 6 arguments; use
  --help" to stderr and exits 2. (Confirmed by direct execution for the
  0-argument case; the "1 argument but wrong keyword" case follows from
  the static control flow and was not separately executed.)
- args[0..2] = R, G, B, each validated to the inclusive range [0,255].
- args[3] = brightness, inclusive range [-100,100].
- args[4] = contrast, inclusive range [0,200].
- args[5] = preset, must be exactly one of "neutral", "mono", "warm"
  (case-sensitive; this is the literal text from --help, and static
  analysis of Main shows a 3-way OR of String.op_Equality tests against
  3 decoded keyword strings gating a later ArgumentException throw site -
  consistent with exactly 3 allowed values).
- A non-integer or out-of-range value for any of the first 5 arguments
  produces "ERROR: integer out of range" on stderr, exit code 2.
  (Confirmed by direct execution for the out-of-range case, R=300.) The
  non-numeric/format-failure case was not separately executed, but static
  analysis of the argument-validation helper shows only one newobj/throw
  site for an ArgumentException inside that method, shared by every
  failing branch of its flattened switch - so there is fairly high
  confidence (but no direct execution confirmation) that a non-numeric
  value produces the exact same "ERROR: integer out of range" message
  and exit code 2.
- An invalid/unrecognized preset string: the control-flow shows this also
  throws an ArgumentException, caught by the same top-level handler as
  every other validation error (so almost certainly also exit code 2 on
  stderr), but the exact message text is a guess - execution budget ran
  out before this case could be tested. "ERROR: unknown preset; use
  --help" is used as a plausible placeholder; this is explicitly flagged
  low-confidence in the code.
- All validation failures are caught by a top-level try/catch for
  ArgumentException in Main, which writes "prefix + ex.Message" to
  Console.Error (confirmed via the method's 2 IL exception regions). Any
  other .NET exception type would NOT be caught and would produce a
  normal unhandled-exception crash - not reproduced here, since nothing
  in the confirmed contract should trigger it.

## The core color transform (empirically determined)

The exact per-channel/per-preset arithmetic could not be reliably
recovered from the static IL alone (see the "hidden operand-less opcodes"
limitation above - repeated attempts kept finding stack-depth
inconsistencies that only resolve if there are invisible binary ops that
cannot be positionally placed). Instead, almost the entire 8-run execution
budget was used to empirically determine the transform by holding
variables at "neutral" values and changing one at a time. All values below
are things that were actually run and observed, not guesses.

Confirmed facts, in the order they were obtained:

1. "128 128 128 0 100 neutral" -> "128,128,128|56195437" - brightness=0,
   contrast=100 is an identity transform, and the output format is
   "R,G,B|HASH" where HASH is an unsigned 32-bit value printed as 8 hex
   digits (uppercase; this particular value happens to contain only
   decimal digits, which is why it does not visually look like hex).
2. "128 128 128 20 100 neutral" -> "148,148,148|2D1CBF73" - with contrast
   neutral (100), brightness is added directly: 128+20=148. Not
   percentage-scaled.
3. "150 150 150 0 150 neutral" -> "161,161,161|3B366CA2" - with
   brightness neutral (0), (150-128)*150/100+128 = 22*1.5+128 = 161. This
   fits the formula contrasted = (channel-128)*contrast/100 + 128.
4. "128 128 128 20 150 neutral" -> "148,148,148|2D1CBF73" (identical to
   #2) - this is the critical disambiguator for operation order. If
   contrast were applied after brightness: (148-128)*1.5+128 = 158 (does
   not match). If contrast is applied first, to the original channel
   value, and brightness is added afterward: (128-128)*1.5+128+20 = 148
   (matches exactly). So: contrast first (centered on 128), then add
   brightness, then clamp to [0,255].
5. "200 100 50 0 100 mono" -> "124,124,124|13FE3A3B" - with
   brightness/contrast neutral, preset mono collapses R,G,B to a single
   value shared by all 3 channels. 0.299*200 + 0.587*100 + 0.114*50 =
   124.2, which truncates/rounds to 124 either way - consistent with the
   standard ITU-R BT.601 luma weights, here implemented as integer math
   (R*299+G*587+B*114)/1000 (no floating point types appear anywhere in
   any method signature in the whole assembly, which is why the real
   implementation is believed to be integer, not float, arithmetic
   throughout).
6. "300 100 50 0 100 neutral" -> "ERROR: integer out of range", exit 2 -
   R out of the documented 0..255 range is rejected as described above.

Final per-channel formula used in the Python port:

    contrasted = truncdiv((channel - 128) * contrast, 100) + 128
    adjusted   = clamp(contrasted + brightness, 0, 255)

applied independently to R, G, and B (this matches the call graph: Main
calls a 3-int wrapper method three times, once per channel, with the same
brightness/contrast pair each time, before combining the three results
according to the preset).

### Preset combination

- neutral: pass the three adjusted channels through unchanged. Confirmed
  (case #1 and #4 above use neutral and show no extra transformation).
- mono: grayscale via BT.601-weighted luma of the already
  brightness/contrast-adjusted channels: Y = (R*299+G*587+B*114)/1000
  (integer truncation), output (Y,Y,Y). Confirmed by case #5. Truncation
  could not be distinguished from round-to-nearest in the single data
  point available (both give 124 here); truncation was chosen as more
  typical of integer-only obfuscated C#, but this is a minor unverified
  detail.
- warm: NOT verified at all. Execution budget was exhausted before this
  preset could be tested. An attempt was made to infer it from static
  analysis of the RefreshToken-like method's flattened switch (a block
  was found that computes a single shared value for all 3 output slots
  from weights 150, 29, 128 against R, G, B respectively - but it could
  not be determined whether that block even corresponds to warm vs. mono
  vs. something else, since the actual switch-case-to-offset mapping is
  not exposed by the tooling, and these particular weights do not match
  the empirically confirmed mono weights, so attributing them with
  confidence was not possible). The Python port's warm implementation
  (R+16, B-16, clamped, G unchanged) is an unverified placeholder guess
  and should be assumed likely wrong in its exact magnitude/shape. This
  is the single biggest gap in this reimplementation.

### Output checksum (empirically determined)

The trailing pipe-separated field is the standard 32-bit FNV-1a hash
(offset basis 0x811C9DC5, prime 0x01000193) of the 3 raw output bytes
[R, G, B] (post-preset-combination, post-clamp). This was verified by
brute-forcing dozens of hash-construction hypotheses (various byte
encodings combined with SHA256/MD5/CRC32/FNV/polynomial-rolling hashes)
against all 4 observed (R,G,B) -> hash pairs from the test runs; plain
FNV-1a of bytes([R,G,B]) is the only one that matched all four exactly.
This is trusted despite not fully understanding why the binary also
references SHA256.Create/ComputeHash elsewhere in the same method - the
best guess is that the SHA256 machinery is either dead/decoy code, or
used for a self-integrity check unrelated to the printed value, since the
simple FNV-1a hypothesis fits the observed output perfectly across 4
independent data points with no fitting parameters left over.

## Execution log (all 8 runs used)

1. PixelTone.exe -> stderr: "ERROR: expected 6 arguments; use --help", exit 2
2. PixelTone.exe --help -> stdout usage text, exit 0
3. PixelTone.exe 128 128 128 0 100 neutral -> "128,128,128|56195437", exit 0
4. PixelTone.exe 128 128 128 20 100 neutral -> "148,148,148|2D1CBF73", exit 0
5. PixelTone.exe 150 150 150 0 150 neutral -> "161,161,161|3B366CA2", exit 0
6. PixelTone.exe 128 128 128 20 150 neutral -> "148,148,148|2D1CBF73", exit 0
7. PixelTone.exe 200 100 50 0 100 mono -> "124,124,124|13FE3A3B", exit 0
8. PixelTone.exe 300 100 50 0 100 neutral -> stderr: "ERROR: integer out of range", exit 2

pixel_tone.py was run against the exact same 8 commands and reproduces
every stdout line and exit code exactly (verified directly during
development).

## What I could NOT verify (honest confidence summary)

High confidence (directly observed or forced by unambiguous static evidence):
- Required argument count (6), argument order, and the exact --help text.
- Bounds for R/G/B (0..255), brightness (-100..100), contrast (0..200).
- The 3 allowed preset names (neutral, mono, warm).
- Exit codes: 0 for success/help, 2 for all tested validation errors.
- "ERROR: expected 6 arguments; use --help" and "ERROR: integer out of
  range" message text, exactly.
- The brightness/contrast formula and operation order (contrast on raw
  value, centered at 128, then add brightness, then clamp 0..255).
- The mono luma formula and weights.
- The output format R,G,B|HASH (hex8, uppercase) and the FNV-1a hash
  algorithm.

Medium confidence (plausible, strongly suggested by code structure, but
not directly executed):
- Non-numeric argument values produce the same "ERROR: integer out of
  range" message/exit code as out-of-range values (inferred from the
  validation helper having a single shared exception-construction site).
- argv length of 1 with a value other than --help falls through to the
  same "wrong argument count" error as 0 arguments.
- Integer truncation versus rounding direction in the contrast and luma
  formulas - untested at a boundary that would disambiguate it.
- The anti-debug (Debugger.IsAttached) and a second boolean self-check
  both guard an Environment.FailFast call; not modeled since unreachable
  in normal use and out of scope for a CLI-contract reimplementation.

Low confidence / explicitly flagged guesses in the code:
- The exact error message for an invalid/unrecognized preset value
  ("ERROR: unknown preset; use --help" is a placeholder).
- The entire warm preset formula - genuinely unverified; the Python
  implementation's warm output should be treated as likely wrong in its
  precise numbers (though probably in the right spirit of shifting
  toward red and away from blue).

If more execution budget were available, the highest-value next probes
would be: (a) one run with preset warm at a known baseline to nail that
formula, (b) one run with an invalid preset string to get its exact error
text, (c) one run with a non-numeric value such as "abc" for R to confirm
the shared error message, and (d) one run with a value that makes the
contrast/luma integer division non-exact (e.g. a value ending in a
remainder) to settle truncation versus rounding.
