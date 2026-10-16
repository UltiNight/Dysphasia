# PixelTone.exe — Reverse Engineering Findings

> Authored by the orchestrator from the subagent's final hand-back message. The
> subagent's own Write tool refused `findings.md` with "Subagents should return
> findings as text, not write report files," so the content below is transcribed
> verbatim from its chat report rather than written by the subagent directly.

## Summary (under 300 words, as the subagent reported it)

PixelTone.exe is a tiny (13.8KB) obfuscated .NET console app. CLI contract (fully
confirmed): `PixelTone R G B brightness contrast preset`, R/G/B 0..255, brightness
-100..100, contrast 0..200, preset in {neutral,mono,warm}; or exactly `--help`. On
success it prints `R,G,B|HHHHHHHH` (final RGB triple + 8-hex-digit checksum) to
stdout, exit 0. On any arg-count/parse/range/preset problem it prints `ERROR: <msg>`
to stderr, exit 2.

Pipeline (per channel): `clamp(128 + trunc((v-128)*contrast/100) + brightness, 0, 255)`,
then a preset transform: neutral=identity; mono=integer BT.601 luma
`(299R+587G+114B)/1000` replicated to all channels; warm is approximately R×1.06,
G×1.03, B×0.82 (integer truncation). The printed checksum is standard 32-bit FNV-1a
(offset 2166136261, prime 16777619) over the final 3 RGB bytes, found by brute-forcing
standard hash algorithms against 5 real outputs after SHA-256 (visibly called in the
IL) turned out to be a decoy/self-check, not the real algorithm.

**Confidence**: High for the CLI contract, brightness/contrast formulas, mono preset,
the checksum algorithm (exact match on 5/5 real samples), and error text for
arg-count/numeric-range (both confirmed verbatim against the real binary, which was run
8 times total). Medium for the brightness-before/contrast order when both are
simultaneously non-default (never isolated). Low/guessed: warm's exact coefficients
(fit to one sample that divided evenly, so denominator is ambiguous), and the
"invalid preset" error text (never observed, no run budget left to probe it). Two
internal `Environment.FailFast`/`Debugger.IsAttached`-guarded anti-tamper checks exist
in the binary but never fired in normal runs and are not reproduced in Python.

`pixel_tone.py` reproduces all 8 observed real outputs byte-for-byte including exit
codes.

## Full findings

### 0. Tooling and its limits

`rea inspect-managed-artifact` on `PixelTone.exe` confirmed: pure IL (`cli flags:
il-only`), x86_64 managed PE, single module `PixelTone`, references only `mscorlib`,
no native boundaries.

`rea inspect-managed-members --full-output` gave type/method/field tables, a call-edge
graph, and member-ref list, very useful for seeing which BCL APIs are used and in what
order. However, its per-method "anchors" are a curated, incomplete subset of the real
instruction stream: common arithmetic/comparison opcodes (`xor`, `and`, `mul`, `add`,
`ceq`, `cgt`, `dup`, etc.) are tallied in `opcode_counts` but mostly omitted from the
anchor listing itself, even with `--full-output`. `rea decompile`/`rea instructions`
refused outright (`managed_target_unsupported`, the only decompiler backend available
on this host, Ghidra, explicitly rejects managed PE/CIL images). So the exact
obfuscated-constant arithmetic and full CFG of the two largest methods (Main at 750 IL
instructions, the checksum method at 242) could not be fully recovered statically.
Static analysis was used for structure/call-order, and all 8 permitted direct
executions were used to pin down actual observable behavior, plus offline
brute-forcing of standard hash algorithms against real outputs for the checksum.

### 1. Obfuscation style observed

Every method is control-flow-flattened into a switch-based state machine. Nearly every
integer constant is replaced by a decoy computation (two numbers pushed twice,
combined via xor/and/mul/add so the result is a fixed constant regardless of what the
carrier numbers "look like"). There are no string literals (`#US` stream heap empty),
every string is reconstructed at runtime from an embedded encrypted byte array
(`FieldRVA`-initialized `u1[]` fields) plus obfuscated key/seed constants via two
internal decoder methods. Class/method names are disguised, several using Cyrillic
homoglyphs to visually mimic plausible English names (e.g. `TransаctionBrokеr` ~
"TransactionBroker", `АuthenticаteSession` ~ "AuthenticateSession") while not matching
byte-for-byte. There are also 20 trivial one-method padding classes (`.ctor`, 7 IL
bytes each) chained via inheritance, pure noise, ignored.

### 2. Static type/method map

- Entry point (token 0x06000006, `(string[])->int`) is the method disguised as
  `RеsоlveDеpendеncy`, this is `Main`.
- `АuthenticаteSession(a,b,c)` is a thin wrapper that just reorders 2 args into
  `m_86cad6b8ca(a,c,b)`, called 3x from Main right before the preset dispatch call.
  Inferred (and confirmed by testing) to be the per-channel brightness+contrast
  helper.
- `RefrеshToken(a,b,c,presetStr)` decodes 2 string literals, compares `presetStr`
  against them via `String.op_Equality`, and dispatches to either a 17-IL-instruction
  identity method (neutral) or a 410-IL-instruction method (mono/warm).
- `InitializеСасhe(int[])` computes the printed checksum. It visibly calls
  `SHA256.Create()`/`HashAlgorithm.ComputeHash` twice, but per the call graph this
  sits behind an opaque-predicate branch feeding only an `Environment.FailFast`
  trip-wire, a decoy, not the real algorithm (confirmed empirically).
- `RеgisterCаllbасk(string,int min,int max)` parses one numeric CLI argument via a
  method matching the signature of `int.TryParse(string, NumberStyles,
  IFormatProvider, out int)`, with the NumberStyles constant 7 = NumberStyles.Integer
  (AllowLeadingWhite|AllowTrailingWhite|AllowLeadingSign) directly visible in the IL,
  using `CultureInfo.InvariantCulture`. Its flattened state machine shows: parse-fail
  to error state; `parsed < min` to error state (via `blt`, i.e. min is inclusive);
  `parsed <= max` to success (via `ble`, i.e. max is inclusive) else error. All three
  failure modes converge on one shared error state that builds one message and throws
  one `ArgumentException`, confirmed structurally (and later empirically) to be a
  single generic message for all 5 numeric CLI arguments regardless of which one or
  which bound failed.
- Two parameterless bool-returning methods are called early in Main, each apparently
  guarding an `Environment.FailFast`, alongside an explicit `Debugger.IsAttached`
  check, read as anti-debug/anti-tamper trip-wires. Never observed to trigger in 8
  plain-console runs.

### 3. The 8 real executions (exact outputs)

| # | Command | Output | Exit |
|---|---|---|---|
| 1 | *(no args)* | `ERROR: expected 6 arguments; use --help` | 2 |
| 2 | `--help` | usage (2 lines) | 0 |
| 3 | `100 150 200 0 100 neutral` | `100,150,200\|975A9C15` | 0 |
| 4 | `240 100 10 30 100 neutral` | `255,130,40\|C0A5B7E4` | 0 |
| 5 | `203 178 78 0 133 neutral` | `227,194,62\|4986A30A` | 0 |
| 6 | `200 100 50 0 100 mono` | `124,124,124\|13FE3A3B` | 0 |
| 7 | `200 100 50 0 100 warm` | `212,103,41\|4F2DD6DF` | 0 |
| 8 | `300 100 100 0 100 neutral` | `ERROR: integer out of range` | 2 |

### 4. Brightness/contrast formula (confirmed)

```
diff   = value - 128
scaled = trunc(diff * contrast / 100)      # C#-style truncation toward zero
result = clamp(128 + scaled + brightness, 0, 255)
```
applied per-channel with the same brightness/contrast. Caveat: run #4 held contrast at
identity, run #5 held brightness at zero, neither tests both non-default
simultaneously, so the exact combination order when both matter at once is inferred
from the call graph and convention, not directly observed.

### 5. The checksum: FNV-1a 32 (very high confidence)

`InitializeCache` visibly calls `SHA256.Create()`/`ComputeHash` twice, which looked
like a truncated-SHA256 checksum. Every plausible encoding was tried (1-byte-per-
channel, 4-byte LE/BE ints, ASCII/UTF-16 CSV strings, single/double hash, truncated
from either end) against CRC32, Adler32, MD5, and SHA256, none matched. Re-examining
the call graph, the `ComputeHash` pair sits behind an opaque-predicate branch feeding
only `Environment.FailFast`, a decoy/self-integrity check, not the returned value.

Brute-forcing standard non-cryptographic hashes against the 5 real (R,G,B)->checksum
pairs instead, standard 32-bit FNV-1a (offset basis 2166136261, prime 16777619, over
bytes R,G,B in that order) matched all 5 exactly:
```
h = 2166136261
for byte in (R,G,B):
    h = (h ^ byte) & 0xFFFFFFFF
    h = (h * 16777619) & 0xFFFFFFFF
# print f"{h:08X}"
```
Since the 5 inputs varied brightness/contrast/preset but the checksum only ever
depended on the final (R,G,B) triple, this also proves the checksum is a pure function
of the final visible triple, independent of the earlier stages.

### 6. Confidence summary (not padded)

**High** (directly confirmed): full CLI contract and --help text; arg-count error text
+ exit 2; numeric parse/range error text ("integer out of range") shared across all 5
numeric args + exit 2; brightness formula; contrast formula (including rounding mode);
neutral=identity; mono=integer BT.601 luma; checksum=FNV-1a-32; stdout/stderr split and
exit 0/2.

**Medium**: brightness/contrast combination order when both are simultaneously
non-default (never isolated in a single run); that every preset always runs strictly
after brightness/contrast (only confirmed per-preset with brightness/contrast held at
identity).

**Low / explicitly flagged guesses**:
- `warm`'s exact multipliers (106%, 103%, 82%, truncating division by 100), fit to one
  sample whose numbers divide evenly by 100, so the true denominator/rounding rule is
  genuinely underdetermined.
- The exact "invalid preset" error message text, never observed; all 8 runs were spent
  on higher-priority probes. `pixel_tone.py` uses an unverified placeholder.
- The exact trigger condition for `--help` beyond the single tested invocation.
- The two internal anti-debug/anti-tamper checks are not reproduced in Python,
  deliberate, documented gap; they never fired in 8 plain-console runs so their
  trigger conditions are unknown.
