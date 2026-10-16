# PixelTone.exe — Reverse-Engineering Findings (pass03)

Target: `artifacts\protected-p1p2p3\PixelTone.exe`
SHA-256: `eddf63044ce45e2897df23321c543350125679964c8e8d74afbd056ea675c9db`
Byte length: 8704. PE32+ (x86_64), CLI (managed .NET), 2 sections.

This report covers static analysis via REA's managed-code tools, supplementary
hand-written CIL decoding, and 8 confirmatory live probes, in that order —
mirroring the actual order of work. `pixel_tone.py` in this directory is the
resulting reimplementation.

## 1. Static analysis via REA

### 1.1 `inspect-managed-artifact` (evidence `ev_2ad524fecd02e126d1c757da82c0fa80d1fcd70bab81492d2160d629ecba40cc`)

Command: `rea inspect-managed-artifact PixelTone.exe --json` (log:
`logs/pass03/01-artifact.stdout.json`).

Observed facts:
- PE: machine `0x8664` (x86_64), `pe32-plus` optional header, 2 sections.
- CLI header at file offset 512, runtime version `2.5`, flags `il-only`
  (no native code, no mixed-mode).
- **Entry point: metadata token `0x06000006`** — this is the method REA later
  reports as `m_ec38e2401a`, i.e. `Main`.
- Metadata: version string `v4.0.30319`, streams `#Blob #GUID #Strings #~`,
  status `complete`, no coverage issues.
- Table row counts: `Module:1 TypeRef:15 TypeDef:3 MethodDef:7 Param:15
  MemberRef:14 CustomAttribute:2 StandAloneSig:6 Assembly:1 AssemblyRef:1`.
  Only **3 types** and **7 methods** total — a very small, single-file
  program.
- Module MVID `7cf7801a-1342-367a-2a70-668ba128cada`.
- Assembly identity: name `PixelTone`, version `0.0.0.0`, no strong name /
  public key.
- Single reference: `mscorlib, Version=4.0.0.0, PublicKeyToken=b77a5c561934e089`
  — this targets the classic .NET Framework (4.x) `mscorlib`, not
  `System.Private.CoreLib`/.NET Core, and not .NET Standard (no
  `target_frameworks` reported). This is relevant to the console newline
  convention (see Section 3, probe 1).
- Two custom attributes on the assembly: `CompilationRelaxationsAttribute`
  and `RuntimeCompatibilityAttribute` — both are ordinary C#-compiler-emitted
  boilerplate, not behaviorally relevant.
- `classification.status = "managed"`, `implementation = "cil"`,
  `runtime_family = "unknown"` (REA leaves this unknown absent an explicit
  ReadyToRun/NativeAOT marker — consistent with an ordinary IL-only build).

### 1.2 `inspect-managed-members` (evidence `ev_a7f5683d817aa9b235c8a844f675aaa3e3e811a8e31c288a13ac383834dc55b4`)

Command: `rea inspect-managed-members PixelTone.exe --json` (log:
`logs/pass03/02-members.stdout.json`).

**Types** (both build-local names are compiler/obfuscator-generated noise,
not meaningful identifiers):

| Token | Name | Flags (decoded) | Extends | Methods |
|---|---|---|---|---|
| `0x02000001` | `<Module>` | 0 | — | 0 |
| `0x02000002` | `Teeef425ae1` | `0x100040` = Sealed + BeforeFieldInit | `0x01000001` (-> `System.Object`, inferred) | 6 (tokens `0x06000001`-`0x06000006`) |
| `0x02000003` | `T84d29266f2` | `0x180` = Abstract + Sealed (C#'s `static class` pattern) | `0x01000001` | 1 (token `0x06000007`) |

So the program is one `internal sealed class` holding `Main` + 5 helpers,
plus one `static class` holding a single string-decoding helper.

**`user_strings.literals` was empty, state `complete`.** No `ldstr`
instructions anywhere in the assembly. Every human-readable string in this
program (help text, error messages, the `"mono"`/`"warm"`/`"neutral"`
preset names, the `"--help"` flag, the output format string) is stored as a
`byte[]` literal (built at runtime via `dup`/`stelem.i1` pairs) and decoded
through a single XOR-with-one-byte-key helper, call token `0x06000007`. This
is a deliberate (if extremely weak) string-hiding obfuscation; REA's
string-literal scanner correctly reports nothing, which is *why* a
supplementary decode (Section 2) was necessary to recover any of the
user-facing text.

**`member_refs`** (external members, all from `mscorlib`) resolved by REA
with full signatures:

| Token | Declaring type | Member | Signature |
|---|---|---|---|
| `0x0a000001` | `System.String` | `op_Equality` | `(string,string)->bool` |
| `0x0a000002` | `System.Globalization.CultureInfo` | `get_InvariantCulture` | `()->CultureInfo` |
| `0x0a000003` | `System.Int32` | `TryParse` | `(string, NumberStyles, IFormatProvider, out int)->bool` |
| `0x0a000004` | `System.ArgumentException` | `.ctor` | `(string)->void` |
| `0x0a000005` | `System.Console` | `WriteLine` | `(string)->void` |
| `0x0a000006` | `System.String` | `op_Inequality` | `(string,string)->bool` |
| `0x0a000007` | `System.Console` | `WriteLine` | `(string, object[])->void` |
| `0x0a000008` | `System.Console` | `get_Error` | `()->TextWriter` |
| `0x0a000009` | `System.Exception` | `get_Message` | `()->string` |
| `0x0a00000a` | `System.String` | `Concat` | `(string,string)->string` |
| `0x0a00000b` | `System.IO.TextWriter` | `WriteLine` | `(string)->void` |
| `0x0a00000c` | `System.String` | `.ctor` | `(char[])->void` |
| `0x0a00000d`/`0x0a00000e` | attribute ctors | — | boilerplate |

**`call_edges`** gave the full call graph (method-def to method-def and
method-def to member-ref edges), which is what let me determine, *before*
decoding a single CIL byte, that: `Main` (`0x06000006`) calls the string
decoder (`0x06000007`) many times, calls a 3-argument helper (`0x06000002`)
exactly 3 times in a row, calls a 4-argument helper (`0x06000003`) once, and
calls a 1-argument helper (`0x06000004`) once, in that order, right before a
`Console.WriteLine(string,object[])` — already a strong hint at a
"transform 3 channels, combine, hash, print" shape before I had read the
opcodes.

**Per-method CIL metrics** (`anchors`, `opcode_counts`, `il_sha256`,
`file_offset`, `il_size` — all from this same evidence record):

| Token | Name | file_offset | il_size | il_sha256 (first 12 hex) | Notable opcodes |
|---|---|---|---|---|---|
| `0x06000001` | `m_4e09ee408f` | 592 | 145 | `7166eb95c077` | `switch`, `blt`, `bgt` |
| `0x06000002` | `m_b2ece2c34c` | 749 | 38 | `ed17b8f2b4cb` | `sub,mul,div,add,add,call` |
| `0x06000003` | `m_b3c4f3c803` | 788 | 528 | `793dc98a62e7` | `switch`, 2x(`newarr`+`call`+`op_Equality`) |
| `0x06000004` | `m_0481f84d57` | 1328 | 144 | `f58e6b11de05` | `switch`, `xor`, `mul`, `blt` |
| `0x06000005` | `m_22283830b7` | 1484 | 453 | `08548e52d328` | `switch`, `call TryParse`, `blt`, `ble`, `throw` |
| `0x06000006` | `m_ec38e2401a` | 1952 | 3308 | `e46e0b1d7181` | entry point; `bne.un`, `beq`, `brfalse` x3, `leave` x2, `throw` x2 |
| `0x06000007` | `m_5558f5ab53` | 5300 | 74 | `58e062b63566` | `ldelem.u1`, `xor`, `conv.u2`, `stelem.i2`, `newobj` |

All 7 methods reported `body.status = "present"`, `coverage.state =
"complete"`, no issues — REA fully decoded every instruction's *opcode*; the
limiting factor was only that its `anchors` array is a *curated subset*
(branches/constants/calls/switches — explicitly not "the full instruction
stream" per REA's own documentation) and that it never decodes the actual
*values* hidden behind the XOR obfuscation. Both gaps motivated Section 2.

Notably: `inspect_managed_members`'s per-method `exception_regions` field
was `[]` (empty) for every method, **including `Main`**. This turned out to
be materially incomplete for my purposes — see Section 2.3.

## 2. Supplementary CIL decoding

REA's docs (`managed-code-analysis.md`) explicitly invite decoding full
method bodies from `file_offset`/`il_size` when anchors aren't enough. I
wrote a small ECMA-335 CIL disassembler (kept in session scratch space, not
shipped as a deliverable — logic is fully described here) that:

1. Opens the `.exe` directly and reads the method header at each reported
   `file_offset` (I verified the byte-for-byte mapping
   `file_offset = rva - 7680` holds for all 7 methods using the `rva`/
   `file_offset` pairs REA reported, confirming there is exactly one
   RVA-to-file-offset delta for this tiny image).
2. Parses the *tiny* or *fat* method header (ECMA-335 Section II.25.4) to
   get `code_start`, code size, max stack, and the `MoreSects` flag.
3. Decodes the raw CIL bytes with a full single-byte (`0x00`-`0xE0`) and
   `0xFE`-prefixed two-byte opcode table (the standard ECMA-335/
   `System.Reflection.Emit.OpCodes` table), resolving branch/switch targets
   to absolute IL offsets.
4. For `newarr <Byte> ; (dup; ldc.i4 idx; ldc.i4 val; stelem.i1)* ; ldc.i4 key
   ; call 0x06000007` sequences (the obfuscated-string-construction idiom
   used everywhere in this binary), automatically extracts the byte array
   and key and computes `chr(byte xor key)` to recover the literal text —
   this is exactly what REA's own `m_5558f5ab53` body does at runtime (see
   Section 2.2), just run statically instead of by executing the target.

I did **not** execute the target to get any of this; it is 100% derived
from the bytes of the `.exe` file at the offsets REA already reported,
which is a read operation, not an execution, and is explicitly sanctioned by
REA's own docs for exactly this situation.

### 2.1 Recovered strings

| Decoded text | Byte count | XOR key | Used in |
|---|---|---|---|
| `--help` | 6 bytes `[245,245,176,189,180,168]` | 216 | `Main`, single-arg flag check |
| `PixelTone R G B brightness contrast preset` | 42 bytes | 133 | `Main`, help line 1 |
| `R/G/B: 0..255; brightness: -100..100; contrast: 0..200; preset: neutral|mono|warm` | 81 bytes | 13 | `Main`, help line 2 |
| `expected 6 arguments; use --help` | 32 bytes | 35 | `Main`, arg-count error |
| `neutral` | 7 bytes `[44,39,55,54,48,35,46]` | 66 | `Main`, preset check |
| `mono` | 4 bytes `[55,53,52,53]` | 90 | `Main` and `BuildTriplet` (`0x06000003`), preset check |
| `warm` | 4 bytes `[250,236,255,224]` | 141 | `Main` and `BuildTriplet`, preset check |
| `unknown preset` | 14 bytes | 41 | `Main`, preset error |
| `{0},{1},{2}|{3:X8}` | 18 bytes | 49 | `Main`, output format string |
| `ERROR: ` | 7 bytes `[17,6,6,27,6,110,116]` | 84 | `Main`, stderr prefix |
| `integer out of range` | 20 bytes | 181 | `ParseIntRange` (`0x06000005`), the one shared validation-error message |

Each entry above was cross-checked against REA's `call_edges` (which
`0x06000007` call site feeds which `op_Equality`/`WriteLine`/`throw`/etc.)
so the mapping from string to usage site is not a guess — it falls directly
out of the decoded instruction sequence immediately following each string
construction.

### 2.2 Method-by-method semantics (fully decoded)

All six real methods use the *identical* obfuscation idiom: a local
"dispatch" variable initialized to a small constant, a `switch` on that
variable jumping to one of several code blocks, and each block either
setting the dispatch variable to a new value and looping back (`br` to the
`nop` right before the `switch`) or `ret`/`throw`ing. This is classic
control-flow flattening; once the switch tables and branch targets are
resolved it collapses to ordinary structured code. I traced every state
transition by hand for each method (full IL offsets available in the
decoder output; omitted here for brevity since the resulting pseudocode is
exact and the per-state detail adds nothing a reviewer could not re-derive
from `il_sha256` + file offset).

**`0x06000001` `m_4e09ee408f` — `int Classify(int x)`**
Pure byte-clamp: returns 255 if x>255, 0 if x<0, else x. I.e. `Clamp(x, 0, 255)`.

**`0x06000002` `m_b2ece2c34c` — `int Tone(int channel, int brightness, int contrast)`**
`return Clamp( (channel-128)*contrast/100 + 128 + brightness )` (calls
`Classify` for the clamp). Division is CIL `div`, i.e. C# integer division
truncating toward zero, not Python's floor division — handled explicitly in
`pixel_tone.py`'s `_trunc_div`. This is a standard brightness/contrast
pixel-tone transform, matching the program's name.

**`0x06000003` `m_b3c4f3c803` — `int[] BuildTriplet(int r, int g, int b, string mode)`**
```
if mode == "mono":
    luma = (77*r + 150*g + 29*b + 128) >> 8     # standard 8-bit luma weights
    return [luma, luma, luma]
elif mode == "warm":
    return [Clamp(r+12), Clamp(g+3), Clamp(b-9)]
else:
    return [r, g, b]                             # "neutral" and (defensively) anything else
```

**`0x06000004` `m_0481f84d57` — `uint Hash(int[] values)`**
Textbook 32-bit FNV-1a: offset basis `0x811C9DC5` (seen in the IL as the
`int32` literal `-2128831035`, the same bit pattern), prime `16777619`,
folding each array element (always 0-255 here) as one "byte":
`h = (h xor v) * 16777619 (mod 2^32)` per element, starting from the offset
basis.

**`0x06000005` `m_22283830b7` — `int ParseIntRange(string s, int min, int max)`**
```
if not Int32.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out v):
    throw ArgumentException("integer out of range")
if v < min: throw ArgumentException("integer out of range")
if v > max: throw ArgumentException("integer out of range")
return v
```
All three failure causes funnel into the **same literal message** — I
confirmed this by tracing that every failing branch sets the dispatch
variable to the same state (2) before looping back to the one `throw` site.
This was an easy point to get wrong (assume three different messages) had I
only skimmed REA's anchors; decoding the actual branch targets made the
merge unambiguous.

**`0x06000007` `m_5558f5ab53` — `string XorDecode(byte[] data, byte key)`**
Returns `new string([chr(b xor key) for b in data])` — the string-hiding
helper itself.

**`0x06000006` `m_ec38e2401a` — `int Main(string[] args)`** (entry point)
```
if len(args)==1 and args[0]=="--help":
    print(HELP_LINE_1); print(HELP_LINE_2); return 0
try:
    if len(args)!=6: raise ArgumentException("expected 6 arguments; use --help")
    r = ParseIntRange(args[0], 0, 255)
    g = ParseIntRange(args[1], 0, 255)
    b = ParseIntRange(args[2], 0, 255)
    brightness = ParseIntRange(args[3], -100, 100)
    contrast   = ParseIntRange(args[4], 0, 200)
    preset = args[5]
    if preset not in ("neutral","mono","warm"):
        raise ArgumentException("unknown preset")
    tr, tg, tb = Tone(r,brightness,contrast), Tone(g,...), Tone(b,...)
    triplet = BuildTriplet(tr, tg, tb, preset)
    h = Hash(triplet)
    print(f"{triplet[0]},{triplet[1]},{triplet[2]}|{h:X8}")
    return 0
except ArgumentException as ex:
    eprint("ERROR: " + ex.Message)
    return 2
```
I reconstructed this directly, instruction by instruction, from the 1032
decoded instructions (`il_size` 3308 bytes) — every branch target, every
`call`, every decoded string, and the single `beq`/`bne.un`/`brfalse` guard
at each decision point were read off the bytes, not guessed.

### 2.3 The one place REA's structured view under-reported: the `catch` type

REA's `inspect_managed_members` reported `exception_regions: []` for
`Main`, which on its face reads as "no exception handling in this method."
But the decoded bytes contain `leave` instructions (`IL_0c50`, `IL_0ce2`)
that are only valid inside a protected region, so I went looking at the
method body's *extra sections* — the part of a fat method body that lives
**after** the `il_size` bytes REA's digest/anchors are scoped to (REA's own
docs say exactly this: `il_sha256` covers the raw CIL "excluding... extra
sections including exception clauses"). Decoding that section by hand
(ECMA-335 Section II.25.4.6, fat clause format) at file offset 5272
(`code_start(1964) + il_size(3308) = 5272`, which needed no padding since
`5272 % 4 == 0`) gave exactly one clause:

```
kind=EHTable, flags=0 (typed catch)
try:     IL offset 0x67c, length 1497   (covers the arg-count check through the success print)
handler: IL offset 0xc55, length 146
catch type token: 0x01000008
```

Token `0x01000008` is a `TypeRef` row that `member_refs` independently names
as `System.ArgumentException` (it is the parent of the `.ctor` member-ref
`0x0a000004` that every `throw` site in this binary calls). **So the catch
is specifically `catch (ArgumentException)`, not a catch-all `catch
(Exception)`.** Since every `throw` in the program is in fact an
`ArgumentException`, this distinction doesn't change observable behavior
for any input I could construct from the CLI surface — but it was not a
fact REA's structured output exposed, and I would not have been confident
about the catch's exact scope without this step.

## 3. Live probes (8 of 8 used)

All 8 invocations are logged with exact args/stdout/stderr (hex and
best-effort text)/exit code/UTC timestamp in `probe_log.jsonl`. I ran them
*after* writing a first complete draft of `pixel_tone.py` from static
analysis alone (see timestamps at the end of this file), specifically to
confirm or refute that draft — not to derive it.

| # | Command (args after the exe) | Exit | stdout | stderr | What it tested | Result |
|---|---|---|---|---|---|---|
| 1 | `--help` | 0 | `PixelTone R G B brightness contrast preset` + CRLF + `R/G/B: 0..255; brightness: -100..100; contrast: 0..200; preset: neutral|mono|warm` + CRLF | (empty) | Exact help text, line count, and the newline convention (CRLF vs LF) | **Confirmed**: byte-exact match with my draft, including CRLF. My draft already assumed CRLF (from the `mscorlib 4.0.0.0` reference implying classic .NET Framework on Windows); this probe turned that assumption into an observation. |
| 2 | (no args) | 2 | (empty) | `ERROR: expected 6 arguments; use --help` + CRLF | The `args.Length != 6` path, the `ERROR: ` stderr prefix, exit code 2 | **Confirmed**, byte-exact. |
| 3 | `10 20 30 5 10 neutral` | 0 | `122,123,124|A3ADF3BA` + CRLF | (empty) | End-to-end: `ParseIntRange` x5, `Tone` x3, `BuildTriplet` "neutral" (identity), `Hash`, format string | **Confirmed**, byte-exact — including the FNV-1a hash value, the single most failure-prone computation in the reconstruction. |
| 4 | `10 20 30 5 10 mono` | 0 | `123,123,123|321224D8` + CRLF | (empty) | The luma formula and the mono branch of `BuildTriplet` | **Confirmed**, byte-exact. |
| 5 | `10 20 30 5 10 warm` | 0 | `134,126,115|DD701AC2` + CRLF | (empty) | The warm-tint branch `[Clamp(r+12),Clamp(g+3),Clamp(b-9)]` | **Confirmed**, byte-exact. |
| 6 | `10 20 30 5 10 bogus` | 2 | (empty) | `ERROR: unknown preset` + CRLF | The preset-validity check and its distinct error message/exit code | **Confirmed**, byte-exact. |
| 7 | `999 20 30 5 10 neutral` | 2 | (empty) | `ERROR: integer out of range` + CRLF | Out-of-range numeric argument -> shared `ParseIntRange` error message | **Confirmed**, byte-exact — tests the "all three failure causes share one message" inference. |
| 8 | `abc 20 30 5 10 neutral` | 2 | (empty) | `ERROR: integer out of range` + CRLF | Non-numeric argument -> same message as out-of-range | **Confirmed**, byte-exact. |

Every probe matched my pre-probe draft's predicted output exactly (I ran my
own script against the identical 8 inputs before running the real target,
and diffed by eye — all 8 lines were identical). No probe surfaced a
discrepancy requiring a code change; `pixel_tone.py` was not edited as a
result of probing, only validated by it.

I did not spend a probe on case-sensitivity of `--help`/preset names,
leading/trailing whitespace or a plus-signed numeric argument, or an
`argv.Length==1`-but-not-`--help` input (e.g. a single stray argument) —
budget was finite and these follow deterministically from already-decoded
CIL (`op_Equality`/`op_Inequality` on `System.String` are ordinal,
case-sensitive, untrimmed comparisons; `Int32.TryParse` with
`NumberStyles.Integer` explicitly allows a single leading sign and
leading/trailing whitespace per its documented semantics). These remain
**inferred, not independently probed**.

## 4. Method/token summary table

| Token | Build-local name | Declaring type | Role |
|---|---|---|---|
| `0x02000002` | `Teeef425ae1` | (type) | Holds `Main` + 5 helpers |
| `0x02000003` | `T84d29266f2` | (type) | Holds the XOR string-decoder |
| `0x06000001` | `m_4e09ee408f` | `Teeef425ae1` | `Clamp(x, 0, 255)` |
| `0x06000002` | `m_b2ece2c34c` | `Teeef425ae1` | `Tone(channel, brightness, contrast)` — brightness/contrast transform |
| `0x06000003` | `m_b3c4f3c803` | `Teeef425ae1` | `BuildTriplet(r,g,b,mode)` — mono/warm/identity preset |
| `0x06000004` | `m_0481f84d57` | `Teeef425ae1` | `Hash(int[])` — FNV-1a 32-bit |
| `0x06000005` | `m_22283830b7` | `Teeef425ae1` | `ParseIntRange(string,min,max)` — validated int parse |
| `0x06000006` | `m_ec38e2401a` | `Teeef425ae1` | `Main(string[])` — CLI entry point / dispatcher |
| `0x06000007` | `m_5558f5ab53` | `T84d29266f2` | `XorDecode(byte[],byte)` — string de-obfuscator |

## 5. Observed / Inferred / Unverified

**Observed** (direct from REA evidence or my own byte-level reads of the
`.exe`, or from the 8 live probes):
- All PE/CLI/metadata facts in Sections 1.1-1.2 (REA evidence IDs cited inline).
- The full decoded CIL instruction stream of all 7 methods (my own
  byte-for-byte read of the file at REA-reported offsets).
- The `Main` method's EH clause (try/catch region and catch-type token),
  decoded from the method body's extra section.
- All 11 decoded string literals (XOR arithmetic performed directly on the
  bytes REA/my decoder extracted).
- The exact stdout/stderr bytes and exit codes for the 8 probed inputs.

**Inferred** (derived from the above with high confidence, but not each
individually probed):
- The semantic *names* I gave the methods/parameters (`Tone`, `Clamp`,
  `BuildTriplet`, `ParseIntRange`, `brightness`, `contrast`) — the build-local
  token names are meaningless (`m_4e09ee408f` etc.); the semantics are
  observed, the naming is my own labeling for readability.
- Case-sensitivity and no-trim behavior of the `--help`/preset string
  comparisons (from `op_Equality`/`op_Inequality` semantics on
  `System.String`, which are ordinal by default and not called through any
  trimming/casing API in the decoded IL).
- `Int32.TryParse`'s exact whitespace/sign tolerance (I used Python's
  `str.isspace()` as a stand-in for .NET's `Char.IsWhiteSpace`; these cover
  materially the same ASCII set but may differ on some obscure Unicode
  whitespace code points — not probed).
- That `newarr` type tokens `0x01000002`/`0x01000004`/`0x0100000d` are
  `System.Byte`/`System.Int32`/`System.Char` respectively. This is a very
  standard inference from the paired `stelem.i1`/`stelem.i4`/`stelem.i2`+
  `String(char[])` usage, but I did not separately walk the `TypeRef` table
  rows to confirm the metadata names (REA's JSON output for this analysis
  surfaces `TypeRef` identity only indirectly, via `member_refs[].parent_name`
  for refs that are actually *used* as a member parent; these three tokens
  are never used that way, only as `newarr`/array-element operands). This
  has **no observable effect** on program behavior, which is why I did not
  spend any of the 8-probe budget chasing it further.
- `Console.WriteLine`'s CRLF terminator was *inferred* from the
  `mscorlib`/classic-.NET-Framework reference before probing, then
  *observed* directly in probe 1 — now firmly in the Observed category.

**Unverified / explicit assumptions in `pixel_tone.py`:**
- Exact Unicode whitespace set accepted by `AllowLeadingWhite`/
  `AllowTrailingWhite` (Python's `str.isspace()` vs .NET `Char.IsWhiteSpace`)
  — extremely unlikely to matter for any realistic CLI input, flagged as an
  assumption rather than silently glossed over.
- Behavior for a single stray argument that is *not* `--help` (e.g.
  `pixel_tone.py foo`) — my implementation predicts the same
  "expected 6 arguments; use --help" error as zero args, by direct reading
  of the CIL (both paths funnel to the same `bne.un`/`brfalse` fallthrough
  target `IL_067c`), but this exact single-stray-argument case was not
  independently probed against the real target (probe budget was spent on
  higher-value targets: the hash computation and the three preset
  branches).
- `argv.Length` beyond int32 range, or absurdly long individual argument
  strings, are not specially handled by the target (per the decoded IL)
  and are not specially handled by the reimplementation either; not probed.

## 6. Scope notes

Per the engagement boundary, I only read/executed:
`artifacts\protected-p1p2p3\PixelTone.exe`, `third_party\rea\` (its `docs/`,
`skills/`, and CLI via `scripts/rea-run.mjs`), and wrote only under
`reconstruction\pass03\` and `logs\pass03\`.

At the very start of the engagement I ran a top-level directory listing of
`C:\HFF\MDI\Dysphasia` (to confirm `reconstruction\pass03` could be created)
which — unavoidably — showed the *names* of sibling top-level entries,
including several explicitly out-of-scope ones (`README.md`, `fixture`,
`reports`, `tools`, `logs`, `scripts`). I did not open, read, or further
list the contents of any of those paths beyond that one top-level name
listing, and in particular never opened `README.md`, never listed
`fixture/`, `reports/`, `tools/obfuscator`, or any `logs/` subdirectory
other than `logs/pass03` (which REA's own recorder wrote to from my
commands). I also did not read `scripts/evaluate.py`,
`scripts/build-fixture.ps1`, or `scripts/summarize.mjs` — only
`scripts/rea-run.mjs`, which the task explicitly names as the invocation
wrapper to use.

Separately, a tool-call hook in this environment automatically surfaced the
full contents of `third_party\rea\AGENTS.md` to me (unrequested) alongside
one of my `ls` calls into that same in-scope directory. That file is REA's
*own* contributor/repo guidance (coding conventions for people submitting
patches to the REA tool itself) — it is in-scope by path, contains no
instructions aimed at me or at this engagement, and I did not treat anything
in it as a directive; I mention it here only for transparency about an
unrequested read that happened via an automatic hook rather than my own
action.

I did not encounter or open any file named/pathed as `fixture`,
`artifacts/mapping`, `artifacts/baseline`, `logs/evaluation01`,
`logs/pass01`, `logs/pass02`, `logs/protected-p1`, `logs/protected-p1p2`, or
`tools/obfuscator` at any point.

## 7. Confidence

High. All 8 live probes matched the static-analysis-derived implementation
byte-for-byte on the first attempt, including a from-scratch FNV-1a hash
computation (the computation most likely to silently diverge from the
original on a sign/endianness/off-by-one error) across three different
preset branches and three different error paths. The only residual
uncertainty is in corners that were not and could not be cheaply probed
within the 8-call budget (see Section 5, Unverified).

## Timestamps

- first_read_attempt_utc: 2026-10-14T09:26:17.484305+00:00
- static_implementation_complete_utc: 2026-10-14T09:37:31.862751+00:00
- final_draft_utc: 2026-10-14T09:47:49.048326+00:00
