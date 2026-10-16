# PixelTone.exe -- static + light dynamic reverse-engineering report

Target: `C:\HFF\MDI\Dysphasia\artifacts\protected-p1p2p3\PixelTone.exe`
SHA-256: `b9029acfbf9920db60a56b8e0622de20d41614e4e8641a2bd0738bb370a72a1c`
Size: 6144 bytes. PE32+, x86_64, CLI (managed, "il-only"), runtime 2.5, no strong name,
references `mscorlib 4.0.0.0` only. MVID `7cf7801a-1342-367a-2a70-668ba128cada`.

This report documents an independent black-box reimplementation built from:
(1) REA's static managed-code inspection, (2) a supplementary CIL decoder I wrote
against the raw PE bytes (explicitly permitted by the engagement brief), and
(3) 8 budgeted live executions of the real binary used to test, not to shape,
the reconstruction -- the Python script (`pixel_tone.py`) was fully written
*before* any live probe was run.

## 1. REA static evidence

### 1.1 `inspect-managed-artifact` (evidence `ev_2125304e0a7ad2582579d4e45d8921d2e3ee9ac4c677be6118f7e100b6b74d52`)

Command: `rea inspect-managed-artifact PixelTone.exe --json`
(log: `logs/pass05/01-artifact.stdout.json`)

Key observed facts:
- PE classification: `managed`, container `pe`, implementation `cil`, managed architecture `x86_64`.
- CLI header at file offset 512, size 72, runtime version 2.5, flags `il-only`,
  **entry point metadata token `0x06000006`**.
- Metadata: `v4.0.30319`, streams `#Blob, #GUID, #Strings, #~` -- **no `#US` stream**
  (no user-string heap at all).
- Table row counts: `Module=1, TypeRef=19, TypeDef=4, Field=2, MethodDef=8, Param=16,
  MemberRef=15, CustomAttribute=2, ClassLayout=1, StandAloneSig=6, FieldRVA=1,
  Assembly=1, AssemblyRef=1, NestedClass=1`.
- Assembly `PixelTone 0.0.0.0`, no public key, references `mscorlib 4.0.0.0`
  (public key token `b77a5c561934e089`) only.
- Two `CustomAttribute` rows: `CompilationRelaxationsAttribute`,
  `RuntimeCompatibilityAttribute` -- standard compiler-emitted attributes, nothing
  diagnostic.

**Observation, not inference:** the absence of a `#US` heap means the assembly
cannot contain a single `ldstr` instruction anywhere -- confirmed independently
below in Section 1.2 and by exhaustive CIL decoding in Section 2.

### 1.2 `inspect-managed-members` (evidence `ev_b0a6513baf3626cbd544974d441c01d2dd837a7c63b5895f9474b596624e5210`)

Command: `rea inspect-managed-members PixelTone.exe --json`
(log: `logs/pass05/02-members.stdout.json`)

**Types** (4 TypeDefs):

| Token | Name | Notes |
|---|---|---|
| `0x02000001` | `<Module>` | required pseudo-type |
| `0x02000002` | `Teeef425ae1` | holds 6 methods incl. entry point; "main class" |
| `0x02000003` | `T84d29266f2` | holds 2 fields + `.cctor` + 1 method; string/data helper class |
| `0x02000004` | `Tf9ec26c126` | `ClassLayout` row present, extends `0x01000011` (System.ValueType) -- the compiler-generated fixed-size struct used to back a `new byte[]{...}` RVA literal |

All type/method/field names are hex-suffixed placeholders (`Teeef425ae1`,
`m_4e09ee408f`, `f_2898b321ff`, ...) -- consistent with the `protected-p1p2p3`
directory name implying one or more identifier-renaming/obfuscation passes were
applied to an originally human-named program.

**Fields:**

| Token | Name | Type | Notes |
|---|---|---|---|
| `0x04000001` | `f_2898b321ff` | `valuetype:16` (`Tf9ec26c126`) | static, has the sole `FieldRVA` row -- backs a literal byte blob |
| `0x04000002` | `f_134b552a1f` | `u1[]` | static, `byte[]`; materialized from the RVA blob once in `.cctor` |

**Methods** (8 MethodDefs; declaring type -> name -> signature -> REA `opcode_counts`):

| Token | Declaring type | Name | Signature | opcode highlights |
|---|---|---|---|---|
| `0x06000001` | `Teeef425ae1` | `m_4e09ee408f` | `int(int)` | `switch`, `blt`, `bgt` |
| `0x06000002` | `Teeef425ae1` | `m_b2ece2c34c` | `int(int,int,int)` | `sub,mul,div,add,add,call` |
| `0x06000003` | `Teeef425ae1` | `m_b3c4f3c803` | `int[](int,int,int,string)` | `switch`, `newarr`x3, `stelem.i4`x9, `call` to `0x06000008`/`0x0a000001` |
| `0x06000004` | `Teeef425ae1` | `m_0481f84d57` | `uint(int[])` | `switch`, `xor,mul,ldlen,blt` |
| `0x06000005` | `Teeef425ae1` | `m_22283830b7` | `int(string,int,int)` | `switch`, calls `0x0a000002/0x0a000003`, `newobj 0x0a000004`, `throw` |
| `0x06000006` | `Teeef425ae1` | `m_ec38e2401a` | `int(string[])` | **entry point**; `bne.un`, `beq`, exception region, `leave`x2 |
| `0x06000007` | `T84d29266f2` | `.cctor` | `void()` | `newarr, ldtoken, call RuntimeHelpers.InitializeArray, stsfld` |
| `0x06000008` | `T84d29266f2` | `m_5558f5ab53` | `string(int,int,byte)` | `newarr(char[]), xor, conv.u2, stelem.i2, newobj String(char[])` |

**`call_edges`** confirmed the intra-assembly call graph exactly as decoded
in Section 2 (Main calls the five `Teeef425ae1` helpers and `m_5558f5ab53`
repeatedly; `m_b3c4f3c803` and `m_22283830b7` also call `m_5558f5ab53`).

**`field_accesses`**: only `0x06000007` (`stsfld f_134b552a1f`) and `0x06000008`
(`ldsfld f_134b552a1f`) touch the byte-array field -- i.e. the array is built
once at module load and only ever read by the string-decode helper.

**`user_strings`**: `{"state":"complete","literals":[]}` -- REA confirms, by
direct heap inspection, that **zero `ldstr` literals exist anywhere** in the
assembly. Combined with method `0x06000008`'s signature (`string(int,int,byte)`,
no string/char operands) not matching any plausible `ldstr`-based helper, this
is exactly the case the engagement brief flagged: "consider that literal
values might be reconstructed at runtime rather than loaded directly as string
constants." This hypothesis is confirmed in Section 2.3.

`member_refs` identified all external (`mscorlib`) call targets by name:
`String.op_Equality/op_Inequality/Concat/.ctor(char[])`,
`CultureInfo.get_InvariantCulture`, `Int32.TryParse`, `ArgumentException.ctor(string)`,
`Console.WriteLine(string)` / `WriteLine(string,object[])` / `get_Error`,
`Exception.get_Message`, `TextWriter.WriteLine(string)`,
`RuntimeHelpers.InitializeArray`.

The one `exception_regions` entry (on method `0x06000006`) has
`class_token = 0x01000007`, which `member_refs[].parent_token` resolves to
**`System.ArgumentException`** -- i.e. Main's try block catches
`ArgumentException` specifically, not a bare `Exception` (the local variable
inside the handler is later used via `Exception.get_Message`, which is valid
because `ArgumentException` derives from `Exception`).

REA's curated *anchors* (branches/constants/calls only, not every opcode) were
sufficient to see the overall shape of each method (switch-based flattened
control flow in every "real" method, a tell of flattening-style obfuscation),
but were not sufficient to safely reconstruct exact arithmetic ordering,
exact loop bounds, or the exact byte offsets needed to decode the string blob.
That is why I did the full CIL decode below.

## 2. Supplementary CIL decoding

### 2.1 Decoder

I wrote a small standalone ECMA-335 CIL decoder (scratch file, not a
deliverable) covering the full standard 1-byte and `0xFE`-prefixed 2-byte
opcode tables, and ran it directly against the raw PE bytes at each method's
reported `file_offset`.

**Correction discovered empirically:** REA's `file_offset` points to the
*start of the tiny/fat method header*, not to the first CIL byte (the
engagement brief's phrasing was ambiguous on this point). I confirmed this by
reading the raw bytes at `file_offset` for two methods and finding they
exactly reproduce REA's own reported header fields:
- Method `0x06000001` (fat, `file_offset=592`): bytes `03 30 02 00 91 00 00 00 01 00 00 11`
  decode as Flags/Size-nibble=`0x3003` (FatFormat, no InitLocals -- REA said
  `init_locals:false`), MaxStack=2 (REA: `max_stack:2`), CodeSize=`0x91`=145
  (REA: `il_size:145`), LocalVarSigTok=`0x11000001` (REA: matches exactly).
- Method `0x06000002` (tiny, `file_offset=749`): byte `0x9A` = `(38<<2)|2`,
  exactly the tiny-header encoding for `il_size=38` (REA: matches).

So CIL actually starts at `file_offset + 1` (tiny) or `file_offset + 12`
(fat, standard 3-DWORD header). After this correction, the decoder's
per-method instruction count matched REA's reported `instruction_count`
exactly for all 8 methods (e.g. Main: 172/172, including its one exception
region), which I treat as strong internal corroboration that both the header
convention and the opcode table are correct.

### 2.2 Full decoded control flow

All 8 methods use the same obfuscation idiom: an integer "state" local
initialized to some starting case, a `switch` over it, and each case block
ending by setting the next state and jumping back to the switch (classic
control-flow-flattening). After manually tracing every case for every method
against the decoded instruction stream (not just REA's anchors), the semantics
reduce to ordinary code:

- **`m_4e09ee408f(int v) -> int`**: `Clamp(v, 0, 255)` -- returns 0 if `v<0`,
  255 if `v>255`, else `v`.
- **`m_b2ece2c34c(int value, int brightness, int contrast) -> int`**:
  `return Clamp( (value-128)*contrast/100 + 128 + brightness )`. The CIL `div`
  is **signed division truncated toward zero** (ECMA-335 III.3.17), which
  differs from Python's floor-dividing `//` whenever the dividend is negative
  and not an exact multiple -- verified empirically in probe 3 (Section 3).
- **`m_b3c4f3c803(int r, int g, int b, string mode) -> int[3]`**: if
  `mode == decode(0,4,38)` ("mono"), returns a 3-element array of
  `(77*r+150*g+29*b+128)>>8` (standard integer luma/grayscale weighting,
  repeated 3x); if `mode == decode(4,4,99)` ("warm"), returns
  `[Clamp(r+12), Clamp(g+3), Clamp(b-9)]`; otherwise (the only other value
  Main allows through is "neutral") returns `[r,g,b]` unchanged.
- **`m_0481f84d57(int[] arr) -> uint`**: standard 32-bit **FNV-1a** hash:
  `h = 2166136261; for v in arr: h = ((h ^ v) * 16777619) mod 2^32; return h`.
  The literal `-2128831035` is exactly `(int)0x811C9DC5`, the canonical FNV-1a
  32-bit offset basis, and `16777619` is the canonical FNV-1a 32-bit prime.
- **`m_22283830b7(string s, int min, int max) -> int`**: calls
  `Int32.TryParse(s, NumberStyles=7, CultureInfo.InvariantCulture, out v)`
  (the literal operand `7` is exactly `NumberStyles.Integer` =
  `AllowLeadingWhite|AllowTrailingWhite|AllowLeadingSign`); if parsing fails,
  **or** `v<min`, **or** `v>max`, throws
  `new ArgumentException(decode(8,20,8))`; otherwise returns `v`. Note: parse
  failure and out-of-range share the *same* exception message -- the binary
  does not distinguish them.
- **`m_ec38e2401a(string[] args) -> int`** (Main / entry point):
  - If `args.Length==1` and `args[0]==decode(28,6,71)`: print two decoded
    lines and return 0.
  - Otherwise (including the `Length==1`-but-not-matching case, which falls
    through to the same merge point as any other length), enters a
    try-block guarded by `catch(ArgumentException)`:
    - if `args.Length!=6`: throw `ArgumentException(decode(157,32,21))`.
    - parse `r,g,b` via `ParseIntInRange(args[i],0,255)`, `brightness` via
      `ParseIntInRange(args[3],-100,100)`, `contrast` via
      `ParseIntInRange(args[4],0,200)`; `mode = args[5]`.
    - if `mode` is not `decode(189,7,151)` and not `decode(0,4,38)` and not
      `decode(4,4,99)`: throw `ArgumentException(decode(196,14,123))`.
    - `adjR/adjG/adjB = AdjustChannel(r|g|b, brightness, contrast)` (calls
      `m_b2ece2c34c` three times).
    - `result = m_b3c4f3c803(adjR,adjG,adjB,mode)`; `hash = m_0481f84d57(result)`.
    - `Console.WriteLine("{0},{1},{2}|{3:X8}", box(result[0]), box(result[1]),
      box(result[2]), box(hash))`; return 0.
    - catch block: `Console.Error.WriteLine(decode(228,7,62) + e.Message)`;
      return 2.

### 2.3 Locating and decoding the embedded string blob

Method `0x06000008` (`T84d29266f2.m_5558f5ab53(int start, int length, byte key)
-> string`) decodes to exactly:

```
char[] out = new char[length];
for (int i = 0; i < length; i++)
    out[i] = (char)(data[start + i] ^ key);   // data = static byte[] f_134b552a1f
return new string(out);
```

i.e. a one-byte-per-UTF-16-code-unit XOR cipher over a static byte array. The
array (`f_134b552a1f`) is populated exactly once, in `.cctor`, from field
`f_2898b321ff` via `RuntimeHelpers.InitializeArray` -- the standard C#-compiler
pattern for `new byte[235]{...}` literals, where the literal bytes live in the
PE file at the field's `FieldRVA`.

I located that blob by manually reconstructing the `#~` metadata table layout
from REA's reported row counts and ECMA-335 II.22 row-size formulas (Module
10B, TypeRef 6B x19, TypeDef 14B x4, Field 6B x2, MethodDef 14B x8, Param 6B x16,
MemberRef 6B x15, CustomAttribute 6B x2, ClassLayout 8B, StandAloneSig 2B x6,
FieldRVA 6B x1, ...), assuming 2-byte heap/table-index widths (justified by the
file's tiny size). **Every computed row offset exactly matched REA's own
reported `row_offset` for every TypeDef/Field/MethodDef/MemberRef/attribute
row** (e.g. TypeDef table computed to start at file offset 3040, which is
exactly REA's reported `row_offset` for `<Module>`) -- strong corroboration the
layout reconstruction is correct. This placed the single `FieldRVA` row at
file offset 3438: `RVA=0x27c8, Field index=1`. Converting that RVA through the
PE section table (`.text`: VirtualAddress `0x2000` -> RawPtr `0x200`) gives file
offset 2504, where the 235-byte blob lives.

Decoding all 11 distinct `(start,length,key)` triplets observed at call sites
against that blob with the XOR formula above produced exclusively clean,
printable ASCII text -- strong evidence both the blob location and the decode
algorithm are correct (garbage bytes at any wrong offset/key would show up as
non-printable characters):

| Call site(s) | `(start,len,key)` | Decoded text |
|---|---|---|
| Main, help check | `(28,6,71)` | `--help` |
| Main, help line 1 | `(34,42,95)` | `PixelTone R G B brightness contrast preset` |
| Main, help line 2 | `(76,81,238)` | `R/G/B: 0..255; brightness: -100..100; contrast: 0..200; preset: neutral\|mono\|warm` |
| Main, arg-count error | `(157,32,21)` | `expected 6 arguments; use --help` |
| Main, preset check | `(189,7,151)` | `neutral` |
| Main + `m_b3c4f3c803` | `(0,4,38)` | `mono` |
| Main + `m_b3c4f3c803` | `(4,4,99)` | `warm` |
| Main, unknown-preset error | `(196,14,123)` | `unknown preset` |
| Main, output format | `(210,18,116)` | `{0},{1},{2}\|{3:X8}` |
| Main, stderr prefix | `(228,7,62)` | `ERROR: ` |
| `m_22283830b7`, range error | `(8,20,8)` | `integer out of range` |

`pixel_tone.py` inlines these decoded strings directly rather than
re-implementing the XOR scheme, since only observable behavior needs to match
and the plaintext is simpler to maintain/verify.

## 3. Live probes (8/8 budget used)

All 8 were decided *after* the static reconstruction was complete, specifically
to stress-test points where static analysis alone left residual uncertainty
(signed-division rounding direction, clamp boundaries, the exact message for
different failure classes, and one non-obvious control-flow fallthrough).
Full command/stdout/stderr/exit-code/timestamp detail is in
`probe_log.jsonl`; summary:

| # | Command (args after .exe) | Exit | Result | What it confirmed/refuted |
|---|---|---|---|---|
| 1 | `--help` | 0 | two decoded help lines, CRLF endings | Help text and CRLF line endings exactly as predicted; refuted nothing. |
| 2 | *(no args)* | 2 | `ERROR: expected 6 arguments; use --help` | Zero-arg path reaches the generic wrong-count error, not a separate "no args" message. |
| 3 | `50 50 50 0 37 neutral` | 0 | `100,100,100\|E55BEF83` | **Confirmed truncate-toward-zero division**: `(50-128)*37/100` truncates to `-28` -> adjusted `100`; floor division would have given `-29` -> `99`. Independently recomputed the FNV-1a32 hash of `[100,100,100]` in Python = `E55BEF83`, matching, confirming the hash algorithm exactly. |
| 4 | `0 0 0 0 100 mono` | 0 | `0,0,0\|4AB0F7B7` | Confirmed the mono/luma formula and the `-128+128=0` clamp boundary; hash independently re-verified. |
| 5 | `255 255 255 0 100 warm` | 0 | `255,255,246\|886279CF` | Confirmed warm-preset offsets and the upper clamp (`255+12`, `255+3` clamp back to 255; `255-9=246` does not clamp); hash re-verified. |
| 6 | `256 0 0 0 100 neutral` | 2 | `ERROR: integer out of range` | Confirmed the out-of-range path/message for a numeric argument. |
| 7 | `0 0 0 0 0 banana` | 2 | `ERROR: unknown preset` | Confirmed the preset-validation path/message. |
| 8 | `foo` | 2 | `ERROR: expected 6 arguments; use --help` | Confirmed the inferred fallthrough: a single non-`--help` argument is *not* a distinct error case -- it merges into the generic "wrong argument count" path (same message as probe 2), exactly as the decoded CIL predicted. |

No probe contradicted the static reconstruction. Running `pixel_tone.py`
against all 8 probe argument sets and diffing raw stdout/stderr bytes against
the captured real-`.exe` output found **one real bug**: the first draft
literally copied C#'s composite-format spec `"{3:X8}"` into a Python
`str.format()` call, which raises `ValueError` because Python's mini-language
needs the width before the type character (`"{3:08X}"`), not after. This was
a genuine static-only blind spot (REA/CIL only told me *that* `"{0},{1},{2}|{3:X8}"`
was the literal format string, not that its syntax would need translation to
run in Python) and was caught by the dynamic comparison, not by re-reading the
CIL. Fixed in `pixel_tone.py`; after the fix, all 8 probes match byte-for-byte
(stdout, stderr, and exit code) between the real `.exe` and the Python
reimplementation.

## 4. Method/token to behavior map

| Token | Name | Behavior |
|---|---|---|
| `0x06000006` | `Teeef425ae1.m_ec38e2401a` | **Main/entry point.** Argument parsing, validation, dispatch, error handling, exit code selection. |
| `0x06000001` | `Teeef425ae1.m_4e09ee408f` | `Clamp(v, 0, 255)`. |
| `0x06000002` | `Teeef425ae1.m_b2ece2c34c` | `AdjustChannel(value, brightness, contrast)` = brightness/contrast transform + clamp. |
| `0x06000003` | `Teeef425ae1.m_b3c4f3c803` | `ApplyPreset(r,g,b,mode)`: mono (luma grayscale) / warm (fixed per-channel offset) / neutral (identity). |
| `0x06000004` | `Teeef425ae1.m_0481f84d57` | `Fnv1a32(int[])` checksum of the final RGB triplet. |
| `0x06000005` | `Teeef425ae1.m_22283830b7` | `ParseIntInRange(s, min, max)`: culture-invariant integer parse + range check, throws on any failure. |
| `0x06000007` | `T84d29266f2..cctor` | One-time materialization of the embedded byte blob into the static `byte[]` field. |
| `0x06000008` | `T84d29266f2.m_5558f5ab53` | `DecodeString(start, length, key)`: XOR-decode a run of the embedded blob into a `string`. |
| `0x04000001` | `T84d29266f2.f_2898b321ff` | RVA-backed static field holding the raw 235-byte literal blob. |
| `0x04000002` | `T84d29266f2.f_134b552a1f` | Materialized `byte[]` copy of the blob, read by the decode helper. |
| `0x02000004` | `Tf9ec26c126` | Compiler-generated fixed-size struct (`ClassLayout`) backing the RVA blob; never referenced except as `f_2898b321ff`'s type. |

## 5. Observed vs. inferred vs. unverified

**Observed** (direct, high-confidence facts from REA and/or raw-byte decoding):
PE/CLI structure, all metadata table row counts and offsets, all 8 method
signatures and exact decoded CIL instruction streams, the exception region
and its catch type, the FieldRVA blob's exact bytes, all 11 decoded string
literals, and (via the 8 live probes) exact stdout/stderr bytes and exit codes
for 8 concrete argument vectors.

**Inferred** (derived by reasoning over observed facts, not independently
verified bit-for-bit against the binary beyond what the probes covered):
- The semantic *names* I gave things (`Clamp`, `AdjustChannel`, `ApplyPreset`,
  `ParseIntInRange`, "brightness/contrast", "luma/grayscale") are
  interpretive labels for CIL arithmetic that has no surviving identifier
  names; the arithmetic itself is decoded fact, the labels are my inference
  of intent.
- `Int32.TryParse`'s exact whitespace/sign grammar: I inferred the standard
  .NET `NumberStyles.Integer` + `InvariantCulture` semantics from the literal
  operand `7` and the `member_ref` signature, and reimplemented it with a
  Python regex (`^\s*([+-]?[0-9]+)\s*$`) plus an Int32-range check. This was
  not independently probed against exotic inputs (e.g. non-ASCII digits,
  `+`/`-` combined with internal whitespace, thousands separators, a bare
  sign with no digits, leading zeros, Unicode whitespace beyond ASCII). I
  believe it is correct for ordinary decimal integer arguments (which is all
  8 probes used) but flag it as the least-verified piece of logic.
- `Console.WriteLine`'s exact byte-level encoding on arbitrary consoles/
  redirected streams for non-ASCII input is irrelevant here because every
  string the program ever emits is pure ASCII (verified by decoding all 11
  literals), so no encoding edge case can actually be exercised through this
  program's own output.
- The `string[] args` to `object[] args` boxing order for `String.Format`
  (`box(int)`, `box(int)`, `box(int)`, `box(uint)` in that exact order) is
  read directly from the decoded CIL (`box` opcodes in sequence before
  `stelem.ref`), not inferred.

**Unverified / explicit assumptions** (no static or dynamic evidence either
way, so I made an explicit implementation choice):
- Exact Unicode-whitespace equivalence between .NET's `char.IsWhiteSpace` and
  Python's regex `\s` for `Int32.TryParse`'s leading/trailing-whitespace
  allowance -- assumed close enough; untested for exotic whitespace code
  points.
- Behavior for an Int32-overflowing numeric argument (e.g. `99999999999`):
  my implementation treats this as a parse failure (mirroring .NET's
  `TryParse` returning `false` on overflow) rather than a separate error path;
  not independently probed (would have required a 9th probe beyond budget),
  but follows directly from `Int32.TryParse`'s documented contract, which the
  decoded CIL explicitly calls.
- Argument encoding/locale edge cases for non-ASCII command-line arguments
  (e.g. a mode string containing non-ASCII characters) -- the program's own
  string comparisons are ordinal (`String.op_Equality`/`op_Inequality`, not
  culture-aware), so Python's default string `==`/`!=` should match exactly,
  but this was not independently probed.

## 6. Scope-boundary notes

Two directory listings incidentally showed the names of out-of-scope entries,
which were not opened or read, per the engagement's procedural scope
boundary:
- Listing `C:\HFF\MDI\Dysphasia` (to confirm `reconstruction\pass05` was
  created) showed `README.md`, `fixture\`, `reports\`, `tools\`,
  `PixelTone.obj`, `PixelTone.protected.obj`, `PixelTone.protected2.obj`, and
  sibling `logs\`/`reconstruction\` entries other than `pass05`.
- Listing `C:\HFF\MDI\Dysphasia\scripts` (to find `rea-run.mjs`) showed
  `build-fixture.ps1`, `build-native-fixture*.bat`, `evaluate*.py`,
  `ida-start-mcp.py`, and `rea-ida-mcp-config.json`.

Neither listing's out-of-scope entries were opened, read, or used in any way
in this reconstruction; both were immediately backed away from once the
in-scope target (the `pass05` directory / `rea-run.mjs`) was located.

A tool-call hook also auto-injected the full contents of
`third_party\rea\AGENTS.md` (REA's own contributor/development guidelines)
when I first read a file under `third_party\rea`. That file is in-scope
(under `third_party\rea\`) and was not something I had to back away from, but
its content is REA's own build/contribution process documentation, not
instructions for this engagement, so it was treated as background data and
not acted on.

## 7. Timestamps

- `first_read_attempt_utc`: 2026-10-14T11:14:30.342752+00:00
- `static_implementation_complete_utc`: 2026-10-14T11:26:05.351632+00:00
- `final_draft_utc`: 2026-10-14T11:36:45.150725+00:00
