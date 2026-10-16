# PixelTone.exe — Reverse-Engineering Findings (pass04)

**Target:** `artifacts\protected-p1p2p3\PixelTone.exe`
SHA-256 `b9029acfbf9920db60a56b8e0622de20d41614e4e8641a2bd0738bb370a72a1c`, 6144 bytes,
PE32+/x86_64, CLI (managed .NET) IL-only, runtime v4.0.30319, MVID
`7cf7801a-1342-367a-2a70-668ba128cada`.

No source code for this target was seen or assumed at any point. Everything
below is derived from (a) REA's static managed-analysis commands, (b) a small
supplementary PE/ECMA-335 parser and CIL decoder written for this engagement
(reading only the bytes of the target file — never executing it), and (c) 8
live executions of the target.

---

## 1. What REA's static output showed

### 1.1 `inspect-managed-artifact` (`node scripts/rea-run.mjs pass04 01-artifact ...`)

Evidence ID `ev_2125304e0a7ad2582579d4e45d8921d2e3ee9ac4c677be6118f7e100b6b74d52`.

- PE: x86_64, PE32+, 2 sections, CLI header at file offset 512, IL-only flag
  set, entry point token `0x06000006`, metadata RVA `0x28b4`/size 1696.
- Metadata table row counts: `Module:1, TypeRef:19, TypeDef:4, Field:2,
  MethodDef:8, Param:16, MemberRef:15, CustomAttribute:2, ClassLayout:1,
  StandAloneSig:6, FieldRVA:1, Assembly:1, AssemblyRef:1, NestedClass:1`.
- Assembly name `PixelTone`, version `0.0.0.0`, unsigned (no public key).
  Single reference: `mscorlib, Version=4.0.0.0`.
- **The presence of exactly one `FieldRVA` row and one `ClassLayout` row on
  only 4 TypeDefs is the first strong signal** that this binary stores
  initialized data (not `ldstr` literals) via a field-RVA-backed byte array,
  per the task's hint about auxiliary data in metadata fields.

### 1.2 `inspect-managed-members` (`02-members`)

Evidence ID `ev_b0a6513baf3626cbd544974d441c01d2dd837a7c63b5895f9474b596624e5210`.

- 4 types: `<Module>`, `Teeef425ae1` (6 methods — the "Program"/entry-point
  type), `T84d29266f2` (2 fields + 2 methods — a static helper type), and
  `Tf9ec26c126` (0 fields/methods, `NestedPrivate` visibility, extends
  TypeRef `0x01000011`). All type/method/field names are hashed/obfuscated
  identifiers — there is no readable naming left anywhere in metadata.
- `T84d29266f2` has two fields: `f_2898b321ff` (`valuetype:16`, later shown
  to be `Tf9ec26c126`, the compiler-style "private implementation details"
  struct sized by `ClassLayout`) and `f_134b552a1f` (`u1[]`, i.e. `byte[]`,
  static). Its `.cctor` (`0x06000007`) and one more method, `m_5558f5ab53`
  (`0x06000008`), are the only members.
- **`normalized_result.user_strings` was `{"state":"complete","literals":[]}`
  — zero `ldstr` string literals anywhere in the assembly.** This directly
  matches the task's hint: "if you see a method signature that doesn't match
  any `ldstr` pattern you'd expect, consider that literal values might be
  reconstructed at runtime." Every human-readable string in this program had
  to be reconstructed from the embedded byte blob.
- `call_edges` / `field_accesses` gave the call graph and the two `cctor`->
  `f_134b552a1f` / `m_5558f5ab53`->`f_134b552a1f` field accesses, matching
  the "decode table" hypothesis.
- `member_refs` named the external BCL surface used: `String.op_Equality`,
  `String.op_Inequality`, `String.Concat`, `String.ctor(char[])`,
  `CultureInfo.get_InvariantCulture`, `Int32.TryParse(string, NumberStyles,
  IFormatProvider, out int)`, `Console.WriteLine(string)`,
  `Console.WriteLine(string, object[])`, `Console.get_Error`,
  `TextWriter.WriteLine(string)`, `Exception.get_Message`,
  `ArgumentException.ctor(string)`, `RuntimeHelpers.InitializeArray`.
- Anchors (REA's curated opcode/operand subset) showed every method body
  opens with a `ldc.i4 N; stloc; nop; ldloc; switch` pattern — i.e.
  control-flow-flattening obfuscation, consistent with the directory name
  `protected-p1p2p3` suggesting multiple protection passes applied. Anchors
  are explicitly a curated subset (REA's own docs: "selected opcodes/
  operands... not the full instruction stream"), so I did not trust them for
  exact semantics and instead fully decoded every method body myself (§2).

### 1.3 `inspect-managed-native-boundaries` (`03-native`)

Evidence ID `ev_467d3ad9d9dbb7b0f9cb9b1047bbf1c4f0014c7e8917c6f1a82729e09ba4a026`.

Confirms: IL-only, no P/Invoke imports, no ModuleRefs, no native entry point,
not ReadyToRun/NativeAOT. This rules out any native-code or P/Invoke
component to the obfuscation — everything observable is pure CIL plus
embedded data, which the live probes later confirmed is sufficient to fully
explain the program's behavior.

---

## 2. Supplementary static analysis (own CIL decoding)

REA's anchors are a curated subset of each method's instructions, not the
full stream, and its JSON explicitly reports only `file_offset` and `il_size`
per method body (plus `header_format`). To get exact, in-order semantics
(critical here because of the control-flow flattening) I wrote three small
scripts in `reconstruction/pass04/`:

- **`pe_probe.py`** — parses the target's DOS/PE/COFF headers, the CLI
  header, the metadata root, and the `#~` tables stream completely by hand
  (table row counts -> heap-index sizes -> per-table row sizes -> row
  offsets), purely to cross-check REA and to locate the one `FieldRVA` row.
  Every row offset my parser computed (e.g. Module row at file offset 2916,
  Field rows at 3096/3102, Assembly row at 3444) matched REA's reported
  `row_offset` values exactly, which gave confidence the rest of the hand
  parsing (which REA does not expose, e.g. `FieldRVA`/`ClassLayout` rows)
  was also correct.
  - `FieldRVA` row: RVA `0x27c8` -> `Field` index 1 (`f_2898b321ff`). RVA
    `0x27c8` maps (via the `.text` section header, VA `0x2000` -> file
    offset `0x200`) to file offset `0x9c8` (2504).
  - `ClassLayout` row: packing 1, **class size 235 bytes**, parent TypeDef
    row 4 (`Tf9ec26c126`) — the sized nested struct that gives the
    field-RVA blob its length. This is the classic Roslyn
    `<PrivateImplementationDetails>`/static-array-initializer pattern, just
    with obfuscated names.
  - Reading 235 bytes at file offset 2504 gives the raw blob (hex-dumped in
    `pixel_tone.py`'s `_BLOB` constant).
- **`cil_decoder.py`** — a minimal but complete ECMA-335 opcode table
  (single-byte opcodes plus the 0xFE-prefixed two-byte extended opcodes),
  decoding raw bytes into `(il_offset, mnemonic, operand)` tuples. This is
  pure static analysis: it only ever reads bytes already present in the PE
  file (at the `file_offset` REA reported, after skipping the 1-byte "tiny"
  or 12-byte "fat" method-header prefix — confirmed by manually checking the
  header byte/word values at those offsets against REA's reported
  `max_stack`/`local_var_sig_token`/`il_size`, e.g. the fat header at file
  offset 592 decodes to `maxstack=2, codesize=145,
  localvarsig=0x11000001`, exactly matching REA's method `0x06000001`
  record).
- **`decode_all.py`** — runs the decoder over all 8 `MethodDef` bodies and
  additionally resolves every branch/`switch` target to an absolute IL
  offset (REA's anchors only give the *raw* relative operand for branches,
  which is easy to misread — my first pass mis-traced method `0x06000005`'s
  state machine until I added target resolution and re-derived it correctly;
  see the method table in Section 4).

Full instruction listings for all 8 methods are reproducible by running
`python reconstruction/pass04/decode_all.py` in this environment; they are
not repeated verbatim here for brevity, but every control-flow and
arithmetic claim in Section 4 and in `pixel_tone.py`'s comments was read
directly off that output, not inferred from anchors alone.

### 2.1 Recovering the embedded strings

Method `0x06000008` (`T84d29266f2.m_5558f5ab53(int offset, int length, byte
key) -> string`) decodes to (annotated):

```
newarr char[length]          ; chars = new char[length]
i = 0
loop:
    chars[i] = (char)(f_134b552a1f[offset + i] ^ key)
    i++
while i < length
return new string(chars)
```

i.e. a trivial repeating-XOR string decoder keyed per call site. Every call
site in `Main` and in the preset-transform helper pushes 3 integer literal
constants immediately before calling this method -- `(offset, length, key)`
-- so all 11 such call sites were extracted from the decoded CIL and the
same XOR decode was run in Python against the 235-byte blob extracted
above. All 11 decoded to plausible, grammatical English CLI text on the
first attempt (nothing required adjustment/guessing), which is strong
corroborating evidence that both the blob-extraction and the
decode-algorithm transcription are correct:

| offset | len | key | decoded text |
|---|---|---|---|
| 28 | 6 | 71 | "--help" |
| 34 | 42 | 95 | "PixelTone R G B brightness contrast preset" |
| 76 | 81 | 238 | "R/G/B: 0..255; brightness: -100..100; contrast: 0..200; preset: neutral\|mono\|warm" |
| 157 | 32 | 21 | "expected 6 arguments; use --help" |
| 8 | 20 | 8 | "integer out of range" |
| 189 | 7 | 151 | "neutral" |
| 0 | 4 | 38 | "mono" |
| 4 | 4 | 99 | "warm" |
| 196 | 14 | 123 | "unknown preset" |
| 210 | 18 | 116 | "{0},{1},{2}\|{3:X8}" |
| 228 | 7 | 62 | "ERROR: " |

These were all **observed** by decoding bytes that are physically present in
the shipped file; no text was guessed.

---

## 3. Live probes (8/8 used)

All 8 probes were run through `reconstruction/pass04/probe_runner.py`
(captures exact stdout/stderr bytes + exit code, timestamps, and appends to
`probe_log.jsonl`). Every probe was chosen to confirm a specific point that
static analysis alone left as an inference rather than a certainty (exact
byte framing/newlines, the CLI argument order and which numeric argument
feeds the additive vs. multiplicative term of the brightness/contrast
formula, the hash algorithm's exact constants, and clamp/rounding behavior
at extreme values). **All 8 matched the static reconstruction exactly, byte
for byte, with no adjustments needed to `pixel_tone.py` afterward.**

| # | Command | Result (exit, stdout/stderr) | Confirmed / refuted |
|---|---|---|---|
| P1 | `PixelTone.exe --help` | exit 0; stdout = the two decoded help lines, each terminated CRLF; stderr empty | Confirms exact help-line text and that `Console.WriteLine` emits CRLF (not LF) -- informed the decision to write raw CRLF bytes in `pixel_tone.py` rather than relying on `print()`'s platform-dependent newline translation. |
| P2 | `PixelTone.exe` (no args) | exit 2; stdout empty; stderr = "ERROR: expected 6 arguments; use --help" + CRLF | Confirms the "wrong argument count" path, the "ERROR: " prefix, and exit code 2 for the caught-`ArgumentException` path. |
| P3 | `PixelTone.exe 100 150 200 0 100 neutral` | exit 0; stdout = "100,150,200\|975A9C15" + CRLF | Confirms `neutral` preset is a true passthrough at brightness=0/contrast=100 (the formula's identity point), and that the FNV-1a32 hash constants/algorithm are exactly as decoded -- the Python reimplementation independently produced the identical hash before this probe ran. |
| P4 | `PixelTone.exe 10 20 30 0 100 mono` | exit 0; stdout = "18,18,18\|B4C6FD95" + CRLF | Confirms the `mono` luma formula `(77R+150G+29B+128)>>8` and that all three output channels are set equal to that luma. |
| P5 | `PixelTone.exe 250 250 250 0 100 warm` | exit 0; stdout = "255,253,241\|91670528" + CRLF | Confirms the `warm` per-channel offsets (+12/+3/-9) and that `Clamp255` correctly saturates the R channel at 255 (250+12=262->255) while G/B stay in range. |
| P6 | `PixelTone.exe 300 0 0 0 100 neutral` | exit 2; stderr = "ERROR: integer out of range" + CRLF | Confirms the R-channel [0,255] range check fires (and reuses the same message as a parse failure, as predicted from the flattened CIL where both failure edges converge on one `throw`). |
| P7 | `PixelTone.exe 0 0 0 0 100 purple` | exit 2; stderr = "ERROR: unknown preset" + CRLF | Confirms the preset allow-list is exactly {neutral, mono, warm} and that validation happens in `Main` (after all 5 numeric args parse successfully), not inside the preset-transform helper. |
| P8 | `PixelTone.exe 200 100 50 -50 150 neutral` | exit 0; stdout = "186,36,0\|BF42BA71" + CRLF | The decisive arithmetic test: confirms (a) argument order is R G B brightness contrast preset (not R G B contrast brightness preset -- brightness is the argument whose range is [-100,100] and which is added; contrast is [0,200] and multiplies), and (b) C#'s truncate-toward-zero integer division is reproduced correctly. The Python script reproduced this value exactly before the live answer was known. |

No probe needed to be "spent" re-confirming something already pinned down
unambiguously by the CIL control-flow itself (e.g. that a non-numeric
string in an R/G/B/brightness/contrast slot produces the identical "integer
out of range" message as an out-of-range number -- both paths demonstrably
jump to the exact same single `throw` instruction in the decoded IL, so
this was treated as *observed from code*, not left as an untested
inference).

---

## 4. Method table

Tokens/names as reported by REA; "assigned name" is the role determined
from full CIL decoding (Section 2) and probe confirmation (Section 3).

| Token | REA name | Assigned name | Behavior |
|---|---|---|---|
| `0x02000002` | `Teeef425ae1` | `Program` | Entry-point type; holds `Main` and all the per-pixel math helpers. |
| `0x06000001` | `m_4e09ee408f(i4)->i4` | `Clamp255` | Returns 0 if x<0, 255 if x>255, else x. Implemented as a 5-state flattened switch; fully traced in Section 2. Observed via CIL + probes P5/P8 (saturation). |
| `0x06000002` | `m_b2ece2c34c(i4,i4,i4)->i4` | `AdjustChannel(channel, brightness, contrast)` | `Clamp255( truncdiv((channel-128)*contrast, 100) + 128 + brightness )`. Observed via CIL + probe P8. |
| `0x06000003` | `m_b3c4f3c803(i4,i4,i4,string)->i4[]` | `ApplyPreset(r,g,b,preset)` | 5-state flattened switch comparing `preset` (via `DecodeString`+`String.op_Equality`) to "mono" (-> grayscale [luma,luma,luma], luma=(77r+150g+29b+128)>>8) then "warm" (-> [Clamp255(r+12),Clamp255(g+3),Clamp255(b-9)]); default/no-match -> [r,g,b] unchanged (the "neutral" case, and any other string, falls here). Observed via CIL + probes P3/P4/P5. |
| `0x06000004` | `m_0481f84d57(i4[])->u4` | `Fnv1a32(int[] values)` | Standard 32-bit FNV-1a over the array's int32 elements: h=0x811C9DC5; for v in values: h=(h^v)*0x01000193 (mod 2^32). Constants -2128831035/16777619 in the decoded CIL are the canonical FNV-1a-32 offset-basis/prime read as signed i4. Observed via CIL + all success-path probes (hash matched exactly every time). |
| `0x06000005` | `m_22283830b7(string,i4,i4)->i4` | `ParseIntInRange(s, lo, hi)` | `int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out v)`; on failure, or if v<lo/v>hi, throws ArgumentException(DecodeString(8,20,8)) = "integer out of range" (same message for every failure mode); otherwise returns v. Observed via CIL + probe P6. |
| `0x06000006` | `m_ec38e2401a(string[])->i4` | `Main(args)` | See full flow in Section 4.1 below. Observed via CIL + all 8 probes. |
| `0x06000007` | `T84d29266f2..cctor` | static initializer | `f_134b552a1f = (byte[])RuntimeHelpers.InitializeArray(new byte[235], fieldToken(f_2898b321ff))` -- the standard Roslyn pattern for `static readonly byte[] = { ...235 literal bytes... }`, with the 235 bytes supplied via FieldRVA rather than a sequence of ldc.i4/stelem pairs. Observed via CIL + PE/metadata parsing (Section 2). |
| `0x06000008` | `T84d29266f2.m_5558f5ab53(i4,i4,u1)->string` | `DecodeString(offset,length,key)` | `new string([ (char)(blob[offset+i]^key) for i in range(length) ])`. Observed via CIL + all 11 decoded strings being well-formed ASCII English/format text on first attempt, plus every probe's exact text match. |
| `0x02000003` | `T84d29266f2` | string-table holder | Static helper type: 2 fields (f_2898b321ff: the sized struct typed over the raw blob; f_134b552a1f: the materialized byte[]), .cctor, DecodeString. |
| `0x02000004` | `Tf9ec26c126` | blob-sizing struct | NestedPrivate, 0 members, ClassLayout size=235 -- exists purely so the FieldRVA data has a sized type to be typed as (valuetype:16); never otherwise referenced. |

### 4.1 Main(string[] args) -> int control flow (fully observed)

```
if args.Length == 1:
    if args[0] == "--help":
        print(HELP_LINE_1); print(HELP_LINE_2); return 0
    # else: falls through to the generic length check below, which fails

if args.Length != 6:
    throw ArgumentException("expected 6 arguments; use --help")   # caught -> exit 2

# try block starts here (covers everything below, catch(ArgumentException) below)
r          = ParseIntInRange(args[0],    0, 255)
g          = ParseIntInRange(args[1],    0, 255)
b          = ParseIntInRange(args[2],    0, 255)
brightness = ParseIntInRange(args[3], -100, 100)
contrast   = ParseIntInRange(args[4],    0, 200)
preset     = args[5]

if preset not in ("neutral", "mono", "warm"):
    throw ArgumentException("unknown preset")

newR = AdjustChannel(r, brightness, contrast)
newG = AdjustChannel(g, brightness, contrast)
newB = AdjustChannel(b, brightness, contrast)
toned = ApplyPreset(newR, newG, newB, preset)
hash  = Fnv1a32(toned)

print(f"{toned[0]},{toned[1]},{toned[2]}|{hash:08X}")
return 0

# catch (ArgumentException e):
Console.Error.WriteLine("ERROR: " + e.Message)
return 2
```

Argument order R G B brightness contrast preset is confirmed both by the
decoded CIL (the ParseIntInRange range bounds [-100,100] then [0,200] match
the help text's stated order "brightness: -100..100; contrast: 0..200")
and by probe P8, which would have produced a different numeric result
under the opposite assignment.

---

## 5. Observed vs. inferred vs. unverified

**Observed** (read directly from file bytes, decoded CIL, or live process
output -- not guessed):
- All PE/CLI/metadata structure in Sections 1 and 2 (REA JSON + the
  hand-written PE/table parser, cross-validated against each other).
- The full instruction stream of every one of the 8 method bodies (via
  cil_decoder.py), not just REA's curated anchors.
- The 235-byte embedded blob and the XOR string-decode algorithm, and all
  11 decoded string literals.
- Exact stdout/stderr bytes and exit codes for the 8 probed argument
  combinations (probe_log.jsonl), each matching pixel_tone.py's
  independently-computed output byte-for-byte.

**Inferred** (consistent with everything observed, not independently
re-probed for every combination, but not left as a guess -- each follows
mechanically from code that *was* fully decoded):
- That int.TryParse failure and out-of-range values always produce
  "integer out of range" for *every* argument slot (only R-out-of-range and
  a numeric-but-out-of-range value were probed; the identical-message
  behavior for brightness/contrast/non-numeric input follows from the
  single shared throw site in the decoded CIL, which is structurally
  guaranteed).
- NumberStyles.Integer semantics exactly match .NET's documented behavior
  (optional leading/trailing whitespace, optional single leading sign,
  ASCII digits only, no thousands separators/decimal point, must fit
  Int32). Did not probe non-ASCII whitespace or exotic locale edge cases.
- Console output encoding: since every observable string is pure ASCII,
  probing confirmed CRLF framing but could not distinguish between
  possible underlying console encodings (UTF-8 vs. a legacy code page) --
  immaterial here because the byte sequences are identical either way for
  ASCII text, but called out as an assumption that would matter if the
  target were ever extended with non-ASCII text.

**Unverified / explicit assumptions made in pixel_tone.py** (stated here
rather than silently guessed into the code):
- int.TryParse boundary behavior for values exactly at Int32.MinValue /
  MaxValue, and for forms like a lone "+"/"-" or empty string, were not
  live-probed; the regex-based `_try_parse_int32` approximation is a
  best-effort match to the documented NumberStyles.Integer grammar and may
  diverge from the real CLR parser in exotic corner cases (e.g. some
  unusual Unicode whitespace categories the CLR's AllowLeadingWhite /
  AllowTrailingWhite accept that this regex's whitespace class does not,
  or vice versa).
- Whether an argument string containing embedded NUL or other control
  characters is handled identically by the CLR's console argv marshaling
  and Python's sys.argv was not tested (out of scope of the probe budget;
  low likelihood of divergence for a console app).
- The script assumes ASCII/UTF-8-safe stream encoding, since no non-ASCII
  text ever reaches stdout/stderr in any code path that was observed.

No out-of-scope content was accidentally glimpsed during this engagement:
directory listings were restricted to third_party/rea/* (permitted), and
file reads were limited to the REA evidence-workflows doc, REA's own JSON
output, and the target binary's raw bytes -- none of the excluded
fixture/report/other-protection-stage paths were opened or listed.

---

## 6. Deliverables

- `reconstruction/pass04/pixel_tone.py` -- the standalone reimplementation.
- `reconstruction/pass04/pe_probe.py`, `cil_decoder.py`, `decode_all.py` --
  supplementary static-analysis tooling used to produce the above (kept for
  traceability; not required to run pixel_tone.py).
- `reconstruction/pass04/probe_runner.py`, `probe_log.jsonl` -- the
  live-probe harness and its raw, byte-exact results (8/8 probes used).
- `reconstruction/pass04/actions.jsonl` -- audit log of major actions taken.
- `reconstruction/pass04/findings.md` -- this document.

## Timestamps

- first_read_attempt_utc: 2026-10-14T10:49:42.102983+00:00
- static_implementation_complete_utc: 2026-10-14T11:00:39.377710+00:00
- final_draft_utc: 2026-10-14T11:08:16.928655+00:00
