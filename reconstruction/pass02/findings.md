# pass02 independent reconstruction without viewing source

## Result

The Python CLI was implemented first from static analysis, and afterward, across 8 explicitly logged
executions of the target, the raw bytes of stdout and stderr and the exit code all matched. This does not
claim to recover the original source. It is a new implementation of the same functionality, not a proof
of equivalence over the entire input space.

- Implementation: `pixel_tone.py`
- Audit log: `actions.jsonl`
- Supplementary static decoder: `decode_cil.ps1`
- Supplementary decoding output: `derived-cil.txt`
- Code for the 8 executions and comparison: `probe.py`
- Execution observations: `probe-results.json`

## Input boundary and method

The inputs read were limited to `artifacts/baseline/PixelTone.exe`, `logs/pass02/01-artifact.stdout.json`,
`logs/pass02/02-members.stdout.json`, and the REA SKILL.md. The original fixture source, build scripts,
evaluator, oracle, tests, and the pass01 reconstruction or report were not read. Follow-up inspection only
read files generated directly by this task itself. This boundary is procedural non-viewing of source, not
a sandbox enforced by OS access control.

The existing REA JSON was used, and the REA tool itself was not re-run. REA provided CIL anchors such as
metadata, calls, and constants/branches. The full ordering of opcodes is not included in those anchors, so
a separate PowerShell decoder was written to read the method offsets REA specified, from the allowed
executable. This decoder only uses the host's `Reflection.Emit.OpCodes` definitions and does not load or
execute the target assembly. The file's SHA-256 and the CIL SHA-256 of the 6 methods were cross-checked
against REA's values. `derived-cil.txt` is supplementary evidence, not REA output or a REA C# decompilation
result. At the time the implementation was first saved, the number of target executions was 0, and the
hash was recorded in the audit log.

## Evidence identifiers

- A: `ev_b18495a6fa1885e00e264c079ae80b39fbdbaa1b55db071bc6c41298489d4d78` (the REA artifact record).
- M: `ev_6a49f948b9d22f08595da7adb3ef28ec49957efedc7cfd9fc81814381d61875e` (the REA members record).
- D: `derived-cil.txt` (supplementary static decoding). The generation script and output SHA-256 are
  preserved in actions.jsonl.
- P1-P8: execution observation numbers in `probe-results.json`.
- Target SHA-256: `b479f51478e8041f43a91a3a883238bef01a5c7d8917c65dfd3088ecb5a29c95`.
- MVID: `9d8850e2-7741-4869-8f48-b19bab20a9c1`.

Method tokens are coordinates that apply only to this artifact and this MVID.

## Observations and functional inference

| Method token | Observational basis | Functional interpretation |
|---|---|---|
| `0x06000001` ClampByte | M, D: 0/255 comparison, branch, return | Clamps to 0..255 |
| `0x06000002` AdjustChannel | M, D: 128, 100, sub/mul/div/add, calls ClampByte | `clamp(trunc((c-128)*contrast/100)+128+brightness)` |
| `0x06000003` ApplyPreset | M, D: mono/warm string comparison, arithmetic and array stores | mono copies `(77*r+150*g+29*b+128)>>8` into all 3 channels. warm adds +12, +3, -9 respectively then clamps. neutral returns unchanged |
| `0x06000004` Fingerprint | M, D: initial constant -2128831035, XOR, repeated multiplication by 16777619 | unsigned initial value 2166136261, an FNV-1a-shaped XOR/multiply with 32-bit wraparound on each final channel |
| `0x06000005` ReadInt | M, D: InvariantCulture, Int32.TryParse with style 7, min/max comparison | Integer parsing that includes sign and ASCII whitespace, checks RGB 0..255, brightness -100..100, contrast 0..200 |
| `0x06000006` Main | A entry point, M, D call order, strings, exception regions | Handles a single --help, requires exactly 6 arguments, checks integers then checks preset, adjusts the three channels then applies the preset, outputs the final color hash |

The normal output format is `R,G,B|8-digit uppercase hex`, and the exit code is 0 for both normal success
and help. The ArgumentException handling path writes `ERROR: ` plus a message to stderr and returns 2. An
integer error takes priority over a preset error. No case conversion or whitespace stripping on the preset
is visible. The formulas in the table above are an interpretation of the actual CIL order; they do not
mean the original's variable names or expressions were recovered.

A showed a 5120-byte x86_64 managed PE, a CIL implementation, 6 methods, and mscorlib references. M's
method names and strings directly exposed the functional meaning, and D confirmed the exact operations and
order. So in this sample, even renaming alone leaves the possibility of inferring functionality through
constants, calls, and CIL operations. The effect of renaming and of string/control-flow protection needs
to be re-measured on a transformed artifact; we do not predict numbers from this result alone.

## Execution observations

We ran: P1 help, P2 no arguments, P3 neutral with whitespace, a leading plus sign, a leading zero, and a
mid-calculation negative division, P4 mono with saturation during the adjustment step, P5 warm with
saturation at both the upper and lower bound, P6 out-of-range values, P7 a preset with different casing,
and P8 an integer with an NBSP prefix. Across all 8 runs, the actual output's raw bytes (including CRLF),
stderr, and exit code all matched the Python implementation. No implementation changes were made after
the observations.

## Unconfirmed items and limitations

- The 8 observations do not guarantee parsing equivalence over the full input space, every Unicode input,
  or other CLR versions.
- The Python integer parser mimics the observed API contract. Things like NUL, which can't be included in
  the target OS process's arguments, are outside the CLI's scope.
- Output line-ending equivalence was verified on the current Windows environment.
- The original comments, project structure, development intent, and the original source's own expression
  style are unknown.
- The external evaluation corpus was neither read nor requested. Independent evaluation results are not
  included in this report.
- Whether the original source was recovered: not claimed. Whether this is a functional reconstruction:
  supported by the static implementation and the limited execution observations.

## Measured time

First audit log entry UTC: 2026-10-14T05:35:08.651124+00:00
Static implementation completed UTC: 2026-10-14T05:36:16.493223+00:00
Analysis ended UTC: 2026-10-14T05:43:39.474457+00:00
From first audit log entry to static implementation completion: 67.842 seconds.
From first audit log entry to end: 510.823 seconds.
Because the first log entry was written after the initial read request, this measurement is an explicit
lower bound that does not include the time of that earliest read beforehand.

The first `final` row in the audit log had a measurement error: re-parsing the PowerShell JSON date as a
string caused UTC to be mistaken for local time, adding 9 hours. That row was preserved, and corrected
with a `final_correction` row that parses the original ISO timestamp directly, together with its time
zone.
