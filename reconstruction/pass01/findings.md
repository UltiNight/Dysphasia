# PixelTone Blind Behavior Reconstruction (pass01)

I wrote an independent Python implementation, `pixel_tone.py`. This is not recovery of the original source; it is **behavior reconstruction based on REA's static results plus separate byte-level decoding**. After finishing the first implementation, I compared the raw bytes of the exit code, stdout, and stderr across 8 permitted target executions, and all 8 matched. This sample result does not prove equivalence across all inputs.

The scope of analysis was limited to the designated executable, the two REA JSON files, the REA skill/related documentation, and this pass01 output alone. I did not read `fixture/`, build scripts, the evaluator/oracle/undisclosed tests, or other reconstruction folders. There were no network requests or outgoing messages. The source non-disclosure boundary was observed procedurally, not through filesystem isolation.

## Evidence and Scope of Identification

| Identifier | Kind and observed scope |
|---|---|
| E1 = `ev_b18495a6fa1885e00e264c079ae80b39fbdbaa1b55db071bc6c41298489d4d78` | Saved `inspect_managed_artifact` result. PE32+ x86_64, IL-only, 5,120 bytes, entry point `0x06000006`, metadata version `v4.0.30319`, mscorlib 4.0 reference. Not a result of executing the target code. |
| E2 = `ev_6a49f948b9d22f08595da7adb3ef28ec49957efedc7cfd9fc81814381d61875e` | Saved `inspect_managed_members` result. 6 methods, signatures, call relationships, CIL anchors and hashes, error/output strings, exception regions. coverage is complete and issues is empty. |
| D1 = `cil.txt` / `extract_cil.py` | The result of this analyst's own separate decoding of the designated executable's bytes. Not claimed to be the complete CIL that REA outputs. The executable's SHA-256, the 6 methods' IL SHA-256 values, and the decoded instruction count were all cross-checked against E2 and matched. |
| P01-P08 = `probe_results.json` | Direct target-execution observations performed after the initial implementation. Command arguments and the times before and after execution are recorded in `actions.jsonl`. |

All method tokens are valid only for this build. The executable's SHA-256 is `b479f51478e8041f43a91a3a883238bef01a5c7d8917c65dfd3088ecb5a29c95`, and the MVID is `9d8850e2-7741-4869-8f48-b19bab20a9c1`. The artifact hashes are left in `hashes.json`.

The skill actually read was `third_party/rea/.agents/skills/reverse-engineer-anything/SKILL.md`. The initially specified workspace-root `.agents/...` path did not exist and failed; it was found via a permitted hidden-path search inside third_party/rea. I applied the skill's rules for distinguishing observation from inference from unconfirmed items, citing Evidence IDs, and distinguishing static analysis from execution observation.

## Scope Confirmed from REA Results Alone, and the Scope of Additional Decoding

From E1/E2 alone, I could observe the target's kind and entry point, the method names and return/argument types, constants, strings, call relationships, branch anchors, and the presence of exception handling. From this I could form a candidate hypothesis of the functionality: a color-channel adjustment / preset / fingerprint CLI. However, E2 has no full instruction sequence, only anchors and opcode counts. The mere presence of constants did not let me pin down the exact formula or the stack operand order.

The separate D1 decoding confirmed the actual order of constants and arguments, the local-variable flow, all return codes, and the array layout and output order. In particular, `warm`'s green `+3` is present as `ldc.i4.3` and does not appear among the main constant anchors. The integer division in the brightness/contrast calculation, the channel clamp before preset application, and the final RGB order fed into the hash were all reconstructed based on D1's full instruction sequence. So this result cannot be called **REA-alone restoration**.

## Method Mapping and Reconstruction

The formulas below are the result of interpreting, according to CIL semantics, the instruction sequences observed in E2/D1. Only the cases included in P01 through P08 were also confirmed by execution.

| Token / file body offset | Original method name → Python function | Behavior |
|---|---|---|
| `0x06000001` / 592 | `ClampByte` → `clamp_byte` | Returns 0 if below 0, 255 if above 255, otherwise returns the value unchanged |
| `0x06000002` / 615 | `AdjustChannel` → `adjust_channel` | `clamp(trunc0(((channel-128)*contrast)/100)+128+brightness)` |
| `0x06000003` / 644 | `ApplyPreset` → `apply_preset` | `mono`: repeats `(77*r+150*g+29*b+128)>>8` across RGB. `warm`: `clamp(r+12)`, `clamp(g+3)`, `clamp(b-9)` respectively. Otherwise, RGB unchanged |
| `0x06000004` / 796 | `Fingerprint` → `fingerprint` | Initial value 2166136261; for each final RGB value, `(h xor channel)*16777619`, with 32-bit wraparound |
| `0x06000005` / 844 | `ReadInt` → `read_int` | InvariantCulture, Int32.TryParse with number-style value 7, followed by an inclusive range check. On failure: `integer out of range` |
| `0x06000006` / 896 | `Main` → `run` and `main` | Help text, argument-count/integer/preset validation, adjust→preset→fingerprint→output. Writes the ArgumentException to stderr and returns 2 |

Help text is written as two lines to stdout, with exit 0, when the argument is exactly the single `--help`. A normal call takes 6 arguments: `R G B brightness contrast preset`. RGB ranges are 0..255, brightness is -100..100, and contrast is 0..200, all inclusive. Only `neutral`, `mono`, and `warm` are accepted as presets, case-sensitively. Integers are checked first, so if an invalid number and an invalid preset are both present, the number error takes priority.

Normal output is `r,g,b|HHHHHHHH` followed by CRLF, and the fingerprint is an uppercase 8-digit hex value. Normal exit is 0. For an invalid argument count, `ERROR: expected 6 arguments; use --help` is written to stderr with CRLF and the process exits 2; for an invalid number, `ERROR: integer out of range`; for an invalid preset, `ERROR: unknown preset`. On error, stdout is empty.

Python's `//` rounds negative numbers down, which differs from CIL's `div`. I took the integer division of the absolute values and then restored the sign. The fingerprint multiplication was handled with `& 0xffffffff` at every step rather than relying on Python's unbounded integers. Within the permitted input range, no 32-bit overflow occurs during the color calculation.

## Directly Observed Execution Samples

Each row is one separate target-process run, for a total of 8. The output shown in the table omits the trailing CRLF. Detailed arguments, stdout/stderr hex, and the reimplementation's result are in `probe_results.json`.

| Evidence | Check | Target result | Byte/exit-code comparison |
|---|---|---|---|
| P01 | `--help` | 2 lines of help text, exit 0 | Match |
| P02 | No arguments | Argument-count error, exit 2 | Match |
| P03 | `1 127 129 0 33 neutral` | `87,128,128\|417ED4C6`, exit 0 | Match |
| P04 | `13 187 244 -17 143 mono` | `143,143,143\|ADF6A784`, exit 0 | Match |
| P05 | `250 255 0 0 100 warm` | `255,255,0\|D662F499`, exit 0 | Match |
| P06 | `256 0 0 0 100 bogus` | Number error, exit 2 | Match |
| P07 | `1 2 3 0 100 Warm` | Preset error, exit 2 | Match |
| P08 | Integers including signs, leading zeros, and spaces/TAB/CR/LF | `13,0,255\|F66689D5`, exit 0 | Match |

No code was modified based on target execution. The initial implementation passed all of the samples above. The comparison script refuses to re-run when a result file already exists, to avoid accidentally exceeding the budget of 8 runs.

## Unconfirmed Items and Limitations

The number-style value 7 and the InvariantCulture call used in integer parsing were observed statically. The handling of ASCII digits, signs, and whitespace was implemented by inference from CLR semantics, and only part of it was confirmed by P08. All Unicode whitespace and digits, abnormally long input, every quoting/escaping combination on the Windows command line, and other CLR versions or locales were not verified by execution. Rather than relying as-is on Python `int()`'s default behavior of accepting Unicode digits, I restricted it to `[0-9]`.

File/network functionality did not appear in these 6 methods or in REA's call references. This is a result of the build and code scope examined; it does not prove the absence of any side effect across the entire CLR/OS. Environment errors such as output write failures, pipe closure, or runtime startup failure were not included in the scope of replication. An embedded NUL cannot be passed as a normal Windows process argument, so it was not treated as a target for CLI equivalence.

The original comments, the source's syntax/whitespace/file organization, the full set of build options, and the developer's intent are unknown. E1's metadata version and references alone were not used to pin down the actual running CLR patch version. D1 is a small decoder that handles only the opcodes it needs, not a general-purpose CIL analyzer. The match in instruction count and IL hash verifies the consistency of the byte range read; it does not prove the correctness of the Python implementation's behavior as a whole.

The confirmation questions, about CLI format, the conversion calculation, the fingerprint, error handling, and method mapping, were answered using static analysis plus a limited execution sample. Equivalence over the full input space is unconfirmed. Evaluation against the undisclosed corpus is performed independently by the parent party, and this analyst did not read that evaluation's inputs or results.

## Time Record

The first file-read attempt was at 2026-10-14 05:34:34 UTC (14:34:34 KST), and the point at which I actually began reading the two REA files was 05:34:53.862 UTC. The initial implementation was completed at 05:36:39.259 UTC, which was the stage before any target execution. The first probe was planned at 05:37:04.351 UTC, and the 8th result was recorded at 05:37:05.152 UTC. These times are measured wall-clock times, not an estimate of work speed. The first read start is a second-level approximation; the final draft time and elapsed time are recorded automatically below.

Final draft written: **2026-10-14T05:45:01.476048+00:00**. **627.476 seconds (10.46 minutes)** from the first read attempt; **607.615 seconds** from the actual start of reading the REA files.
