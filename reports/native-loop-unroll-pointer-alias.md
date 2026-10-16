# Native Track: Loop Unrolling + Pointer Aliasing

## Background

"Loop unrolling" and "pointer aliasing" from the user's technique list. Both are memory-level/machine-code-level concepts, so they don't naturally fit verifiable .NET IL (managed code has no raw pointers, and loop unrolling is an optimization the JIT already performs, so imitating it at the source level carries little weight), but they apply directly to the native C track (the `fixture/PixelTone.c` family). Unlike the previously deferred "native Dynamic API Resolving," these two don't need to touch the console I/O path again, so there is no risk like the CRLF duplication bug this project already hit once, and I implemented them right away.

## Implementation

[`fixture/PixelTone.protected3.c`](../fixture/PixelTone.protected3.c): built directly on top of `PixelTone.protected2.c` (P2 string obfuscation + P3 control-flow flattening) as the base, adding two things:

**Loop unrolling (`fingerprint`)**: `channels` is **always an array of exactly 3 elements** in this program. That's not an assumption, it's a fact (`wmain`'s only call site passes `int result[3]`). So the 3-iteration loop was unrolled into 3 sequential dispatcher states, with no `i`, no bounds check, and no backward branch. The reason it wasn't simply unrolled into 3 flat, plain lines, and instead **kept the same switch/state-machine shape as the existing P3**, is that simply unrolling it would have the opposite effect, handing back the readability that flattening had hidden (even if you unroll one loop into 3 sequential steps, putting it back into the same state-machine frame erases the very fact that it "was a loop" in the first place).

**Pointer aliasing (`read_int`)**: changed the value being parsed from `long long value` to a double indirection, `long long **value_pp`, so that every read/write goes through `**value_pp`. This adds two extra pointer hops on top of any analysis that's trying to simply track "what does this variable hold."

## Verification

- Built with MSVC via `scripts/build-native-fixture-protected3.bat` (`/O2 /MT /W4`, 0 warnings).
- Compared the full 335-case corpus with `scripts/evaluate-native-protected3.py`: **335/335 match** ([logs/verify-native-protected3](../logs/verify-native-protected3/summary.json)).
- Ran it directly and confirmed the same output as before (`70,141,219|8167D285`, `--help`).
- Compared raw instruction counts with `dumpbin /disasm`: `protected2` at 24,364 → `protected3` at 24,371 (+7; the `mov`/`lea` instructions added by the double pointer dereference slightly outnumber the index increment, bounds check, and backward branch that loop unrolling removes). File size is identical (140,800 bytes, both) due to section alignment, so the byte count shows no change, but the instruction-count change confirms the actual code really did change.

## Limitations (honestly)

- **No REA↔IDA remeasurement was done**: this increment is small (2 functions, source-level changes only), and the existing native baseline report ([native-track-baseline.md](native-track-baseline.md)) already concluded that "Hex-Rays restores almost all of the logic." I judged that the additional information this small change would yield isn't worth the cost of relaunching the IDA Pro GUI and re-setting-up the REA↔IDA integration. The same judgment was applied to every increment after [BCL call hiding](bcl-call-hiding.md): not re-running a full reimplementation experiment every single time.
- **Both fall apart with a single dereference or run**: the moment a real decompiler like Hex-Rays follows the pointer, pointer aliasing goes right back to looking like an ordinary local variable (decompilers follow pointers as a matter of course; this slows down a human's manual grepping, it doesn't stop a decompiler). Loop unrolling may also get recognized as a pattern by Hex-Rays and shown back as a loop (decompilers' loop-recovery heuristics are fairly strong); this increment did not directly check whether that recovery actually happens.
- **Narrow scope**: applied only to a single target each, `fingerprint` (unrolling) and one value in `read_int` (aliasing). The fixed source itself is small, so there isn't much more to apply this to more broadly.
