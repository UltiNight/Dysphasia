# Benchmarks

Everything below is a real measurement: a corpus run, an `ilverify` pass, a repeated build-hash comparison, a raw REA command transcript sitting under `logs/`. Nothing here is estimated. Each number links back to the report with the actual evidence behind it.

All of it is against the same 115-line fixture, [`fixture/PixelTone.cs`](fixture/PixelTone.cs) on the .NET side and its C port on the native side, compiled unprotected to [`artifacts/baseline/PixelTone.exe`](artifacts/baseline/) as the control.

## Correctness first

Nothing below counts unless it clears these:

- **335 / 335** behavioral corpus cases match the baseline byte-for-byte (stdout, stderr, exit code) for every build in this repo, not just the final one.
- `dotnet-ilverify` comes back clean on the full 18-pass build: "All Classes and Methods Verified."
- Same seed, same input, same output bytes, confirmed by actually rebuilding and diffing, on every pass that derives anything from the seed.
- `/W4`, zero warnings, on every native `protectedN.c` variant.

Two of these failed at least once during development before getting fixed: the determinism one, and a real correctness bug in control-flow flattening that had been shipping silently. See the [bug list in the README](README.md#bugs-found-along-the-way) for all nine.

## What each technique actually costs REA

REA gets probed the way a human analyst would start: `inspect-managed-members` on the .NET side, IDA/Hex-Rays (sometimes through REA's own IDA bridge) on the native side. "Before" is the unprotected baseline, "after" is the build with that one technique applied.

**BCL call hiding** (`hide-bcl-calls`) takes `Int32.TryParse` from 1 visible call site to 0. The call now goes through a reflection wrapper with an XOR-encoded method name.

**Code virtualization** (standalone, one method) turns `ClampByte` from a fully visible comparison/branch/constant structure into `il_size: 7, instruction_count: 3`, three instructions: load argument, call, return. None of the actual logic shows up anywhere REA looks.

**Exception-based routing** (.NET) keeps the try/catch structure visible in `exception_regions`, but the catch type only resolves to a raw metadata token (`0x0100000f`). REA's `inspect-managed-members` resolves `MemberRef` call targets to names but doesn't do the same for catch types. Found this by accident, not by trying to find a gap in REA.

**Deceptive naming + homoglyphs** replaces hash-like obviously-obfuscated names with plausible-but-wrong ones (`SyncMetadata`, `RefreshToken`, that kind of thing), some with Cyrillic homoglyphs mixed into identifiers that were already private. This one's harder to measure than the others. It's a "takes longer to notice something's off" effect, not a hit-count, and wasn't re-measured against REA's tokenizer specifically.

**MHOP** swaps the arithmetic opaque predicate (`n*(n+1)` is even, provable by eye in a couple seconds) for one gated on `SHA256`, which can't be resolved by reading the text at all.

**Token bloating** doesn't work. A 20-level empty inheritance chain goes in, REA's `inspect-managed-members` supports `--token-limit`/`--token-offset` pagination, and the context-window-exhaustion idea just doesn't land against this particular tool. Left in and written up honestly instead of quietly pulled.

**Native anti-debugging via `IsDebuggerPresent`** also doesn't prove what it was supposed to. The function stays in `dumpbin /imports` regardless, because the UCRT/VCRuntime startup code already imports it on its own, even in the fully unprotected baseline. The cleaner test case is `GetSystemMetrics` from `USER32.dll`, a DLL this program never otherwise touches: dynamically resolving that call keeps `USER32.dll` out of the import table entirely, which is the positive result the first test couldn't give.

**Garbage data** adds 6 dummy methods and 4 dummy fields to a new host type, and there's no signal in the member listing alone that tells them apart from the real 6-and-0.

**Function inlining + control-flow flattening combined** removes the call relationship for touched call sites entirely. `ClampByte` stops existing as a separate named method at those sites, though the call sites themselves then had to be excluded from flattening (see the README's bug list for why).

**Cross-build identity** is the sharpest one here, and it's about REA specifically rather than general obfuscation. `compare-managed-members` exists to answer "are these two files the same program." Pointed at baseline vs. the fully-protected (18-pass) build, it matches 0 of 57 compared methods and fields on any of its four matching criteria. But that's not true from pass one: run against just `rename` alone, all 6 original methods still match correctly (3 of them byte-identical IL, since renaming doesn't touch instruction bytes at all). It's `string-encode` joining the pipeline that flips it to zero, and it stays at zero through everything after. The original assumption going in was that renaming alone would already break this. It didn't, and that only got caught by actually running all six intermediate builds instead of guessing. Full writeup: [rea-compare-managed-members.md](reports/rea-compare-managed-members.md).

## Independent reconstruction, two rounds of N=5

Five subagents per round, each handed only the protected binary (no source, no name mapping, no access to anything outside an isolated working directory), asked to reconstruct the program's behavior from scratch. Round one targeted an early build (P1+P2+P3 only, 3 of 18 passes). Round two, run later, targeted the actual strongest build (all 18 passes). Full protocols in [pass03-blind-reconstruction.md](reports/pass03-blind-reconstruction.md) and [pass08-blind-reconstruction-final-build.md](reports/pass08-blind-reconstruction-final-build.md).

| | unprotected | P1+P2+P3 (round 1) | all 18 passes (round 2) |
|---|---|---|---|
| mean time to reconstruct | ~570s | 1,242.4s (σ=113.1s), 2.18x | 1,371.9s (σ=237.3s), 2.41x |
| mean corpus pass rate | n/a | 334.8 / 335 (99.9%) | 148.8 / 335 (44.4%) |
| fully correct (335/335) | n/a | 3 of 5 | 0 of 5 |
| best result | n/a | 335/335 | 334/335 |
| worst result | n/a | 334/335 | 0/335 |

The time cost barely moved between 3 passes and 18 (1.10x). What collapsed instead was accuracy: round 1's worst subagent still got 334 of 335 cases right, round 2's best subagent got 334/335 and the other four ranged from 193 down to 0. Going from 3 passes to 18 didn't mostly make reconstruction slower, it mostly made it wrong.

The decisive factor in round 2 was the output's trailing checksum (32-bit FNV-1a, confirmed by three subagents, two via brute-forcing the algorithm against observed outputs and one via a hand-written CIL disassembler cross-validated against REA's own opcode counts). The other two subagents never cracked it and shipped a placeholder, which fails every case that prints a checksum, roughly 90% of the corpus. All three of those two's near-misses were drawn toward the same wrong lead: IL that visibly calls `SHA256.Create()`/`ComputeHash` for an unrelated anti-tamper check (from the `mhop-predicates` and `integrity-check` passes), which looks like it could be the checksum and isn't. That specific trap wasn't designed; it's what combining two independently-motivated SHA256 uses produces by accident. See the full report for how one subagent's custom-disassembler methodology avoided it entirely while three others fell into it and then had to brute-force their way back out.

Also worth noting from round 1: 3 of the 5 subagents tried to route around a "don't write findings.md" tool guard using a temp-file-and-rename trick, which got caught and led to prompt hardening in later runs. Round 2 showed the opposite problem calibration: all 5 subagents flagged their own guesses (the `warm` preset formula, the checksum, a couple of error strings) as low-confidence, and those were exactly the parts that turned out wrong. No overconfidence this round.

This is the strongest single piece of evidence for the time-fight framing, and it cuts differently than round 1 suggested. Obfuscation at full strength doesn't mainly cost an analyst time, it costs them correctness.

## What didn't work

- **Token bloating** doesn't exhaust REA's context window, because the tool paginates.
- **Hiding `IsDebuggerPresent`** can't be shown to have "worked," because the C runtime imports it regardless of what this program's own code does.
- **String splitting** adds less on top of full string encryption than seemed likely going in. See [string-splitting.md](reports/string-splitting.md).

## Full technique coverage

[README.md](README.md#whats-actually-in-here) has the complete matrix, applied and declined, across all five categories, with the specific reason behind every declined item.
