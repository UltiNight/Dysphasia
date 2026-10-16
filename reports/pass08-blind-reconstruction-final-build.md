# Dysphasia: independent reconstruction, round two, against the actual strongest build (pass08-12, N=5)

2026-10-15. The [original N=5 experiment](pass03-blind-reconstruction.draft.md) (pass03-07) only ever targeted an early build (P1+P2+P3, 3 of 18 passes). This re-runs the same experiment against the build this project actually calls strongest, `artifacts/protected-p1p2p3p5p6p7/PixelTone.exe`, all 18 passes applied.

## Why

The earlier "2.18x" number came from a weak build. This project never measured independent reconstruction time or accuracy against the build it actually ships as its strongest. That was a clear gap. This closes it.

## Method

Same principles as the original experiment. Five fresh subagents, each with no access to source, mapping files, or prior logs, each given only the protected binary in its own fully isolated working directory (under scratchpad, separate from the main project). Additional rules set for this round:

- REA's static analysis commands (`inspect-managed-artifact`, `inspect-managed-members`, `inspect-managed-native-boundaries`) were unlimited, since they never execute the target.
- Direct execution of the target was capped at a maximum of 8 runs per session.
- Explicit, firm instruction not to explore anything outside the assigned working directory, including anywhere else under the main project.
- Each subagent wrote `findings.md` (reasoning and confidence) and `pixel_tone.py` (its reimplementation) to its working directory when done.

After all five finished, each working directory was inspected directly for anything outside the given scope (any sign the original project had been read). All that turned up was self-generated scratch material: disassembly dumps, raw REA output, a couple of hand-written disassemblers. Every self-report was then set aside, and each reimplementation was independently re-verified against the existing 335-case corpus, run directly against `artifacts/protected-p1p2p3p5p6p7/PixelTone.exe`. Timing came from the agent harness's own recorded wall-clock duration, not a self-report.

## Results

| | N | mean | stdev | min | max |
|---|---:|---:|---:|---:|---:|
| protected, round 2 (pass08-12, 18 passes) | 5 | 1,371.9s | 237.3s | 1,110.3s | 1,681.5s |
| protected, round 1 (pass03-07, P1+P2+P3 only) | 5 | 1,242.4s | 113.1s | 1,114.8s | 1,344.7s |
| unprotected baseline (pass01-02) | 2 | 569.1s (lower bound) | n/a | 510.8s | 627.5s |

- **Time barely moved.** Going from 3 passes to 18 only raised mean time by 1.10x (1,242.4s to 1,371.9s). Against the unprotected baseline that's 2.41x, a bit higher than round one's 2.18x.
- **Accuracy is a completely different story.**

| Pass | Time | Corpus pass rate | Notes |
|---|---:|---:|---|
| pass08 | 1,681.5s | **334/335 (99.7%)** | the one failure (#315) is the exact same NBSP-whitespace trap round one's pass03 and pass05 hit |
| pass09 | 1,549.4s | 191/335 (57.0%) | `neutral` 100%, `mono` 64%, `warm` 0% |
| pass10 | 1,304.4s | 193/335 (57.6%) | same pattern as pass09, `neutral` 100%, `mono` 64%, `warm` 0% |
| pass11 | 1,214.0s | 26/335 (7.8%) | got the `neutral` formula right, but never cracked the checksum, so every success-path case (valid-boundary/valid-random) failed; only error and help paths passed |
| pass12 | 1,110.3s | **0/335 (0%)** | also never cracked the checksum, plus a separate newline bug in its own script broke every single comparison |

Mean corpus pass rate: 148.8/335 (44.4%). Round one averaged 334.8/335 (99.9%). That collapse is the actual headline here, not a modest time increase. Going to full 18-pass protection didn't mostly slow reconstruction down. It mostly made it wrong.

## The deciding factor: the checksum

All five had to figure out the 8-digit hex checksum appended to every successful output. That's where they split:

- **pass08, pass09, pass10** all found the real algorithm: 32-bit FNV-1a (offset basis 2166136261, prime 16777619). pass09 and pass10 got there by brute-forcing standard hash algorithms against several real outputs. pass08 got there by writing its own CIL disassembler and reading the `InitializeCache` method byte by byte. Two different methods landing on the same answer.
- **pass11 and pass12** never solved it and submitted explicitly labeled placeholders instead.

There's a shared trap worth naming. The IL visibly calls `SHA256.Create()`/`ComputeHash`, which is actually an unrelated anti-tamper guard from the `integrity-check` and `mhop-predicates` passes, nothing to do with the checksum. At least three of the five (pass10, pass11, pass12) used that as their starting hypothesis: "there's SHA256 in here, the checksum is probably SHA256-based." pass09 and pass10 chased that lead until it dead-ended, then switched strategy and brute-forced the checksum statistically instead. pass08 proved statically, before ever guessing, that the SHA256 call only feeds a branch condition and never touches the return value, and skipped the trap entirely. pass11 and pass12 never found their way out of it.

**This wasn't designed.** The MHOP pass uses SHA256 for a control-flow guard, and the integrity-check pass uses it for self-verification, each for its own independent purpose. Combined, they happened to create a plausible-looking but wrong clue: "this binary uses SHA256, so the checksum probably does too." It's a side effect that only shows up when the two passes are stacked together, not something either one produces alone.

## Another split: the warm preset

pass09, pass10, and pass11 all guessed `warm` was multiplicative scaling (roughly R×1.06, G×1.03, B×0.82). It's actually **additive**: R+12, G+3, B-9, each clamped. Only pass08 got this right. pass09 and pass10 both noted, with appropriately low confidence, that their one test sample happened to divide evenly by 100, so the multiplicative hypothesis was never actually disproven even though it was wrong. That's a structural weakness of differential testing (change one value, compare outputs): pick the wrong input and two different hypotheses can produce the same result, so a wrong guess never gets caught.

## Why pass08 pulled so far ahead

pass08's whole approach differed from the other four. Rather than trust REA's `inspect-managed-members` output at face value, it parsed the PE/CLI metadata directly and **wrote its own disassembler from scratch**, then **cross-validated that disassembler's output against REA's own opcode counts across all 43 methods**, catching three real bugs in its own opcode table in the process. With byte-exact disassembly in hand, it folded the MBA obfuscation pattern (`(A^B)+2*(A&B) == A+B`) down to plain constants and reduced the flattened control flow back to linear logic. Direct executions were then used only to confirm answers it was already confident in (it went one execution over its budget of 8, and reported that honestly), rather than to guess at them in the first place. Guesswork made up a much smaller share of its process than for the other four.

The other four leaned on REA's summarized call-graph and member data, then used direct execution as **differential testing** to work out the actual arithmetic. This round showed clearly how that approach breaks down when the execution budget runs out, or when the test sample happens to be ambiguous (as with the warm preset and the checksum).

## A side finding: pass12's corpus score understates what it actually understood

Separately from never cracking the checksum, pass12's own script didn't account for Python's text-mode newline translation on Windows and explicitly wrote `\r\n` on top of it, corrupting every line of output into `\r\r\n`. pass08 made the exact same mistake early on and caught it itself. That one bug alone fails every single corpus comparison, independent of whether the checksum was right. Looking at the raw logs, pass12's `--help` output text is actually identical to the real binary's; only the line ending differs. A corpus score of 0/335 doesn't mean pass12 understood nothing. Its structural understanding was largely correct; one small platform detail wiped out the entire score. **Corpus pass rate and actual understanding aren't the same thing.**

## Self-reported confidence

The earlier experiment (pass03-05) had a case where a subagent reported "very high confidence" and was actually wrong. This round showed the opposite pattern: all five explicitly flagged the parts they were guessing at (the warm formula, the checksum, a couple of error strings) as low confidence, and those were exactly the parts that turned out wrong. Self-reported confidence tracked actual accuracy well this time. The overconfidence problem didn't recur.

## Limitations (honestly)

- **Isolation is trust-based.** Each agent was firmly instructed not to look outside its working directory, and each directory was inspected afterward for signs that it had, with nothing found. That's not OS-level sandboxing, though. The fact that all five showed different methodologies and different mistakes (different combinations of right/wrong answers, different bugs) is circumstantial evidence against copying or outside access, not proof.
- **N=5 is still small.** This round is just as statistically thin as the last one.
- **The unprotected baseline is still N=2, and still marked as a lower bound.** It wasn't re-measured for this round.
- **There's no guarantee the agent model/version matches round one (pass03-07).** Time passed between the two rounds, and which model analyzed which pass wasn't recorded. Treat time and accuracy numbers as "a repeat of comparable analysis ability," not a controlled rerun, with that caveat in mind.
- **The "SHA256 decoy" effect around the checksum is a post-hoc explanation, not a causal claim proven by a controlled experiment.** Three subagents falling into the same trap is strong circumstantial evidence, but this was never compared against a control build with the SHA256 calls removed.
