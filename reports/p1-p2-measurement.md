# Dysphasia protection MVP, first measurement: P1 (renaming), P2 (string encoding), P3 (control flow flattening)

2026-10-14. Implementation of `tools/obfuscator` (`dysob`) and results of applying it to PixelTone.exe

## Conclusion

Actually implemented the "renaming MVP" and "string/branch flow transformation" stages from `obfuscator-plan.md` (`tools/obfuscator`, a CLI called `dysob` built on Mono.Cecil 0.11.6), applied it to the existing baseline `PixelTone.exe`, and measured the effect two ways: (1) re-confirmed behavior preservation byte for byte against the existing 335-case corpus, (2) re-analyzed the protected build with REA from the same commit (`500e323...`) to see how the static artifacts actually changed.

**P1 (renaming) alone changes almost nothing in REA's static output.** Only the names change to hashes: the 11 strings, all numeric constants, branch structure, and `call_edge_count` remain completely identical to the baseline. **Adding P2 (string encoding) drops the `user_strings` count REA reports from 11 to 0**: the usage text, preset names, and error messages disappear from the static string table. **Adding P3 (control flow flattening) turns the branches of the 4 methods with no exception handlers into a single switch dispatch loop each**: the anchor count for the method corresponding to `ClampByte` goes from 4 (`blt.s`, `ldc.i4 255`, `bgt.s`, `ldc.i4 255`) to 25, and REA's anchor summary never shows the contents of the `switch`'s jump table, so which state number corresponds to which original branch can't be told from the anchors alone. The numeric constants themselves (77/150/29, etc.) are still exposed.

**Revision (v2):** the first implementation (`v1`, all archived below) built a byte array from scratch at the call site for every string, which grew the file size by up to +70% over baseline, well past the plan's 20% budget. Rewriting `StringPass` so that all strings are packed into one shared blob and stored with `FieldRVA` (the same technique `csc` uses for large array literals) brought that down to **+20%**. See the "File size improvement" section below. The "P1+P2+P3" figures in this report are all on the v2 basis. **Independent analysts' reconstruction time and accuracy were measured in the [pass03-07 experiment](pass03-blind-reconstruction.md), across 5 runs (meeting the plan's target of N=5)**: mean 1,242.4s, standard deviation 113.1s, 2.18x higher than the unprotected baseline mean (569.1s, a lower bound), with all five observations consistently higher. Accuracy, however, had 2 of the 5 runs (40%) fail at the same NBSP whitespace trap, and one subagent (pass05) was found to have made a self-confidence claim that didn't match its actual result. See the "Quality control" section of that report. **P4 (per-build variation) was confirmed with an actual measurement using the `--seed` CLI option**: changing only the seed on the same source changes all 7 name-mapping entries while behavior stays identical at 335/335. See "P4 measurement" below.

## Implementation

| Component | Description |
|---|---|
| Tool | `tools/obfuscator` (.NET 10 console app, `dysob`), Mono.Cecil 0.11.6 |
| Commands | `inspect`, `plan`, `protect`, `verify` (`benchmark`/`report` from the plan's draft CLI don't exist yet) |
| P0 (`inspect`) | Detects PE/CLI, whether an Authenticode certificate is present (manual PE header parsing), whether a strong-name signature/public key is present, an accompanying PDB file, single-file bundle markers. If any of these is present, `protect` refuses to run |
| P1 (`protect`, `rename` pass) | Deterministically replaces non-public (not externally exposed) type and method names with the first 5 bytes of the SHA-256 of `seed+original full name`. Constructors, compiler-generated members, members with public/family visibility, virtual/abstract members, explicit interface implementations, and members with interop attributes are automatically excluded |
| P2 (`protect`, `string-encode` pass) | **v2:** XOR-encodes every distinct string literal and merges them into a single byte blob, stores it with `FieldRVA`, and restores the `byte[]` once in the type initializer (`.cctor`) with `RuntimeHelpers.InitializeArray`. Each `ldstr` call site only pushes three integers `(offset, length, key)` and calls the shared decoder (v1 built the byte array from scratch at every call site; see "File size improvement" below) |
| P3 (`protect`, `control-flow` pass) | For methods with no exception handler only: analyzes basic blocks and flattens them into a `switch`-based dispatch loop. State IDs are a 0..N-1 permutation shuffled deterministically from the seed, so physical layout order no longer matches execution order. `Main` is automatically excluded because it has an exception handler (the "never apply globally" principle is implemented as a safety condition, not an exclusion list) |
| Mapping storage | `artifacts/mapping/*.mapping.json`: records every original/replacement name pair in a location separate from the output directory (`artifacts/protected-*`) |
| Verification | `dysob verify`: reads the same corpus file used by `scripts/evaluate.py` (`logs/evaluation01/corpus.json`) and does a full comparison of stdout/stderr bytes and exit codes |

### Bugs found and fixed during implementation (recorded transparently)

1. **`InvalidProgramException`.** Replacing string literals with byte-array construction code grew the method bodies, and the offsets of existing 1-byte relative (short-form) branches like `brfalse.s`/`beq.s`/`bne.un.s` exceeded the SByte range. Fixed by using `Mono.Cecil.Rocks.MethodBodyRocks.SimplifyMacros()` to widen all branches to the 4-byte long form before processing.
2. **`MethodAccessException`.** The injected string decoder was declared `private`, so other types (the original `PixelTone` type) couldn't call it. Fixed by changing it to `internal` (`MethodAttributes.Assembly`).
3. **The MVID stayed unchanged even in the protected build.** Found while checking the re-identification path: Mono.Cecil preserves the original module's MVID by default (see "Interpretation" below). Fixed by generating a new MVID deterministically from `policy.Seed + policyHash + original SHA-256` at the end of `protect`.

All three surfaced during actual run/re-identification checks after running `dysob protect`, and passed re-verification after the fix. P3 (control flow flattening) passed 335/335 on its very first run after implementation; no additional bugs.

4. **(v2 improvement, not a bug) File size +70%.** Not a bug, but it violated the plan's performance budget, so it's recorded the same way. `StringPass` v1 built a byte array from scratch at each call site with `dup`+`ldc.i4`+`ldc.i4`+`stelem.i1`, costing roughly 12x the IL per byte. v2 merges all strings into a single `FieldRVA` blob so the decoder only slices shared data; the per-call-site cost dropped to roughly "push 3 integers + call" regardless of byte count. After rebuilding, it passed 335/335 again on the first attempt. All "P1+P2"/"P1+P2+P3" figures in this report are on the v2 basis (both were regenerated with the new `StringPass`); the v1 artifacts are preserved as-is at `artifacts/protected-p1p2-v1/` and `artifacts/protected-p1p2p3-v1/` (and the corresponding `logs/*-v1/`), because pass03 of the already-published [pass03-07 experiment](pass03-blind-reconstruction.md) targeted `protected-p1p2p3-v1`, while pass04-07 targeted v2.

## Results of applying it

| | baseline | P1 only (`pixel-tone.p1.json`) | P1+P2 (`pixel-tone.p1p2.json`) | P1+P2+P3 (`pixel-tone.p1p2p3.json`) |
|---|---|---|---|---|
| SHA-256 | `b479f514...5a29c95` | `0f88a25b...2febce17` | `0087205b...` | `b9029acf...bb370a72a1c` |
| MVID | `9d8850e2-...-b19bab20a9c1` | `a9a033ad-...-f305aa21d63e` (newly issued) | `e8b14d26-...-b94c329e95d6` (newly issued) | `7cf7801a-...-2a70-668ba128cada` (newly issued) |
| File size | 5,120 bytes | 5,120 bytes (no change) | **5,632 bytes (+10%, v2)** | **6,144 bytes (+20%, v2)** |
| Type name | `Dysphasia.Fixture.PixelTone` | `Teeef425ae1` | `Teeef425ae1` (+ 1 nested value type for blob storage) | `Teeef425ae1` (+ 1 nested value type for blob storage) |
| Method names | 6 meaningful names: `ClampByte`, `AdjustChannel`, etc. | 6 hashes like `m_4e09ee408f` | same, plus a decoder and `.cctor` (restores blob to `byte[]`) | same, plus a decoder and `.cctor` (restores blob to `byte[]`) |
| Flattened methods | - | - | - | 4 (corresponding to `ClampByte`, `ApplyPreset`, `Fingerprint`, `ReadInt`); `Main` (has an exception handler) and `AdjustChannel` (only 1 basic block) are excluded |
| Mapping file | - | `artifacts/mapping/PixelTone.0f88a25b3bc1.mapping.json` | `artifacts/mapping/PixelTone.0087205bf6b0.mapping.json` | `artifacts/mapping/PixelTone.b9029acfbf99.mapping.json` |

The seed is fixed at `20261014` for all four policies (the plan's "reproducibility" requirement: the same input and policy produce the same output names). The reason P1+P2+P3 is larger than P1+P2 (6,144 vs 5,632) is almost entirely P3's dispatch overhead; the cost of the P2 (string) piece itself is nearly identical between the two builds (a shared 235-byte blob plus 11 call sites). **The P1+P2/P1+P2+P3 figures in the table above are all on the v2 basis (after the `StringPass` rewrite).** v1 (the first implementation: P1+P2 at 8,192 bytes/+60%, P1+P2+P3 at 8,704 bytes/+70%) is preserved as-is at `artifacts/protected-p1p2-v1/` and `artifacts/protected-p1p2p3-v1/` respectively.

## Behavior preservation verification

Reused the entire existing `evaluation01` corpus (335 cases, covering boundary values, random values, parser edge cases, argument-count errors, and help) with `dysob verify`.

| | Passed | Total | Result file |
|---|---:|---:|---|
| P1 only | 335 | 335 | `logs/verify-p1/summary.json` |
| P1+P2 | 335 | 335 | `logs/verify-p1p2/summary.json` |
| P1+P2+P3 | 335 | 335 | `logs/verify-p1p2p3/summary.json` |

All three protected builds matched the original exactly in stdout bytes (including CRLF), stderr bytes, and exit codes. In particular, the entry point method (`Main`) also had its name changed, and this caused no problems, because the CLR locates the entry point by the metadata token in the CLI header, not by name; this measurement confirms that assumption. Control flow flattening rewrote every branch that leads to negative/boundary saturation (including the mono/warm presets, both ends of the range, and parser boundaries), and all 335 cases still matched, meaning the state transitions landed correctly on every branch path actually taken by the methods corresponding to `ClampByte`/`ApplyPreset`/`Fingerprint`/`ReadInt`.

## REA re-analysis results

Re-ran `inspect-managed-artifact`/`inspect-managed-members` against each protected build with the same REA commit (`500e32399a3bc827e17fb4adaa97db3bc0df29b5`, a local build).

| Observation | baseline | P1 only | P1+P2 | P1+P2+P3 |
|---|---|---|---|---|
| Type/method names | Meaningful (`ClampByte`, etc.) | All replaced with hashes | Same | Same |
| `user_strings` count | 11 | **11 (no change)** | **0** | 0 |
| IL size/instruction count of the method corresponding to `ApplyPreset` | 138 bytes / 84 instructions | 138 bytes / 84 instructions (only tokens differ) | 332 bytes / 90 instructions | **432 bytes / 108 instructions** |
| IL size/instruction count of the method corresponding to `Main` | 345 bytes / 142 instructions | 345/142 (no change) | (not measured, v1 material archived) | **728 bytes / 172 instructions** |
| Anchor count for the method corresponding to `ClampByte` | 4 | 4 (no change) | 4 (no change) | **25** |
| `call_edge_count` | 32 | 32 | 47 | 47 |
| `coverage.state` | `complete` | `complete` | `complete` | `complete` |

Evidence (all v2): `logs/protected-p1/` (evidence `ev_d47ed43b...`, `ev_55df40c6...`), `logs/protected-p1p2/` (evidence `ev_904ca516...`, `ev_84563d79...`), `logs/protected-p1p2p3/` (evidence `ev_2125304e...`, `ev_b0a6513b...`). The v1 REA records are preserved at `logs/protected-p1p2-v1/`, `logs/protected-p1p2p3-v1/`.

The IL size of the method corresponding to `Main` **dropped 78%** from v1 (3,308 bytes, P1+P2+P3 basis) to v2 (728 bytes). Since v1 had inlined all the longest strings (such as the 83-character usage text) directly inside Main, it's also the method that shrank the most once they moved into the shared blob.

### Interpretation

- **P1 alone only erases "name-based clues."** The constants (`77`, `150`, `29`, `12`, `9`, `2166136261`, `16777619`, the range's upper/lower bounds), the branch structure, and the call graph all remain unchanged, so `call_edge_count` stays identical too. The hypothesis `obfuscator-plan.md` already noted in the P1 row ("may still be mappable after renaming if constants and structure stay the same") is confirmed by this measurement: in this sample, erasing only the names still lets you nearly fully re-identify the method corresponding to `ApplyPreset` just from the `mono`/`warm` branches and the `77/150/29` weights.
- **Adding P2 completely blocks static string-table lookups.** REA's `user_strings` dropping to 0 means it shuts down the kind of analysis that reads the usage text to immediately learn the CLI contract, a shortcut two reconstructors actually used in the earlier experiment.
- **But numeric constants still appear in the anchor list.** Even with the shared-blob approach (v2), the method corresponding to `ApplyPreset` still exposes the constants themselves (`77`, `150`, `29`); new blob offset/length/key integers (`ldc.i4 <offset>`, `ldc.i4 <length>`, `ldc.i4 <key>`) are simply mixed in among them. In other words, this **blocks "string grepping" but still leaves it exposed to the "decode the CIL directly and read the anchors" analysis that pass01/pass02 actually did in the earlier experiment**. All that was measured is that the increased instruction count (84 to 90, on the P1+P2 basis) means more noise for the analyst to filter out; whether this actually increases real reconstruction time needs to be measured separately (see Limitations below).
- **Found and fixed an MVID re-identification path.** In the first implementation, the MVIDs of all three builds (baseline/P1/P1+P2) were identical, all `9d8850e2-7741-4869-8f48-b19bab20a9c1`, because Mono.Cecil preserves the original module's MVID by default. This was exactly the re-identification path `obfuscator-plan.md` had flagged as a concern ("also check whether re-identification is possible via evidence tied to the new hash/MVID"): an analyst who already knew the baseline could immediately tell "this is a protected version of that PixelTone" purely from an MVID match, without looking at a single name or string. Fixed in `Protector.cs` to issue a new MVID deterministically from `policy.Seed + policyHash + original SHA-256`; the figures in the table above already reflect the fixed, final build (P1: `a9a033ad-...`, P1+P2: `e8b14d26-...`, both different from the original).
- **File size improvement: +70% to +20%.** `StringPass` v1 unrolled the byte array in place for every string with `dup`+`ldc.i4`+`ldc.i4`+`stelem.i1` instructions, which was expensive per byte. v2 merges all 11 distinct strings into a single 235-byte blob stored with `FieldRVA` (the same technique `csc` uses for large array literals), and restores the `byte[]` once in the type initializer with `RuntimeHelpers.InitializeArray`. Call sites now just push 3 integers (`offset`, `length`, `key`) and call the shared decoder: a fixed cost per call site regardless of byte count. Result: baseline 5,120 bytes to 6,144 bytes, exactly **+20%**, landing almost exactly at the boundary of the initial budget `obfuscator-plan.md` proposed ("within 20%"). The 335/335 re-verification passed on the first attempt after the rewrite. The flattening (P3) overhead (dispatch preprocessing plus state-transition stubs) still remains, though; reducing it further would require work on the P3 side.
- **(found in v1, still present in v2) `SimplifyMacros()` also grows unrelated methods.** `StringPass` unconditionally calls `SimplifyMacros()` even on methods with no strings, widening every short-form opcode (`ldarg.1`, `ldc.i4.s`, etc.) to its long form. The method corresponding to `AdjustChannel` grew from 26 to 38 bytes even though no pass touched it directly (true in both v1 and v2). It has no effect on behavior, but it's an unnecessary size cost, and it hasn't been fixed yet.
- **Control flow flattening hides branch meaning at the anchor level.** The method corresponding to `ClampByte` originally had just 4 anchors (`blt.s`, `ldc.i4 255`, `bgt.s`, `ldc.i4 255`), from which the intent "clamp to 0..255" was nearly readable as-is. After flattening, the anchor count rises to 25, most of which are `ldc.i4 <state number>`+`stloc 0`+`br` (state transitions back to the dispatcher), so every branch looks the same shape. REA's anchor summary doesn't show the `switch` instruction's own jump table (which state number goes to which block), so the fact that "reaching state 5 returns 255" can't be learned from the anchors alone; it requires decoding the full instruction stream directly and tracing the jump table. This extends the work pass01/pass02 already did in the earlier experiment (decoding the whole CIL because the REA anchors alone weren't enough) to also require "tracing back the state numbers," not just "reading." How much this actually increases real reconstruction time, though, can only be confirmed by an independent-analyst experiment (see Limitations below).

## P4 (per-build variation) measurement

Every protected build so far used only the single seed `20261014`. P4 ("per-build variation and mapping management") had been implemented but never actually verified to confirm that different seeds produce different results. Added a `--seed <n>|random` option to `dysob protect` (specifying the seed at build time, instead of hand-editing the policy file, is itself the substance of P4's goal of making "variation a single CLI flag instead of tedious manual work per build"), and built a second build (`artifacts/protected-p1p2p3-variant-b/`) with the same policy (`pixel-tone.p1p2p3.json`) but the seed changed to `99999999`.

| | seed `20261014` | seed `99999999` |
|---|---|---|
| Type name | `Teeef425ae1` | `T26b6ff3de9` |
| `ClampByte` | `m_4e09ee408f` | `m_7e0c14dddd` |
| `AdjustChannel` | `m_b2ece2c34c` | `m_010881d867` |
| `ApplyPreset` | `m_b3c4f3c803` | `m_a19f5783d9` |
| `Fingerprint` | `m_0481f84d57` | `m_06a1a97363` |
| `ReadInt` | `m_22283830b7` | `m_44e4ba3258` |
| `Main` | `m_ec38e2401a` | `m_f381559a37` |
| 335-case corpus verification | 335/335 | **335/335** |

None of the 7 entries overlap at all: even someone who fully analyzed the seed-`20261014` build can't reuse those results (name mappings, string-blob bytes, flattening state IDs) on the seed-`99999999` build. At the same time, both builds are 335/335, fully identical in behavior, confirming that P4's core claim, "varies per build but functionality doesn't change," actually holds.

### Mapping repository: cross-build reverse lookup

The flip side of "variation" is support: if names differ per build, you need to know which build a name like `m_7e0c14dddd` in a crash report belonged to, and to what. Added `mapping-index`/`resolve` commands to `MappingRepository.cs`:

```
dysob mapping-index --mapping-dir artifacts/mapping --out artifacts/mapping-index.json
dysob resolve m_7e0c14dddd --mapping-dir artifacts/mapping --mvid 678c369a-75aa-0d94-2942-4feac12b27f3
# → {"obfuscatedName":"m_7e0c14dddd","originalName":"Dysphasia.Fixture.PixelTone::ClampByte","mappingFile":"...dbb0ecf23028.mapping.json"}
```

Actually indexed the 10 mapping files accumulated under `artifacts/mapping/` in this session (various policy/seed combinations), and confirmed two lookup cases (by MVID, by SHA-256) plus a case of "failing cleanly when no matching build identifier exists." It narrows down "which build" first using the `outputSha256`/`outputMvid` already recorded in each mapping file, then looks up the name only within that build, meaning reverse mapping is possible using only what a crash report typically carries (a module hash or an MVID).

With this, both halves of P4 (per-build variation plus mapping management) have been through actual measurement.

## Unmeasured items and limitations

- **XOR encoding is not a cryptographic secret** (exactly as the plan already stated). The decoder logic and the key-generation method sit in plaintext in the same assembly, so reading just the one decoder method with a disassembler reveals the decryption formula within minutes. This pass only blocks "static string table/grepping" at this level.
- The sample is still just the single `PixelTone`, still a small, simple .NET Framework console program.
- The P0 (signature rejection) logic is implemented but was not tested against a signed input, because `PixelTone.exe` isn't signed.
- **P3 was implemented only under the condition that it doesn't touch methods with exception handlers.** In this sample, that condition happened to result in "the most complex method (`Main`) gets automatically excluded," but in general, flattening methods with exception handlers in more complex programs would require separately handling state transitions that cross try/catch boundaries; that's outside this implementation's scope. Whether the same algorithm is safe on more complex methods with loops (nested branches, multiple `switch`es) was only confirmed within the scope of these 5 methods.
- **P4 was confirmed with actual measurement for both halves, via the `--seed` flag plus the `mapping-index`/`resolve` commands** (see "P4 measurement" and "Mapping repository" above). However, `resolve` doesn't handle the possibility that more than one build matches the same name (e.g. when different sources are protected with the same seed); it only returns the first match. Using this in real operation would require handling "choosing among multiple results."
- The exact composition of the `call_edge_count` 32 to 46 change (beyond the 13 decoder calls) wasn't cross-checked in detail; only the total change is reported.
- **Independent-analyst reconstruction time** met the plan's target (N=5) [pass03-07 experiment](pass03-blind-reconstruction.md): mean 1,242.4s (standard deviation 113.1s), 2.18x the unprotected mean (569.1s, a lower bound). All five observations were consistently higher, so the direction is statistically more trustworthy than it would be at N=1-2. However, only 4 of the 5 (pass04-07) looked at the same build (v2) (pass03 saw v1), and "condition order was not randomized"; see the "Limitations" section of that report. Accuracy had 2 of the 5 runs fail at the same point (NBSP), and also turned up a case showing that a subagent's own self-report shouldn't be trusted without verification (a tool-guard bypass, a mistaken confidence claim); see the "Quality control" section.

## Evidence paths

- Tool source: `tools/obfuscator/`
- Policy files: `tools/obfuscator/policies/pixel-tone.p1.json`, `pixel-tone.p1p2.json`, `pixel-tone.p1p2p3.json`
- Protected builds (current, v2): `artifacts/protected-p1/`, `artifacts/protected-p1p2/`, `artifacts/protected-p1p2p3/` (each a `PixelTone.exe`)
- Protected builds (archived, v1, before the `StringPass` rewrite; pass03 of the [pass03-07 experiment](pass03-blind-reconstruction.md) targeted `protected-p1p2p3-v1`): `artifacts/protected-p1p2-v1/`, `artifacts/protected-p1p2p3-v1/`
- Second seed build for the P4 measurement: `artifacts/protected-p1p2p3-variant-b/`, `logs/verify-p1p2p3-variant-b/`
- Mapping: `artifacts/mapping/`, index: `artifacts/mapping-index.json` (`tools/obfuscator/MappingRepository.cs`)
- Raw REA logs: `logs/protected-p1/`, `logs/protected-p1p2/`, `logs/protected-p1p2p3/` (v1: `logs/protected-p1p2-v1/`, `logs/protected-p1p2p3-v1/`)
- Behavior preservation verification: `logs/verify-p1/`, `logs/verify-p1p2/`, `logs/verify-p1p2p3/` (v1: `logs/verify-p1p2-v1/`, `logs/verify-p1p2p3-v1/`)
- See also: [experiment report](experiment-report.md), [obfuscation tool build plan](obfuscator-plan.md), [independent-analyst reconstruction experiment (pass03-07, N=5)](pass03-blind-reconstruction.md)
