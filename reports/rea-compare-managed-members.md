# Targeting REA's own cross-build comparison tool directly: `compare-managed-members`

## Background

So far, REA measurement has been done almost entirely with `inspect-managed-members` (the command
that shows the member list of a **single** build). But REA also provides `compare-managed-members`,
a **dedicated command that compares two builds to decide "are these different builds of the same
program?"**. It's built for questions like patch diffs, update verification, or "did these two files
come from the same source." This is a measurement that targets, for the first time in this project,
REA's own cross-build identification ability itself.

This command doesn't just go by name. Its own official description states: "Compare managed PE/CLI
member inventories by exact declared type, name, and signature; **names alone never form a match**."
Internally it attempts matching by four criteria: `exact_il_signature` (normalized IL hash match),
`exact_signature` (declared signature match), `structural_method_shape` (structural shape match), and
`field_signature` (field signature match). If all four fail, the member is classified as "unmatched"
(`removed` on one side, `added` on the other).

## Method

`compare-managed-members` was already included in the allowlist (the safety guard in
`scripts/rea-run.mjs` that permits only 4 static-analysis commands), so it was used as is, with no
separate changes:

```powershell
node scripts/rea-run.mjs compare-managed-members compare-members `
  compare-managed-members artifacts/baseline/PixelTone.exe artifacts/protected-p1p2p3p5p6p7/PixelTone.exe --json
```

Compared: `artifacts/baseline/PixelTone.exe` (unprotected, 6 methods, 0 fields) vs.
`artifacts/protected-p1p2p3p5p6p7/PixelTone.exe` (all 18 passes applied, 43 methods, 8 fields).

## Findings

REA's own comparison result:

```json
"summary":  { "unchanged": 0, "changed": 0, "added": 51, "removed": 6, "unknown": 0 },
"matching": { "exact_il_signature": 0, "exact_signature": 0,
              "structural_method_shape": 0, "field_signature": 0,
              "ambiguous": 0, "unmatched": 57 }
```

All 57 compared items (49 methods + 8 fields) are "unmatched": the baseline's 6 methods are all
classified as `removed`, and the protected build's 43 methods and 8 fields are all classified as
`added`. Both `unchanged` and `changed` are 0. In other words, from the perspective of REA's
cross-build identification algorithm, it **cannot tell at all** that these two files are two builds
of the same program. It reports them as though they were two completely unrelated programs.

**An interesting detail**: the `signature_sha256` of `ClampByte` (baseline) and its protected
counterpart (the deceptive-naming pass's replacement name, which also carries Cyrillic homoglyphs
per `DeceptiveNameGenerator.cs`'s a/e/o/p/c/x to а/е/о/р/с/х mapping; REA's own JSON output in this
environment fails to encode those Cyrillic codepoints correctly, rendering them as replacement
characters both in the original captured log and in a fresh re-run, so the exact string isn't
quoted here) **happen to match**,
because both have the signature `int(int)`. But the `normalized_il_sha256` differs (`18cec568...`
vs. `79d97eb0...`, naturally, since control-flow flattening, MBA, and variable splitting actually
changed the body). REA correctly judged this case as "unmatched" too, meaning this result isn't "a
coincidence where the signature hash luck also broke in the same direction," but **a correct
judgment that comes from the IL body itself actually having changed**. This isn't a false negative
from a sloppy REA comparison algorithm. It's REA correctly confirming that the protection passes
actually changed the body.

As a side check, `inspect-managed-native-boundaries` was also run against the same build, to confirm
that the design choice this project has followed so far, implementing anti-debugging purely in
managed code (`Debugger.IsAttached`, `Environment.FailFast`) with no P/Invoke, was actually upheld:
`pinvoke_imports: []`, `module_refs: []`, `native_implementations: []`, `cli_native.il_only: true`.
No native boundary at all.

## Pass-by-pass incremental measurement: at which pass does it break

The results above are about a single build with "all 18 passes applied." An earlier draft only
**guessed, without measuring**, that "probably even `rename` alone would be close to 0 from an early
stage." Actually running `compare-managed-members` against the existing incremental builds that were
already on hand (`artifacts/protected-p1/` through `protected-p1p2p3p5p6p7/`, all already verified at
335/335) showed that guess was **wrong**:

| Build | Passes | Methods (original to protected) | Fields | unchanged | changed | added/removed |
|---|---|---|---|---|---|---|
| `protected-p1` | `rename` | 6 → 6 | 0 → 0 | **3** | **3** | 0 / 0 |
| `protected-p1p2` | `rename, string-encode` | 6 → 8 | 0 → 2 | 0 | 0 | 10 / 6 |
| `protected-p1p2p3` | `rename, control-flow, string-encode` | 6 → 8 | 0 → 2 | 0 | 0 | 10 / 6 |
| `protected-p1p2p3p5` | `+ hide-bcl-calls` | 6 → 11 | 0 → 4 | 0 | 0 | 15 / 6 |
| `protected-p1p2p3p5p6` | `+ opaque-predicates` | 6 → 11 | 0 → 4 | 0 | 0 | 15 / 6 |
| `protected-p1p2p3p5p6p7` | all 18 passes | 6 → 43 | 0 → 8 | 0 | 0 | 51 / 6 |

**`rename` alone doesn't fool REA's comparison algorithm at all**: all 6 original methods found
their exact counterpart in the protected build (0 added/removed). Breaking down how the matches were
found, by method:

```
unchanged  ClampByte      -> m_4e09ee408f   (exact-il-signature, IL bytes are exactly identical)
unchanged  AdjustChannel  -> m_b2ece2c34c   (exact-il-signature)
unchanged  Fingerprint    -> m_0481f84d57   (exact-il-signature)
changed    ApplyPreset    -> m_b3c4f3c803   (structural-method-shape, includes a different method call)
changed    ReadInt        -> m_22283830b7   (structural-method-shape)
changed    Main           -> m_ec38e2401a   (structural-method-shape)
```

For "leaf" methods that don't call other methods (`ClampByte`, `AdjustChannel`, `Fingerprint`),
renaming has no effect at all on the IL bytes themselves (method calls are keyed by metadata token,
not by name), so they are **byte-for-byte identical** and get caught directly by
`exact-il-signature`. For methods that call other methods (`ApplyPreset`, `ReadInt`, `Main`), the
called target's token changes so the IL differs, but REA still finds the exact same method by
call-graph shape (`structural-method-shape`), meaning **renaming alone doesn't fool this REA
comparison tool at all.**

**The moment `string-encode` (P2) joins, it drops to 0/N**: starting from `protected-p1p2` through
the end, every build has unchanged/changed at 0, all unmatched. Interesting point: even `ClampByte`,
`AdjustChannel`, and `Fingerprint`, which don't reference strings directly, all flip to "removed"
too. The exact same three methods that matched precisely under P1 lose their match the instant P2
joins. Why this happens (whether inserting the blob-initialization method changes the relative
structure of the whole type, or whether REA's matching is global) can't be confirmed since it's REA's
internal implementation. **Only the observed fact is honestly recorded here**: for this particular
comparison tool, string encoding (and the new methods/fields it inserts) turned out to be the
decisive turning point for "no longer recognizable as the same program," more so than renaming
itself.

## Verification

- This measurement itself is the result of calling REA's own official static-analysis commands
  (`compare-managed-members`, `inspect-managed-native-boundaries`) directly, against builds whose
  corpus behavior preservation was already verified via `logs/verify-p1p2p3p5p6p7/summary.json`
  (335/335). No new build was made, so no additional behavior verification was needed.
- Raw results: [`logs/compare-managed-members/compare-members.stdout.json`](../logs/compare-managed-members/compare-members.stdout.json),
  [`logs/compare-managed-members/native-boundaries.stdout.json`](../logs/compare-managed-members/native-boundaries.stdout.json);
  the pass-by-pass incremental results are at
  `logs/compare-managed-members/incremental-{p1,p1p2,p1p2p3,p1p2p3p5,p1p2p3p5p6,p1p2p3p5p6p7}.stdout.json`.
- Used `scripts/rea-run.mjs`'s existing safety guard as is (an allowlist that permits only
  static-analysis commands, recording `target_execution: false`). That guard was not extended or
  bypassed for this measurement.

## Limitations (honestly)

- **REA's own JSON output mangles the Cyrillic homoglyph characters in this environment**: both
  `compare-managed-members` and a fresh `inspect-managed-members` run against the same binary emit
  U+FFFD replacement characters in place of the actual Cyrillic codepoints inside the deceptive-naming
  pass's replacement identifiers (confirmed by re-running the command directly and inspecting the raw
  JSON bytes, not just a terminal-display issue). The underlying C# implementation
  (`tools/obfuscator/DeceptiveNameGenerator.cs`) deterministically maps a/e/o/p/c/x to а/е/о/р/с/х, so
  the actual identifiers are well-defined, but this project cannot currently quote the exact string
  REA reports for them, since REA's own output doesn't preserve it correctly on this host. Worth
  investigating separately whether this is a REA bug, a Node.js console-encoding default on this
  Windows/non-English-locale machine, or something specific to this binary.
- **This is still just metadata comparison**: there's a difference between `compare-managed-members`
  answering "I can't tell if it's the same program" and a human or another AI agent actually reading
  the IL line by line and recognizing "this is the same algorithm." This measurement is evidence that
  **one specific REA cross-build identification command** was defeated, not evidence that every
  reasoning path REA has was blocked.
- **(Resolved) The single comparison pair limitation**: initially only one pair (the build with all
  18 passes applied) was measured, with the guess, left unverified, that "probably even `rename`
  alone would be close to 0 from an early stage." The "Pass-by-pass incremental measurement" section
  above actually ran it against all 6 existing incremental builds and **confirmed that guess was
  wrong**: `rename` alone doesn't fool REA's matching at all (0 unmatched), and the moment
  `string-encode` joins, everything abruptly flips to unmatched. This honestly records that the
  hypothesis formed before writing this report differed from the measured result, another instance
  of a lesson this project has learned repeatedly: a hypothesis formed without measuring can be
  wrong.
- **`compare-managed-members` may not be REA's only cross-build tool**: other comparison commands
  such as `compare` (general-purpose) and `compare-process-captures` were not measured this time. All
  of those are out of scope.
