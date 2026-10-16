# Changelog

No planned releases here, just milestones as they got verified: 335-case
corpus, `ilverify`, determinism, a before/after REA measurement, in that
order, before anything got folded into the main build. Dates are rough
session boundaries, not version tags.

## Baseline and MVP

- Unprotected .NET baseline (`fixture/PixelTone.cs`, `artifacts/baseline/`)
  and the first REA passes against it.
- Obfuscation engine MVP: identifier renaming (P1), control-flow flattening
  (P3), string encoding (P2). First combined measurement:
  [`reports/p1-p2-measurement.md`](reports/p1-p2-measurement.md).
- Independent reconstruction experiment, N=5: protected builds took 2.18x
  longer to reconstruct than the baseline, with 2/5 attempts failing on the
  same whitespace edge case. See
  [`reports/pass03-blind-reconstruction.md`](reports/pass03-blind-reconstruction.md).
- Native Windows track established (C port, IDA/Hex-Rays baseline, REA/IDA
  bridge). See [`reports/native-track-baseline.md`](reports/native-track-baseline.md).
- Per-build variation plus a mapping repository for resolving obfuscated
  names back from crash symbols (`dysob mapping-index` / `resolve`).

## Incremental hardening (18 .NET passes, 5 native variants)

Added one at a time, each with its own report and REA re-measurement:

- `hide-bcl-calls`: reflection-indirected BCL calls
- Opaque predicates and bogus control flow, alongside a real fix to a
  control-flow-flattening bug that had silently skipped the one method
  with a real loop in every prior build
- A fix to non-deterministic string-encoding keys (`string.GetHashCode()`
  replaced with seeded `SHA256`); "same seed, same build" had been false
  since P2 was introduced
- `mba-constants`, `split-variables`, `garbage-data`
- `function-outlining` (with a fix to an infinite self-re-extraction bug)
- `string-splitting`
- `integrity-check` (behavioral self-check, with a fix to a target-detection
  heuristic broken by control-flow-flattening overhead)
- `function-inlining` (three bugs found in sequence, the deepest one a
  stack-boundary conflict with control-flow flattening, caught precisely
  by newly-adopted `ilverify`)
- `anti-debugging` (.NET)
- `token-bloating`, kept as a documented negative result once REA's
  pagination support was discovered to defeat its original purpose
- `exception-routing` (.NET), with two sequential bugs: a stale-index
  instruction removal, and a nested-exception-handler ordering violation
  that `ilverify` didn't catch but the real CLR loader did
- `code-virtualization`: a hand-assembled 8-opcode bytecode VM for one
  method, verified standalone
- Native track: loop unrolling plus pointer aliasing, SEH-based exception
  routing, dynamic API resolution (`GetProcAddress`) with an anti-debugging
  call
- `deceptive-naming` plus `homoglyph-identifiers`, with a fix to a name
  collision bug (checked the post-homoglyph string instead of the base
  word, letting two methods collide)
- `mhop-predicates`: `SHA256`-gated opaque predicates, not just arithmetic

## Packaging for public release

- English-first `README.md`, consolidated `BENCHMARKS.md`, `LICENSE`,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue templates, and a CI
  workflow (`.github/workflows/verify.yml`) that rebuilds the fixture,
  applies the full 18-pass policy, and fails on any corpus regression.
- `dysob list-passes`, and a fix to CLI help text that had still been
  describing the tool as "rename pass only" long after 17 more passes
  were added.
- First git history for the project.

## REA-specific measurements

Two findings that are about REA's own tooling specifically, not generic
obfuscation applied to one more binary:

- `inspect-managed-members` resolves `MemberRef` call targets to names but
  not exception-handler catch types, which come back as a bare metadata
  token. Found by accident while measuring exception-based routing.
- `compare-managed-members`, REA's own cross-build identity comparator,
  matches 0 of 57 members between baseline and the fully-protected build.
  Checked all six intermediate builds to find where that actually starts:
  `rename` alone doesn't move the needle at all, `string-encode` is what
  flips it to zero. See [`reports/rea-compare-managed-members.md`](reports/rea-compare-managed-members.md).

## Independent reconstruction, round two: the actual strongest build

The original N=5 reconstruction experiment (pass03-07) only ever targeted an
early build (3 of 18 passes). Re-ran it as a second N=5 round (pass08-12),
five fresh isolated subagents, no source, no mapping, no access to anything
outside an assigned working directory, against the real `protected-p1p2p3p5p6p7`
build this project actually calls its strongest.

Time barely moved (1.10x versus round one). Accuracy collapsed instead: mean
corpus pass rate dropped from 99.9% to 44.4%, and for the first time across
both rounds, zero of five reconstructions were fully correct. The output's
FNV-1a checksum was the deciding factor: three subagents cracked it (two by
brute force against observed outputs, one via a hand-written CIL disassembler
cross-validated against REA's own opcode counts), two didn't and lost every
case that prints one. Most who failed were drawn toward the same wrong lead:
IL that visibly calls `SHA256.Create()` for an unrelated anti-tamper check,
an accidental side effect of combining `mhop-predicates` and `integrity-check`,
neither of which was designed to decoy the checksum specifically. See
[`reports/pass08-blind-reconstruction-final-build.md`](reports/pass08-blind-reconstruction-final-build.md).
