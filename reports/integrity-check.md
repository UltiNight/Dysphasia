# Code integrity check: behavioral self-verification instead of a full-file hash

## Background

The "code integrity check" item from the user's technique list: described as "continuously checking
its own memory hash or CRC during execution, and crashing if even a single byte is tampered with
(patched)." This serves to protect the other passes implemented so far in this session from a patch
designed to disable them (e.g., a patch that reverts another protection pass).

## Design decision: choosing behavioral self-verification instead of a full-file hash

A true "self-hash" (checking the running binary's own bytes against a checksum) has a
**chicken-and-egg problem**: the checksum value itself has to go inside the file, but computing the
checksum requires the file to already be finished. The real solution is to reserve a fixed-size
region for the checksum up front, write the whole file, compute the hash over everything except that
region, then go back and patch that hash into **the exact PE file offset that was already written**,
which needs RVA-to-file-offset conversion (parsing section headers by hand), and a single byte of
error in the offset calculation breaks the PE file itself.

This increment **did not choose** that approach, since it would be the riskiest binary surgery in
this session. Instead, **behavioral self-verification** was implemented: call `ClampByte` with a
handful of **known input to output** pairs, and if even one doesn't match, terminate immediately with
`Environment.FailFast`. Since the expected values come not from the file's bytes but from **the
algorithm's own specification** (e.g. `ClampByte(300)` must always be `255`), there's no
chicken-and-egg problem at all.

## Implementation

[`tools/obfuscator/IntegrityCheckPass.cs`](../tools/obfuscator/IntegrityCheckPass.cs), the
`"integrity-check"` pass in policy. It injects `SelfCheckOk()`, which calls `ClampByte` with 5
`(input, expected)` pairs, `(-50,0), (300,255), (100,100), (0,0), (255,255)`, and inserts
`call SelfCheckOk(); brtrue continue; ldstr "integrity check failed"; call Environment::FailFast(string)`
at the **very start** of `Main`. On success it falls straight through to the original `Main` logic;
on failure it terminates before any real work begins.

**Finding the target method**: it can't be found by name (by the time this pass runs, P1 has already
renamed it). Instead it's found by shape: "takes one int, returns an int, contains the literal
`255`, and is not the entry point." An extra condition, "fewer than 20 instructions," was added at
first, but since this pass runs **after** control-flow flattening, dispatcher overhead alone violated
that condition and caused a failure to find it, a bug that was fixed by removing the condition
(below).

**Pipeline order**: placed right after `opaque-predicates`, right before `string-encode`, so the
newly injected `"integrity check failed"` string is naturally absorbed into the existing P2 mechanism
without needing its own separate encoding logic, and so `string-encode`/`mba-constants` later apply
equally to the constants and strings this pass plants.

## Bug found: an overly strict size threshold

The first implementation added a "fewer than 20 instructions" condition to the target search, which
resulted in `IntegrityCheckInjected: false`, finding nothing, in the integrated pipeline (after
control-flow flattening finished). Cause: even a very short method like `ClampByte` easily exceeds 20
instructions with just P3 (dispatcher plus 5 blocks). This is the fourth case this session of using a
"plausible-looking" threshold without verifying it and getting bitten. Fixed by removing the size
condition entirely, after confirming that the signature "contains the literal 255" was distinguishing
enough on its own.

## Verification

- `artifacts/protected-p1p2p3p5p6p7/PixelTone.exe` (all 11 passes combined): 335/335
  ([logs/verify-p1p2p3p5p6p7](../logs/verify-p1p2p3p5p6p7/summary.json)).
- Rebuilt repeatedly with the same policy to confirm byte-identical output (reproducibility).
- Ran the protected build directly: passes the self-check silently on normal input and produces the
  same output as before (`70,141,219|8167D285`, and `--help` both exit with code 0 normally).
- The `Environment.FailFast` call is caught as-is by REA `inspect-managed-members`
  (`logs/integrity-check/after.stdout.json`), which is expected since the goal here is detection, not
  concealment.

## Limitations (honestly)

- **Doesn't catch full-file tampering**: this check only verifies `ClampByte`'s "behavior on these 5
  inputs." A patch anywhere unrelated to `ClampByte` (e.g. one that disables another protection pass)
  has no way of being caught by this check. It doesn't give the "catches a change anywhere" guarantee
  a true full-file hash would, a tradeoff deliberately chosen as explained above.
- **The check itself can be patched out**: changing `brtrue` to `br`, or patching `SelfCheckOk` to
  always return `true`, ends it right there. The self-verification code itself wasn't given any
  additional protection (e.g. nesting an opaque predicate or control-flow flattening on top of this
  check function), a delay that stays within the "buying time" scope.
- **Only 5 test vectors**: doesn't cover the full behavior of `ClampByte`. More vectors would
  increase detection power, but would also make the pattern (the repeated `call;ldc.i4;bne.un`
  structure) more conspicuous.
