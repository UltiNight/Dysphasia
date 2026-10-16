# MHOP (mathematically transparent conditional, cryptographically opaque predicate)

## Background

The "MHOP" item from the user's technique list: "attach an operation that can't be computed from text alone, such as a cryptographic hash, to a conditional, to paralyze static reasoning." The [Opaque Predicate report](opaque-predicates-and-cff-fix.md) noted that the reason it first chose an arithmetic identity (`n*(n+1)` is always even) was that "REA itself doesn't do deep symbolic execution, so the arithmetic level is enough," but that arithmetic identity clearly had a remaining limitation: **a person can look at it and prove it in one second.** MHOP fills exactly that gap. SHA256's result can't be known by mental calculation; you actually have to run it.

## Implementation

I added a third kind of predicate to `EmitTransition` in [`tools/obfuscator/ControlFlowPass.cs`](../tools/obfuscator/ControlFlowPass.cs). The policy's `"mhop-predicates"` only makes sense turned on together with `"opaque-predicates"` (since it's a variant inserted into the same guard slot): half of the transitions already picked as guard targets, chosen by seed, use this predicate instead of the arithmetic identity:

```
SHA256(fixed 4 bytes)[0] == <the actual first byte of that hash>   // always true, by construction
```

Both `the fixed 4 bytes` and `the actual first byte of that hash` are computed at obfuscation time, **using this tool's own (.NET 10) runtime**, and baked in as constants. SHA256 isn't an algorithm whose output differs by platform. It's standardized and fully deterministic, so computing it on the older .NET Framework runtime this protected binary runs on, for **the same input bytes**, is guaranteed to produce **the exact same result**. (This project previously had exactly this assumption broken by `string.GetHashCode()`, see [that report](string-pass-determinism-fix.md). SHA256 is the opposite of that problem: it's standardized, so there's no difference across platforms.)

**API choice**: this fixture's source is built targeting .NET Framework mscorlib with the older `csc` compiler (recorded in `reports/environment.json`): that runtime doesn't have the static convenience method `SHA256.HashData(byte[])`, added in .NET 5+. So I hand-wrote the IL using the older, instance-based API (`SHA256.Create()` + `HashAlgorithm.ComputeHash(byte[])`). This tool's own code (the very part used for "constant calculation" in the paragraph above) is `.NET 10`, so it can freely use `HashData`, but this is another case confirming that **the IL being generated** has to be written against the target runtime, not the tool's own.

**Safe on the false branch too**: the same design principle as the existing opaque predicate. The false side (never executed) only computes the same hash once more and discards it; it never diverges into different code. Even if there's a bug in the predicate calculation, it just gets slower, it never produces a wrong value.

## Verification

- `artifacts/protected-p1p2p3p5p6p7/PixelTone.exe` (full combination of 16 passes): 335/335
  ([logs/verify-p1p2p3p5p6p7](../logs/verify-p1p2p3p5p6p7/summary.json)).
- Re-verified the full build with `ilverify`: "All Classes and Methods Verified."
- First confirmed 335/335 on a standalone build with only `rename`+`control-flow`+`opaque-predicates`+`mhop-predicates` turned on.
- Confirmed byte-for-byte identity (reproducibility) by rebuilding repeatedly with the same policy.
- Ran the protected build directly: confirmed output identical to before (`70,141,219|8167D285`).
- REA's `inspect-managed-members` still catches the `SHA256`/`ComputeHash` calls as is
  (`logs/mhop-predicates/after.stdout.json`). There's no need to hide this, since the goal is "blocking the easy shortcut," not evading detection.

## Limitations (honestly)

- **It's still broken by actually running it or dereferencing it directly**: running it once under a debugger to see the branch result, or feeding the byte value straight into SHA256 by hand (or with a tool), reveals that it's "always true" within a second. This only removes the shortcut of "knowing just by looking"; the path of "actually computing it" is still open. This is a delay on the order consistent with this project's "race against time" premise.
- **The input being a fixed constant reveals the pattern**: the shape `SHA256(constant)[0] == constant` is itself a signal that "this is an opaque predicate." Just from the structure, you can suspect it's not a real cryptographic secret but just a number comparison precomputed at obfuscation time.
- **Mixed in with the arithmetic version**: only half of the guarded transitions (determined by seed) use MHOP, and the rest use the existing arithmetic identity. Since this fixture's source has only 2 guard targets, I couldn't observe any more variation than that.
