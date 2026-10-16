# Variable splitting

## Background

The "variable splitting/merging" item from the user's technique list. Makes a local variable's
"meaningful accumulated value" (e.g. `Fingerprint`'s hash state) impossible to follow with data-flow
tracing alone: the variable itself is eliminated, and in its place, storage is done as two shares
that only reconstruct the value when XORed together.

## Implementation

The identity is simple: so that `v == shareA ^ shareB` holds, a freshly seeded mask `m` is drawn at
every store point, and `shareA = v ^ m`, `shareB = m` are written. On read, `shareA ^ shareB`
reconstructs the value. This is safe even though the mask differs from one store to the next (the
mask only needs to be consistent within a single store/immediate-use pair), so it always reconstructs
correctly.

```
// stloc v  →
stloc tmp
ldloc tmp
ldc.i4 m
xor
stloc shareA
ldc.i4 m
stloc shareB

// ldloc v  →
ldloc shareA
ldloc shareB
xor
```

Implementation: [`tools/obfuscator/VariableSplitPass.cs`](../tools/obfuscator/VariableSplitPass.cs),
the `"split-variables"` pass in policy.

**Safeguard, address-taken variables are excluded**: local variables whose address is taken via
`ldloca`/`ldloca.s` (in this fixed source, just one: `ReadInt`'s `out int` target) are left
untouched. Splitting would eliminate the very concept of "that variable's address" (a value split
into two shares has no single memory location to point at).

**Pipeline order, runs before control-flow flattening**: placed ahead of `"control-flow"` in
[`Protector.cs`](../tools/obfuscator/Protector.cs). That way, the local variables this pass sees are
only the fixed source's original variables, and it leaves alone the dispatcher state variable that
CFF adds later, since the state value is already a meaninglessly shuffled integer, splitting it would
gain nothing and would only add cost at every state transition.

## Verification

- `artifacts/protected-p1p2p3p5p6p7/PixelTone.exe` (all 7 passes combined, `pixel-tone.full.json`):
  335/335 ([logs/verify-p1p2p3p5p6p7](../logs/verify-p1p2p3p5p6p7/summary.json)).
- First confirmed 335/335 on a standalone build with only `rename` + `split-variables` turned on:
  behavior is preserved standalone, with no cross-pass effects.
- Rebuilt repeatedly with the same policy to confirm byte-identical output (reproducibility).
- Across the fixed source, 9 local variables get split (only `ReadInt`'s out-target variable is
  excluded). REA `inspect-managed-members` confirms `Fingerprint`'s `il_size` goes from 36 bytes
  (original) to 615 bytes (`logs/split-variables/after.stdout.json`), though since CFF, Opaque
  Predicate, MBA, and variable splitting all overlap at this point, this number is the combined
  effect of all four techniques.

## Limitations (honestly)

- **Fixed mask pairs, not runtime randomness**: masks are decided by seed at obfuscation time and
  baked into the binary as constants. Following two `ldc.i4` constants and one `xor` during
  execution restores the value immediately. This is effective against a static analyzer that
  "automatically" tracks data flow (taint analysis, etc.), but a human or an AI reading a handful of
  instructions by hand can restore it within a minute, a delay that stays within the "buying time"
  scope.
- **No threshold, every eligible variable gets split**: unlike the MBA pass, there's no size
  criterion like "skip small values." This fixed source is small enough that it wasn't a problem, but
  applying this unconditionally to a program with very many variables could lead to excessive size
  growth.
- **Array/reference-type variables aren't targeted**: only `Int32`/`UInt32` local variables are
  targeted. The `int[]` result array that `ApplyPreset` returns, or string reference variables,
  aren't touched by this pass (XOR splitting doesn't make sense for reference types).
