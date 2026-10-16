# MBA (Mixed Boolean-Arithmetic) constant obfuscation

## Background

The "MBA" item from the user's technique list: a technique that turns a simple operation like `x+y` into a bitwise-operation formula shaped like `(x^y) + 2*(x&y)`. Same principle as the other increments this session ([BCL call hiding](bcl-call-hiding.md), [Opaque Predicate](opaque-predicates-and-cff-fix.md)): **the value left on the stack stays the same, only the way it's produced changes.**

I picked the target with the highest exposure value first: `Fingerprint`'s FNV-1a constants (`16777619` = the FNV prime, `-2128831035` = the offset basis) immediately give away "this is an FNV-1a hash," from just a single number. Even with every name hidden and every variable flattened, the algorithm's identity still leaks.

## Implementation

The identity `a + b == (a ^ b) + 2 * (a & b)` holds true for **any** 32-bit two's-complement integer value (it's exactly the adder's formula of "carryless sum" = xor, "carry" = `2*(a&b)`). So replacing `ldc.i4 V` with a seed-chosen `a` and `b = unchecked(V - a)` still leaves the same value V on the stack, always. The call site and the consumer never need to be touched at all.

```
ldc.i4 a
ldc.i4 b
xor
ldc.i4 a
ldc.i4 b
and
ldc.i4 2
mul
add
```

Implementation: [`tools/obfuscator/MbaPass.cs`](../tools/obfuscator/MbaPass.cs), the policy's `"mba-constants"` pass.
**Scope**: only targets `ldc.i4` where `|V| > 20`. I judged that blowing up every small constant (array indices, loop counters, etc.) with MBA would only add bulk for no benefit, so I filtered it out with a threshold (`MagnitudeThreshold`).

## Verification

- `artifacts/protected-p1p2p3p5p6p7/PixelTone.exe` (every pass so far + MBA): 335/335
  ([logs/verify-p1p2p3p5p6p7](../logs/verify-p1p2p3p5p6p7/summary.json), the directory name is kept the same as
  `protected-p1p2p3p5p6p7`).
- Confirmed via a static dump that both FNV constants are **completely gone** (`16777619` and `-2128831035` both at 0 occurrences; the original had 1 occurrence each).
- Reconfirmed the same result with REA's `inspect-managed-members` (`logs/mba-constants/after.stdout.json`).

## Limitations (honestly)

- **Only the constant changes, and the operation itself can be instantly recovered by constant folding**: `(a^b)+2*(a&b)` is an expression made entirely of literals, so a real decompiler like IDA/Hex-Rays, or a .NET-specific decompiler (ILSpy/dnSpy), folds it straight back to the original value in a single constant-folding optimization pass. REA's own `inspect-managed-members` was confirmed not to do this folding, since it's a metadata/CIL-anchor-level analysis, but analyzing with **a tool other than REA** (or if REA later routes through a decompiler) effectively nullifies this protection. In line with the "race against time" premise, this technique only blocks "static grepping/string browsing"; it does not block "determined decompilation".
- The choice of `a`/`b` repeats the exact same mathematical pattern (xor + and + double + add) everywhere. Looking at several sites side by side immediately reveals the pattern. If there's a next increment, diversifying the operation shape itself (mixing in other, multiplication-based identities, etc.) would be a natural improvement.
