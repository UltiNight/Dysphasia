# Token bloating

## Background

The "token bloating" item from the user's technique list: "insert meaningless infinite class inheritance and long fake logic to exceed the AI's context window." This was initially deferred on the judgment that the already-implemented [garbage data insertion](garbage-data.md) produces a similar effect, but the two actually target different things: garbage data adds "useless fields/methods," while token bloating exaggerates the **inheritance chain** itself. Since literally implementing the user's specified "infinite class inheritance" had not been done before, it was split out separately.

## Implementation

[`tools/obfuscator/TokenBloatingPass.cs`](../tools/obfuscator/TokenBloatingPass.cs), the `"token-bloating"` policy pass. It builds a chain of 20 empty classes shaped like `A20 : A19 : ... : A1 : Object`. Each class has only a single constructor (with no logic other than calling the parent constructor), and **nothing ever instantiates any of them with `new`**. "Infinite" cannot be taken literally (the file size would actually grow without bound), so the scale was set to a depth (20) that the fixed 115-line source could plausibly carry.

**There is structurally no runtime risk**: since none of this chain's constructors are ever executed (nothing calls them), even a mistake in the constructor-chaining logic would only remain as **unreachable, dead metadata**. This is the same "if there's no call site, there's nothing to verify" safety logic as the garbage data pass.

## Verification

- `artifacts/protected-p1p2p3p5p6p7/PixelTone.exe` (all 17 passes combined): 335/335 ([logs/verify-p1p2p3p5p6p7](../logs/verify-p1p2p3p5p6p7/summary.json)).
- Re-verified the full build with `ilverify`: "All Classes and Methods Verified."
- First confirmed 335/335 on a standalone build with only `rename`+`token-bloating` turned on, and confirmed reproducibility.
- Confirmed 25 hash-named types in REA's `inspect-managed-members` output (a few host types created by existing passes plus the 20-type chain added here): `logs/token-bloating/after.stdout.json`.

## Limitations (honestly)

- **This does not block REA itself by "exceeding the context window"**: REA's CLI supports `--token-limit`/`--token-offset`. It is designed to be paged through rather than dumping all of its large output at once. This technique's original target (simply overflowing a pure text-based AI's fixed context window) barely works against a tool like REA that supports pagination. Said plainly, what this pass actually increases is "the volume of member listings that have to be scanned by eye," not "the point where analysis becomes impossible."
- **The depth is finite and fixed**: 20 levels is an arbitrarily chosen value. Increasing it further grows the file size, but the perceived effect probably would not scale linearly with it. This was not experimented with in this increment.
- **The inheritance chain itself is a pattern**: a long row of types like `A20:A19:...:A1:Object` that have no logic and just chain-call constructors becomes a signal of "this is dead metadata" the moment someone draws out the call graph or type hierarchy. This is the same limitation already acknowledged by [garbage data](garbage-data.md).
