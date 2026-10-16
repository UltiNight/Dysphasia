# Garbage Data Insertion

## Background

The "garbage data insertion" item from the user's technique list. Mixes dummy fields/methods that are never used at runtime into the module, forcing an analyst (or an AI) scanning the member list with `inspect-managed-members` to first determine "is this real logic or not" before anything else.

## Implementation

[`tools/obfuscator/GarbageDataPass.cs`](../tools/obfuscator/GarbageDataPass.cs), the `"garbage-data"` pass in the policy. Adds 4 `static int` fields to a new host type (each seeded in the type initializer with a different SHA256-derived constant; avoided making them all 0, since that would be a signal of "this is dead code"), plus 6 methods that read those fields and do plausible-looking arithmetic of the form `(x ^ fieldA) + fieldB * x`. **Nothing calls them**: since they're completely disconnected from the execution path, whatever value this pass computes can't affect program behavior in any way (which also means there's no "call site" at all to verify; of the passes added this session, this one carries the lowest accuracy risk).

## Verification

- `artifacts/protected-p1p2p3p5p6p7/PixelTone.exe` (full combination of 7 passes): 335/335 ([logs/verify-p1p2p3p5p6p7](../logs/verify-p1p2p3p5p6p7/summary.json)).
- Confirmed byte-level identity (reproducibility) by rebuilding repeatedly with the same policy.
- Confirmed that the 4 dummy fields and 6 methods appear in REA `inspect-managed-members` output **indistinguishably from ordinary members**: REA's static analysis shows everything, without filtering out "code that never executes" (`logs/garbage-data/after.stdout.json`).

## Limitations (honestly)

- **Doesn't work against dynamic analysis (coverage measurement)**: analysis that measures coverage during actual execution (code coverage tools, JIT call tracing) immediately filters these out as "methods that were never called." This technique only works against static member browsing, which is exactly the category REA's `inspect-managed-members` falls into.
- **There may be a signal that distinguishes it from real logic**: the fact that the dummy methods all repeat the same arithmetic pattern (`xor`+`mul`+`add`) and are never called from anywhere is itself a signal, if you draw the call graph, that "this is dead code." This increment only achieved "indistinguishable in a listing," not "not suspicious even once you draw the call graph." It doesn't stand out because the count is small (6), but scaling it up more would actually increase the risk of looking like a "block of dummies."
