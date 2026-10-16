# Function Outlining

## Background

The "function outlining" item from the user's technique list: splits a single function into several meaningless small functions, complicating the call hierarchy. Control flow flattening (P3) disrupts a function's **internal** structure but leaves its **boundaries** (member list, call graph) untouched. This technique attacks the opposite axis.

## Implementation

[`tools/obfuscator/FunctionOutliningPass.cs`](../tools/obfuscator/FunctionOutliningPass.cs), the `"function-outlining"` pass in the policy. Finds **single basic blocks ending in `ret`**, extracts each one into a new static method that takes as parameters only the values the block reads from outside it (argument `ldarg`, and local variables `ldloc` the block reads before defining them itself), and replaces the original site with "push those values, call the new method, then return."

**Safeguard: an explicit allowlist, not a denylist.** If any instruction in a block doesn't belong to a pre-defined safe opcode set (argument/local-variable access, arithmetic, array operations, calls, constants), the whole block is skipped. It never takes the "extract first and see" approach even if there's some dangerous opcode it failed to anticipate. Blocks ending in `throw` and non-static methods are entirely out of scope.

**Pipeline order**: runs right after `rename`, before `split-variables`/`control-flow`, because it needs to see the original block structure as-is (targeting blocks already altered by variable splitting or control flow flattening would scramble which "externally dependent values" need to be passed as parameters).

## Bug found: an infinite loop (a size threshold that failed to prevent self-replication)

The first implementation produced an **infinite loop** in `AdjustChannel` (3 parameters: value, contrast, brightness). Cause: it only used the threshold "skip if block size is under 5 instructions," but the extraction result itself was "load 3 arguments + call + ret = 5 instructions," so **that result itself became an "extraction target" again**. Every extraction kept creating "a wrapper of a wrapper," the size never shrank, and it repeated forever. It was discovered only because it hit a 60-second timeout (it really was an infinite loop, not just slow; the 200-iteration cap added as a safeguard proved this immediately).

**Fix**: replaced "block size >= 5" with "block size must be **strictly greater than that block's extraction result**" (`e - s > deps.Count + 2`). This guarantees that the instruction count strictly decreases with every extraction, and a sequence of non-negative integers that keeps decreasing is guaranteed to terminate in finitely many steps. This is the third bug found this session caused by not setting a rigorous termination condition from the start, in the same family as the CFF `??=` skip bug and P2's `GetHashCode()` nondeterminism bug ("verify boundary conditions by proof, not by assumption").

## Verification

- `artifacts/protected-p1p2p3p5p6p7/PixelTone.exe` (full combination of 9 passes): 335/335 ([logs/verify-p1p2p3p5p6p7](../logs/verify-p1p2p3p5p6p7/summary.json)).
- Confirmed byte-level identity (reproducibility) by rebuilding repeatedly with the same policy.
- 4 blocks were extracted from the fixed source (all of `AdjustChannel`, plus the blocks eligible for extraction among `ApplyPreset`'s three preset branches). Confirmed with REA `inspect-managed-members` that the main type's method count rose from 6 to 10 (`logs/function-outlining/after.stdout.json`).
- Also confirmed via a dump that the extracted methods got MBA constant obfuscation applied on top: `AdjustChannel` is now left with just 3 lines of "pass arguments, then call," and the actual arithmetic runs entirely inside the new method, together with constants hidden by MBA.

## Limitations (honestly)

- **The target is narrow**: it only handles "a single basic block ending in `ret`." Blocks with branches or loops, and blocks that throw exceptions, are all out of scope; in this fixed source, it ended up applying only to a few spots doing "a simple calculation followed by an immediate return." Generalizing to more complex blocks would need more data-flow/control-flow analysis.
- **Still traceable if you draw the call graph**: it doesn't hide the call relationship itself (the new method's name is obscured, but the fact that "A calls B" remains as a clear `call` instruction). It has no effect against call-graph tracing tools, only against analysis that scans members one at a time.
