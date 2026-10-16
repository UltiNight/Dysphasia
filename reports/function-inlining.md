# Function Inlining, and Bugs Five and Six

## Background

The "function inlining" item from the user's technique list: the exact opposite of [function outlining](function-outlining.md). It stuffs the entire function body directly into the call site, erasing the call relationship (`call ClampByte`) itself. I hand-picked a single target, `ClampByte` (small, pure, no side effects beyond its return value, and called from several places), rather than building a generalized "inline anything" pass, because I judged it to be the transformation most likely to fail in this session (multiple `ret` points have to be merged into a shared join point, every local variable has to be duplicated, and every internal branch target has to be rewired to the *clone*, not the original).

## Implementation

[`tools/obfuscator/FunctionInliningPass.cs`](../tools/obfuscator/FunctionInliningPass.cs), the policy's `"function-inlining"` pass. It stores the target method's arguments into cache local variables, clones the body and splices it in, remaps `ldarg`→`ldloc(cache)` and the internal `ldloc`/`stloc`→the cloned local variables, and turns each `ret` into a branch to a shared join point.

## Bugs Found (the Fifth and Sixth of This Session)

### Bug 5: missed short-form opcodes

The first implementation's remapping switch failed to catch **short-form** opcodes like `ldarg.0`/`ldloc.1` (it only matched `Code.Ldarg`/`Code.Ldloc`, not macro variants like `Code.Ldarg_0`), so it copied the target method's own parameters **as-is** instead of converting them to the caller's cache local variables. Only 29 of 335 passed. Fix: also call `target.Body.SimplifyMacros()` on the target method (the same normalization every other pass already does).

### Bug 6: a return value left on the stack collides with flattening (the deepest bug)

Even after fixing Bug 5, applying control-flow flattening (P3) afterward at a **complex call site** (such as `arr[i] = ClampByte(x)`, where an array reference and index are already on the stack before the call) produced an `InvalidProgramException`. Pinpointing the exact location with `ilverify` (newly installed for this session) showed `Stack underflow`, exactly at the `stelem.i4` site.

**Cause**: the first implementation turned each `ret` into "branch to the shared join point while leaving the value on the stack." That's fine in a method that never gets flattened (passing a stack value across a forward branch is an ordinary IL pattern). The problem is that **inlining plants a new branch inside the caller's own instruction stream**: `arr[i] = ClampByte(x)` used to be a single block, "push array, index onto the stack → (one `call`, no branch) → `stelem.i4`," but once inlined, `ClampByte`'s internal `if/else` branch appears **right there**. When control-flow flattening later processes this method, it sees those internal branches as block boundaries, and the flattening dispatcher only carries **a single state variable** across a block boundary; the array and index pushed onto the stack *before* the branch appeared vanish the moment they pass through the dispatcher. That's exactly why `AdjustChannel`'s call site (`return ClampByte(x)`, with no other value left across the call) never hit this problem.

**Fix (two layers)**:
1. Turn each `ret` into "store the value in a local variable → branch to the join point," and read that local variable back at the join point. This matches the assumption flattening expects: that the stack is empty at a block boundary.
2. Even so, the caller method that inlining was applied to is itself **excluded from control-flow flattening** (`Protector.cs` adds callers touched by inlining to `policy.ExcludeMembers`). Fix 1 alone can't rescue "other values that were already on the stack *before* the call" (the array plus the index). This is fundamentally a conflict caused by ControlFlowPass and inlining resting on different assumptions, so I judged it correct to block it with a safety rule of "don't use this combination together," the same philosophy as the existing rule that excludes methods with exception handlers from flattening.

### A side-discovered InitLocals defect (the seventh)

During debugging, `ilverify` raised an "InitLocals not set" error on `ClampByte` itself (untouched by anything else, only flattened). The baseline (`artifacts/baseline/PixelTone.exe`) verifies cleanly, but this project's CFF, when it added a new local variable (`state`), **never set `MethodBody.InitLocals` to true**. The defect surfaced because CFF created a local variable for the first time in a method (`ClampByte`) that originally had none at all. The newly created methods in [`FunctionOutliningPass.cs`](../tools/obfuscator/FunctionOutliningPass.cs) had the same defect (found first, fixed at the same time). Both were fixed by explicitly setting `Body.InitLocals = true`, which just matches what a real compiler always does for a method with local variables.

## Verification

- Ran `ilverify` (the official .NET IL verifier, installed for this session with `dotnet tool install -g dotnet-ilverify`) against the whole of `artifacts/protected-p1p2p3p5p6p7/PixelTone.exe`: **"All Classes and Methods Verified."** Before the fix, it reported `InitLocals`/`Stack underflow` errors. This verifier was decisive for debugging in this session: the `InvalidProgramException` the runtime throws only tells you *which method* it happened in, not *why*, while `ilverify` points to the exact IL offset and error kind (`StackUnderflow`, `InitLocals`).
- 335/335 ([logs/verify-p1p2p3p5p6p7](../logs/verify-p1p2p3p5p6p7/summary.json)), reproducibility confirmed, and running the protected build directly confirmed the same output as before (`70,141,219|8167D285`).
- Confirmed the absence of the `ClampByte` call with REA's `inspect-managed-members` (`logs/function-inlining/after.stdout.json`).

## Limitations (honestly)

- **Narrow scope**: applied only to the single, hand-picked `ClampByte`. If generalized, the two kinds of bugs found this time (missing opcode normalization, the stack-boundary collision) could just as easily show up again at other call sites. The real lesson from this debugging session is that verifying with ILVerify every single time is what keeps it safe.
- **Flattening coverage shrinks**: a caller that has been inlined into drops out of the control-flow flattening target set. This is accepting, as-is, the tradeoff that the two techniques cannot both be applied to the same method at once. A more sophisticated solution (moving every value left on the stack before the call into local variables too, at inlining time, so it can coexist with flattening) is possible, but it is beyond the scope of this increment.
