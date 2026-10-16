# Opaque Predicate + Bogus Control Flow, and a P3 bug found along the way

## Background

Following [hiding BCL call targets](bcl-call-hiding.md), among the techniques the user listed,
"Opaque Predicate" and "Bogus Control Flow," plus a lightweight "MHOP," were combined and added to
the existing P3 (control-flow flattening) dispatcher. In the process of implementing this, **an
actual bug in the existing P3 pass was found**. This section is the core of this report.

## Bug found: the Unconditional/Fallthrough transition is silently dropped

`ControlFlowPass.FlattenMethod` records "the first instruction emitted for this block" via
`firstEmitted[bi] ??= original[k]` when copying a block, and uses that value as the switch table's
case label. The problem is that the code emitting the block's actual state transition
("ldc.i4 target; stloc state; br dispatch") was wrapped in **the same `??=` operator**:

```csharp
case ExitKind.Unconditional:
    firstEmitted[bi] ??= EmitTransition(il, stateVar, dispatch, ids[exit.Target]);
    break;
```

`??=` **doesn't evaluate the right-hand side at all** if the left side is already non-null, meaning
`EmitTransition` isn't even called. If the block has even one actual instruction copied into it
(which is almost always true for blocks ending in `Unconditional`/`Fallthrough`), `firstEmitted[bi]`
is already filled in from the copy loop, so emitting the transition instruction is skipped entirely.
That block simply **silently falls through** to whatever block comes next in textual order, never
going through the switch dispatcher at all.

**Why 335/335 kept passing until now**: in this project's fixed source (`fixture/PixelTone.cs`),
methods whose blocks only end in `Conditional`/`Terminal` (`ClampByte`, `ApplyPreset`, `ReadInt`) are
unaffected by this bug (`Conditional` branches always use a separate code path that is called
regardless, without `??=`). The only affected method is `Fingerprint`, the only one with a real loop
(`for`), which produces `Unconditional` (loop entry) and `Fallthrough` (loop body to condition check).
But **this method's original bytecode already has its textual order match its control-flow order**
(initialization to body to condition check to return, executed exactly as written), so even with the
transition missing, falling through "by chance" to the next block happened to coincide with the
originally intended target, so it wasn't functionally wrong. **The intended flattening never actually
happened, but the result value happened to be correct anyway**, just lucky, not by design.

**Actual impact**: in every P3-applied build this project has made so far, including
`artifacts/protected-p1p2p3/PixelTone.exe`, the loop in `Fingerprint` only wore the "switch/state
variable" appearance but **wasn't actually flattened**: only the condition-check block really went
through the dispatcher, while the other two blocks (initialization, body) stayed hidden in their
original order. The "`FlattenedMethods: 4`" figure reported in the
[P1/P2/P3 first-round measurement](p1-p2-measurement.md) and the
[N=5 independent reconstruction experiment](pass03-blind-reconstruction.md) is correct at the
method-count level, but not all four of those methods were flattened at the same strength across
**every branch edge**: `Fingerprint` was handed to the analysts only partially flattened.
Functionality was always correct (335/335 was true every time), so this bug never produced a "false
result," but it **did overstate the actual protection strength**. To correct this honestly: the
2.18x measurement so far was taken against a build where `Fingerprint` was protected more weakly than
intended.

## Fix

The fix is simple: separate "whether to emit the transition" from "what to put into
`firstEmitted[bi]`." `EmitTransition` is now **always** called, and only whether its return value
fills `firstEmitted[bi]` is decided by `??=`:

```csharp
var transitionFirst = EmitTransition(il, stateVar, dispatch, ids[exit.Target], ...);
firstEmitted[bi] ??= transitionFirst;
```

Fixed both the `Unconditional` and `Fallthrough` cases in
[`ControlFlowPass.cs`](../tools/obfuscator/ControlFlowPass.cs). The `Conditional` case never used
`??=` to begin with, so it had no bug.

**Verification**: after the fix, `Fingerprint` was dumped again to confirm: both the initialization
block and the body block now correctly emit their own "ldc.i4 target; stloc state; br dispatch"
transition (confirmed directly by comparing the IL dump before and after the fix). Rebuilt with the
same policy (`pixel-tone.p1p2p3.json`) as `artifacts/protected-p1p2p3/PixelTone.exe` and re-verified
at 335/335: behavior is preserved. **The existing `artifacts/protected-p1p2p3/PixelTone.exe` file
itself was left untouched**, to preserve the exact bytes that pass03 through pass07 actually
analyzed. The fixed pass is reflected starting from the newly built `artifacts/protected-p1p2p3p5/`
and `artifacts/protected-p1p2p3p5p6/`.

## Opaque Predicate + Bogus Control Flow (lightweight MHOP)

On top of the bug fix, the `"opaque-predicates"` policy pass was added: it wraps every
`Unconditional`/`Fallthrough` transition in the following trick:

```
n = state;  (n*n + n) % 2 == 0   -- always true (the product of two consecutive integers is always even)
if (true) goto real transition;
else { state * constant; discard the result; }   -- never executes, but valid IL, not dead space
real transition: state = target; goto dispatch;
```

The key design decision: **make the false branch "safe" too**. The false side only does a
computation that doesn't change actual program state (multiply and discard), then falls straight
through to the real transition. Even if there were a bug in the predicate computation (there
shouldn't be), the program would only get slower, never produce a wrong value, the same "never bet
correctness on a trick" principle followed throughout this session. Implementation:
[`ControlFlowPass.EmitTransition`](../tools/obfuscator/ControlFlowPass.cs) guard branch, policy
example: [`pixel-tone.p1p2p3p5p6.json`](../tools/obfuscator/policies/pixel-tone.p1p2p3p5p6.json).

**Scope**: not applied to blocks ending in `Conditional` (where the method already has its own real
conditional branch). This increment is `Unconditional`/`Fallthrough` only. In this fixed source, it
only applies to `Fingerprint`'s two loop-entry/body transitions (`OpaquePredicatesInjected: 2`). The
other four methods all end in `Conditional`/`Terminal`, so there was no target for them.

## Verification

- `artifacts/protected-p1p2p3p5/PixelTone.exe` (bug fix only, no opaque-predicates): 335/335
  ([logs/verify-p1p2p3p5](../logs/verify-p1p2p3p5/summary.json)).
- `artifacts/protected-p1p2p3p5p6/PixelTone.exe` (bug fix + opaque-predicates + existing P5): 335/335
  ([logs/verify-p1p2p3p5p6](../logs/verify-p1p2p3p5p6/summary.json)).
- Remeasured `Fingerprint` with REA `inspect-managed-members`: `il_size` 36 bytes (original) to 258
  bytes, `instruction_count` 24 to 69 (`logs/opaque-predicates/after.stdout.json`), actually larger
  and more complex than the state reported as "flattened" before the bug fix.

## Limitations (honestly)

- **A classic opaque predicate, not true MHOP**: cryptographic-hash-based predicates
  (`SHA256(x)==constant`) carry too much risk and execution cost to write the IL by hand, so this
  increment narrowed scope to an arithmetic identity (`n*(n+1)` is always even). Since REA is a
  static-analysis tool that doesn't do deep symbolic execution, this level of predicate was judged
  sufficient to achieve the goal of making it hard to *statically* prove "always true." The extra
  benefit of a cryptographic predicate is judged to matter more only for a human reading it by hand,
  and to be overkill investment relative to REA's own analysis depth. The state variable (`state`) is
  a counted value, not an input, so a reverser working it out by hand can tell within a second that
  it's "always true": this is the kind of delay consistent with the "buying time" premise, not a
  complete block.
  - This arithmetic predicate repeats **the exact same mathematical form** (`n*n+n mod 2`) at every
    transition. Lining up several transitions side by side reveals the pattern immediately. Mixing in
    a different identity per transition would be a natural improvement for the next increment.
- **Narrow scope of application**: not yet applied to `Conditional` transitions. This fixed source is
  so small to begin with (5 methods, one loop) that there were only 2 places to apply it. A larger
  program is expected to see a bigger effect, but that isn't proven with this fixture.
