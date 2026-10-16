# Hiding BCL call targets (next step after P1-P3, item 1)

## Background

After the [P1/P2/P3 first measurement](p1-p2-measurement.md) and the [independent reconstruction experiment (N=5)](pass03-blind-reconstruction.md), when asked what the next step should be to push past the roughly 2x level, four options were ranked, and the one with the highest payoff and lowest difficulty (item 1: hiding BCL call targets via reflection) was implemented right away.

Even with the existing protected build (`artifacts/protected-p1p2p3/PixelTone.exe`) applying renaming (P1), control-flow flattening (P3), and string encoding (P2) all together, **which BCL method a method body calls** still sits in the MemberRef table in plain text. Even after `ReadInt` is renamed to an anonymous name (`m_22283830b7`), a single line like `call System.Int32::TryParse(System.String, System.Globalization.NumberStyles, System.IFormatProvider, System.Int32&)` immediately tells you "this is a function that parses a string into an integer," with no need to see a name at all. In the independent reconstruction experiment, analysts actually used exactly this path to quickly figure out what `ReadInt` meant.

## Implementation

**The trick**: swap only the call site's **operand** for `call Int32.TryParse(string, NumberStyles, IFormatProvider, out int)`, pointing it at a custom method with the exact same parameter types, count, and order. Since the stack contract (4 args in, 1 bool out) is completely identical, not a single character of the argument-loading code at the call site needs to change. This is the same "swap only the metadata handle" strategy P1 (renaming) uses, just applied to the call target instead.

The replacement method (`HiddenTryParse`, injected into a host type) internally obtains the `System.Int32` type with `Type.GetTypeFromHandle`, then calls the method via reflection using `Type.InvokeMember`. The `out int` parameter is handled by putting a boxed placeholder in the corresponding slot of the `object[]` argument array; `InvokeMember` writes the result back into that slot after the call. The method name string itself ("TryParse") that gets passed in is encoded with the same XOR-blob plus `FieldRVA` plus `RuntimeHelpers.InitializeArray` pattern as P2 (`StringPass`), injecting a small, single-string blob and decoder dedicated to this pass into a separate host type (kept independent of `StringPass`'s own blob, so it does not depend on pipeline ordering).

Implementation: [`tools/obfuscator/BclCallHidingPass.cs`](../tools/obfuscator/BclCallHidingPass.cs), wired into [`Protector.cs`](../tools/obfuscator/Protector.cs) as the `"hide-bcl-calls"` policy pass. Example policy: [`tools/obfuscator/policies/pixel-tone.p1p2p3p5.json`](../tools/obfuscator/policies/pixel-tone.p1p2p3p5.json).

**Scope**: the first implementation targets only a single overload, `Int32.TryParse(string, NumberStyles, IFormatProvider, out int)`. That is the exact overload `ReadInt` calls, and it was identified during this session's measurements as the single point with the highest exposure value. The remaining BCL targets, such as `Console.WriteLine`, `ArgumentException..ctor`, and `String.op_Equality`, each have lower individual exposure value and are left for a follow-up increment.

## Verification

- **Behavior preserved**: re-verified `artifacts/protected-p1p2p3p5/PixelTone.exe` (baseline + P1+P3+P2+the new pass) against the full 335-case corpus with `dysob verify`. **335/335 match** (`logs/verify-p1p2p3p5/summary.json`).
- **Exposure measurement via REA (own `dump`)**: in the pre-protection build, `call System.Boolean System.Int32::TryParse(...)` appears as-is in the `dump` output; after the new pass is applied, it does not appear at all. The binary itself also has 0 occurrences of the ASCII string `"TryParse"` (1 before protection).
- **Exposure measurement via REA (REA itself)**: ran `rea inspect-managed-members` on the before and after builds (`logs/bcl-call-hiding/before.stdout.json`, `after.stdout.json`). The case-insensitive match count for "tryparse" went from 1 to **0**. In its place, `Type.InvokeMember`/`Type.GetTypeFromHandle` calls newly appear in the REA output (2 each). This is the honest trade-off: the fact that "it calls TryParse" is gone, but the fact that "it dynamically invokes something via reflection" remains. Which method name actually gets passed can only be learned by watching the runtime decoding or by unpacking the blob directly; a static MemberRef listing no longer tells you.

## Limitations (honestly)

- **Only the method name is hidden, not the type**: `ldtoken System.Int32` is still there, so you can tell that "something related to Int32 is being called via reflection." The goal was never full concealment, only removing "which member" from what static analysis can tell you.
- **The reflection call itself is a pattern**: the `Type.InvokeMember`/`GetTypeFromHandle` combination is unusual enough that it can actually signal to an analyst, "this function is hiding something." It blocks automated string/name scanning, but a person who notices that signal and steps through the decoded name at runtime in a debugger can recover it just as easily. That result matches this project's original premise (not full blocking, but a time fight).
- **The key/encoding is not a cryptographic secret**: the same limitation as P2. The decoder and the blob live in the same module.
- **Performance**: a reflection call is slower than a direct `call`. At this one point (`ReadInt`, parsing 5 user CLI arguments) the cost is negligible, but applying it broadly to high-call-frequency paths would need the cumulative cost measured.
- **The remaining BCL targets are not yet covered**: `Console.WriteLine`, `ArgumentException..ctor`, `CultureInfo.get_InvariantCulture`, and others are still sitting in the MemberRef table as-is. Each one was judged to have lower individual exposure value than `TryParse`, but added together they still tell an analyst most of the "input/output flow."

## Relationship to the next round of remeasurement

This increment was added *after* the N=5 independent reconstruction experiment ([pass03-07](pass03-blind-reconstruction.md)) finished, so it is not reflected in the existing 2.18x statistic. Time was not remeasured by having analysts independently reconstruct this pass alone. The change's scope (a single call site) was judged too small relative to the cost of rerunning the existing N=5 methodology to be worth the information gained. Instead, the primary evidence used was that REA's own static exposure (MemberRef inspection) actually decreased.
