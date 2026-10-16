# Anti-Debugging

## Background

The user's technique list has an "anti-debugging" item, described as "detect the OS's debugger flag
(PEB), hardware breakpoints, debugger window names, etc. and block execution." In .NET managed code,
though, the simplest and most reliable method is `System.Diagnostics.Debugger.IsAttached`. It's a
property the CLR manages directly, so there's no need to hand-parse the PEB flag.

## Why this pass doesn't conflict with this project's verification pipeline

`Verifier.cs` launches the protected build with a plain `Process.Start`. It never attaches a debugger. So
across the entire 335-case corpus, `IsAttached` is always `false`, and this check never interacts at all
with this project's existing measurement of "is the code correct." What this check actually blocks is
someone attaching IDA, dnSpy, `dotnet-dump`, or a managed debugger directly to the protected build to step
through it line by line. That is exactly the scenario this project's own goal targets (maximize delay on
REA usage, make the analyst spend more time), so it's a reason to implement this, not a reason to avoid
it.

## Implementation

[`tools/obfuscator/AntiDebuggingPass.cs`](../tools/obfuscator/AntiDebuggingPass.cs), the policy's
`"anti-debugging"` pass. It reuses **the exact same injection shape** as the
[integrity check](integrity-check.md), since that pattern was already verified safe:

```
call System.Diagnostics.Debugger::get_IsAttached()
brfalse continue          // no debugger -> go to Main's original logic
ldstr "debugger detected"
call System.Environment::FailFast(string)
continue: <Main's original first instruction>
```

This is inserted at the very start of `Main`. When used together with the
[integrity check](integrity-check.md), each check inserts itself ahead of whatever is currently Main's
first instruction at the time it runs, so the two accumulate safely regardless of order.

**Pipeline order**: right after `integrity-check`, before `string-encode`, so that the newly added
`"debugger detected"` string gets naturally absorbed into the existing P2 mechanism.

## Verification

- `artifacts/protected-p1p2p3p5p6p7/PixelTone.exe` (the full combination of 13 passes): 335/335
  ([logs/verify-p1p2p3p5p6p7](../logs/verify-p1p2p3p5p6p7/summary.json)).
- Re-verified the full build with `ilverify`: "All Classes and Methods Verified."
- Rebuilt with the same policy to confirm byte-for-byte identity (reproducibility).
- Ran the protected build directly, with no debugger attached: confirmed it produces the same output as
  before (`70,141,219|8167D285`).
- The `Debugger.IsAttached` call shows up as-is in REA's `inspect-managed-members`
  (`logs/anti-debugging/after.stdout.json`). Since the point is detection, there's no need to hide it.

## Limitations (honestly)

- **`IsAttached` is bypassed by a one-line patch**: Changing `brfalse` to `br`, or patching
  `get_IsAttached` to always return `false`, is enough to defeat it. More sophisticated techniques, such
  as hardware breakpoint detection or searching for debugger window names (including the direct PEB-flag
  reading the user originally described), were not implemented. `IsAttached` is effectively the standard
  approach in .NET managed code, and anything beyond it requires calling native APIs
  (`CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`) directly via P/Invoke, which falls outside
  this project's managed-code scope.
- **Timer-based detection was not added**: "Timing-difference detection" (RDTSC and similar) was
  deliberately excluded because of its high false-positive risk in CI/virtualized environments (this
  project's own verification relies on automated, repeated execution).
- **`IsAttached` only catches a debugger that is already attached at process start**: The pattern of
  launching the process first and attaching later is not caught by this single check. That would require
  adding a repeated check during execution (e.g. a timer callback), which reintroduces the same risk as
  the "timer-based detection" noted above.
