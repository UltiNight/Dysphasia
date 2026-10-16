# Exception-based routing (.NET): a second bug, and an unexpected gap in REA

## Background

In [exception-based routing on the native track](native-exception-routing.md), it was written that
"this technique directly collides with .NET control-flow flattening's safety rule of 'don't flatten
methods that have exception handlers,' so it wasn't brought to .NET." Looking again, though, **`Main`
already has an exception handler and was therefore already excluded from control-flow flattening**,
so applying this technique to `Main` doesn't change CFF's exclusion list at all. The same technique
was applied at the same spot as the native side (preset validation).

## Implementation

[`tools/obfuscator/ExceptionRoutingPass.cs`](../tools/obfuscator/ExceptionRoutingPass.cs), the
`"exception-routing"` pass in policy. It finds the
`preset != "neutral" && preset != "mono" && preset != "warm"` chain in `Main` (3 `op_Inequality` plus
3 `brfalse`), and replaces it with a version that gets the same result by catching an integer
divide-by-zero in a try/catch, using `DivideByZeroException`, which, like the native side, causes
**no memory corruption at all** (no null-reference tricks or similar used).

**Detection method**: rather than a generalized "find and replace if-else" pass, it looks for the
`ldstr "unknown preset"` right before the `ArgumentException` constructor as a marker, then scans
backward from there for how many `ldloc;ldstr;call op_Inequality;brfalse` groups of 4 chain together
(with the same variable, same branch-target condition). In this program that comes out to 3. This is
the same principle as `IntegrityCheckPass`/`FunctionInliningPass` finding `ClampByte` by signature:
"handle exactly one known pattern precisely, don't generalize."

The new `try`/`catch` is nested so that it is **fully contained inside** the outer `try`/`catch` that
`Main` already had (the block that catches every `ArgumentException` and prints
`ERROR: {message}`).

## Bug found (the Nth this session)

### Bug: index-based deletion drifts after insertion

The first implementation recorded the old instruction range by index, then inserted new
instructions, then deleted by that index. The problem: once `InsertBefore` runs, **the indices of
every instruction after it shift**, but the deletion used the stale index that had been computed
*before* the insertion. Result: **the first half** of the newly inserted instructions got deleted,
and the original comparison chain wasn't removed at all, it stayed exactly where it was. 0 of 335
passed, entering "warm" still unconditionally produced "ERROR: unknown preset." `ilverify` judged
this "verifiable" too (structurally it was valid IL), so once again, only direct execution caught the
logic bug.

**Fix**: the instructions to delete are first collected into a list **by object reference**, not
index, and after insertion finishes, those objects are `Remove`d directly. Cecil's
`Remove(Instruction)` works by object identity, so index shifts from insertion don't affect it.

### A subtler bug: nested exception handler order

(Hit right when first designing this pass, separate from the bug above) ECMA-335 requires nested
exception handlers to be listed **innermost first** (II.25.4.6). Adding the new handler with
`body.ExceptionHandlers.Add(...)` appended it **to the end** (with the existing outer handler already
in the list, producing an "outer then inner" order), which threw `InvalidProgramException`.
`ilverify` again said "fully verified." Fixed by switching to `Insert(0, ...)`, putting the inner
handler at the front of the list.

## Verification

- `artifacts/protected-p1p2p3p5p6p7/PixelTone.exe` (all 18 passes combined): 335/335
  ([logs/verify-p1p2p3p5p6p7](../logs/verify-p1p2p3p5p6p7/summary.json)).
- `ilverify` against the full build: "All Classes and Methods Verified." (though, as confirmed twice
  in this section, this tool saying "verified" is no guarantee the actual CLR reaches the same
  conclusion; direct execution was the final confirmation.)
- Rebuilt repeatedly with the same policy to confirm byte-identical output (reproducibility).
- Confirmed both a valid preset (`warm`) and an invalid preset (`bogus`) produce exactly the same
  output as before (`70,141,219|8167D285` / `ERROR: unknown preset`, exit 2).

## Unexpected finding: REA doesn't show the exception handler's catch-type name in this command

Checking with REA `inspect-managed-members` shows that `Main`'s `exception_regions` field
**correctly shows the new handler with exactly the right nested structure** (the try range fully
contained inside the outer try): the structure itself isn't hidden. But that entry's `class_token`
appears **only as a raw metadata token (`0x0100000f`)**, and the name "DivideByZeroException"
**doesn't appear as a string anywhere** in this output. `MemberRef` call targets (e.g.
`ArgumentException..ctor`) do get resolved to names in this output, but the exception handler's catch
type doesn't seem to get resolved to a name by this particular command.

**This isn't something I deliberately hid**: it looks like this REA command simply doesn't resolve
catch-type tokens to names, whether it's `DivideByZeroException` or any other type (handled
differently from `MemberRef`). So, honestly noted: an analyst who wants to know what this token is
would have to look up the TypeRef table separately, a small but real extra step of delay.

## Limitations (honestly)

- **Shows up fine in disassembly/decompilation**: tools like IDA/dnSpy/ILSpy standardly recover
  exception handler ranges and catch types. If `try`/`catch(DivideByZeroException)` is visible right
  there, it's easy to raise suspicion ("why is this here?"), since it doesn't look like ordinary
  divide-by-zero guard code and is an unusual pattern to use in place of control flow.
- **Only one target**: applied only to `Main`'s preset validation. As with the native side, the same
  approach could be applied to other comparisons (e.g. `ReadInt`'s range check), but that's already
  inside an already-flattened, complex state machine, so it was left out of scope for this increment.
