# Code virtualization (miniature version)

## Background

"Code virtualization (VMP)" from the user's technique list: "fully translate the original assembly into custom bytecode for an independently designed virtual machine." At first this was deferred, on the judgment that **correctly translating arbitrary IL into a custom instruction set is effectively a small compiler backend** (it has to handle arbitrary call targets, exception regions, floating point, boxing, and more), making it a multi-week undertaking for this fixed 115-line research source. That judgment still holds for a **generalized virtualization pass**. But applying the pattern used throughout this session (handling one small, well-defined target like `ClampByte` properly by hand) meant a **miniature version** was actually something that could be done.

## Implementation

[`tools/obfuscator/CodeVirtualizationPass.cs`](../tools/obfuscator/CodeVirtualizationPass.cs), the `"code-virtualization"` policy pass. `ClampByte`'s logic (`if v<0 return 0; if v>255 return 255; return v;`) was hand-assembled directly into a hand-designed, 8-instruction stack-machine instruction set:

```
0x01 PUSH_ARG            push the argument onto the stack
0x02 PUSH_CONST <i32>    push a constant
0x03 LT                  pop b,a; push (a<b)?1:0
0x04 GT                  pop b,a; push (a>b)?1:0
0x05 JZ <i32 target>     pop cond; if cond==0, jump to target
0x06 JMP <i32 target>    unconditional jump
0x07 RET_CONST <i32>     return a constant and halt
0x08 RET_ARG             return the argument itself and halt
```

A single 35-byte program was **first hand-assembled in Python and verified by simulation to produce results identical to the real `ClampByte` across boundary values plus 59 random inputs**, and only then were those exact bytes embedded into the module with Cecil. The entire body of `ClampByte` is replaced with 3 lines that hold a bytecode array and call an interpreter. The interpreter (`Interpret`) is another method, also hand-written with Cecil, built from a fixed 8-slot `int[]` stack, `sp`/`pc` local variables, and a `switch` dispatch with one branch per opcode.

**None of the other call sites are touched at all**: everywhere `ClampByte` used to be called is still just `call ClampByte(x)`. Only `ClampByte`'s **own insides** changed, so this pass was able to move the entire logic into data (bytecode) without changing the function's signature or calling convention at all.

**Why this was not generalized, once more**: this is not a "virtualize any method" pass. Just like `IntegrityCheckPass`/`FunctionInliningPass`, it finds `ClampByte` by signature and hand-translates **only that one method**. A general backend that correctly translates arbitrary IL (including calls, boxing, exceptions, array indexing, and more) is still out of scope.

## Why this was not combined with `function-inlining`

`FunctionInliningPass` also finds `ClampByte` using **the exact same signature heuristic** ("takes one int, returns an int, contains the literal 255"). Turning both on: if virtualization runs first, `ClampByte`'s body becomes `ldarg; call Interpret; ret`, **the 255 literal disappears**, and when inlining later tries to find that method, the signature match fails and nothing gets inlined (in the reverse order, virtualization would end up applying to a copy nobody calls anymore, making it pointless). This is a real conflict that arises because the two techniques rest on different assumptions, so they were kept separate in `pixel-tone.full.json` rather than combined, and **verified independently**. This simply acknowledges the same kind of trade-off found earlier in this session between control-flow flattening and inlining.

## Verification

- `artifacts/protected-p1-code-virtualization/PixelTone.exe`: 335/335 ([logs/verify-p1-code-virtualization](../logs/verify-p1-code-virtualization/summary.json)).
- Verified the full build with `ilverify`: "All Classes and Methods Verified."
- Rebuilt with the same policy repeatedly and confirmed byte-identical output (reproducibility).
- Confirmed via dump that `ClampByte`'s new body is exactly `ldarg.0; call Interpret; ret` (3 instructions): no comparisons (`clt`/`cgt`), no branches, and no `255`/`0` constants are visible at all.
- Confirmed the same thing via REA's `inspect-managed-members`: `il_size: 7`, `instruction_count: 3`, `opcode_counts: {ldarg.0:1, call:1, ret:1}`. To REA's static analysis, `ClampByte` looks like nothing more than "passes its argument to another method and returns the result." To learn the real logic, you have to **separately locate the interpreter method and the bytecode array, and interpret the meaning of every single byte by hand** (`logs/code-virtualization/after.stdout.json`).

## Limitations (honestly)

- **Only one target, not generalized**: as explained above. What can honestly be claimed as "implemented VMP" is "hand-translated one method, `ClampByte`, into bytecode and made it return correctly," not "virtualized this entire program."
- **The interpreter itself is plain, ordinary CIL**: the `Interpret`/`ReadInt32` methods are not hidden. REA can inspect these two methods just as easily, and nothing stops a determined analyst from reading the interpreter's 8 switch cases and reverse-engineering the opcode meanings. The bytecode array itself is not encrypted either (applying an XOR layer like P2 was left out of scope for this increment).
- **One trace through a debugger is all it takes**: stepping through the interpreter once reveals the meaning of all 8 opcodes. That is a delay consistent with the "time fight" premise, not the "complete concealment of the original" ideal that VMP aims for.
