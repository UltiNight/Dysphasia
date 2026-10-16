# Native track: exception-based routing

## Background

The "exception-based routing" item from the user's technique list: "deliberately cause an error instead of using if-else, and continue control flow from a try-catch block." On the .NET side, [control-flow flattening](opaque-predicates-and-cff-fix.md) has a safety rule that "methods with exception handlers are not flattened" (which is exactly why Main is excluded), so adding this technique to .NET IL would collide directly with that rule. The native track has no such constraint, so it was applied right away.

## Design decision: a division exception, not memory corruption

The textbook implementation of this technique usually triggers an exception by deliberately causing **memory corruption**, such as a null pointer dereference. This increment **does not use that approach**. If exception handling behaves even one byte differently than expected (OS protection features, debugger interference, and so on), there is a real risk of it turning into an actual memory error, which conflicts with the "don't use tricks that gamble on correctness" principle this session has kept to throughout. Instead, it uses **integer division by zero**. On x86, `idiv` dividing by zero always raises a well-defined `#DE` (divide error) fault, and Windows always translates that into `EXCEPTION_INT_DIVIDE_BY_ZERO`. It is a completely safe hardware trap that never touches a memory address at all.

## Implementation

[`fixture/PixelTone.protected4.c`](../fixture/PixelTone.protected4.c), built directly on top of `PixelTone.protected3.c` (loop unrolling plus pointer aliasing) as its base, changing one spot: the preset validation in `wmain`:

```c
static int preset_is_valid(const wchar_t *preset) {
    int valid = (wcscmp(preset, STR_NEUTRAL) == 0 || wcscmp(preset, STR_MONO) == 0 ||
                 wcscmp(preset, STR_WARM) == 0) ? 1 : 0;
    int ok = 1;
    __try {
        volatile int denom = valid;
        volatile int probe = 100 / denom;  // an exception is raised if valid==0
        (void)probe;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = 0;  // the fact that it's "invalid" is learned by catching an exception, not by a conditional
    }
    return ok;
}
```

`volatile` prevents `/O2` from deciding this is "a division whose result is never used" and deleting it outright. This uses MSVC's `__try`/`__except` (Structured Exception Handling, SEH): since it's a C-level Microsoft extension rather than a C++ exception, it works under the existing build settings with no extra flags like `/EHsc` needed.

## Verification

- Built with MSVC via `scripts/build-native-fixture-protected4.bat` (`/O2 /MT /W4`, 0 warnings).
- Compared against the full 335-case corpus with `scripts/evaluate-native-protected4.py`: **335/335 match** ([logs/verify-native-protected4](../logs/verify-native-protected4/summary.json)).
- Directly re-confirmed by execution that **5 invalid-preset cases** in the corpus (`Warm`, `MONO`, an empty string, and others) actually take the exception path (`exit 2`, `ERROR: unknown preset`). This confirms not merely that "the valid paths pass," but that **the catch path itself works correctly**.
- Confirmed both valid presets and `--help` produce the same output as before.

## Limitations (honestly)

- **Still visible to a disassembler/debugger**: recovering `__try`/`__except` blocks is a standard feature of IDA and Hex-Rays. Because the SEH frame structure itself is recorded in the PE's exception-handling tables (`.pdata`/`.xdata`), native analysis tools can tell right away that "this is an exception-based branch." What this technique slows down is the habit of scanning code by eye looking for `if`, not actual disassembly analysis.
- **Only one target**: this was applied only to the one preset-validation spot in `wmain`. Other comparisons, such as the range check in `read_int`, could be converted the same way, but since they already sit inside a complex state machine, they were left out of scope for this increment.
- **Performance cost**: entering and leaving an SEH block is slower than an ordinary conditional. For a low-call-frequency point like in this program the cost is negligible, but generalizing this would need measurement.
