# Native track: anti-debugging + dynamic API resolving

## Background

"Hiding API calls (Dynamic API Resolving)" from the user's technique list: an item deferred earlier in the [loop unrolling/pointer aliasing report](native-loop-unroll-pointer-alias.md). Reason: the CRT functions this program calls directly (`wprintf`, `fwprintf`, `wcscmp`, `wcslen`) are all statically linked via `/MT`, so **there was no existing import at the source-code level worth hiding in the first place**. The only natural target would have been reimplementing console I/O directly, and that carried CRLF-bug-level risk this project had already run into once.

Looking again this time, **a newly added feature** could be a natural target: adding the native counterpart to [anti-debugging](anti-debugging.md), which previously existed only on the .NET side, and resolving that call (`IsDebuggerPresent`) dynamically via `GetModuleHandleW`+`GetProcAddress` instead of a static import creates **a real call site that this source code directly controls**.

## Implementation

Using [`fixture/PixelTone.protected5.c`](../fixture/PixelTone.protected5.c), based directly on `PixelTone.protected4.c` (exception-based routing), two things were added:

1. **Anti-debugging**: calls `IsDebuggerPresent()` at the very start of `wmain`, on the same basis as the .NET-side `Debugger.IsAttached` check (this project's verification script runs as a plain subprocess with no debugger, so this is always false across the entire 335-case corpus, with no conflict with the existing measurements). Only the function name string (`"IsDebuggerPresent"`) was hidden, with the same XOR encoding as P2.
2. **Dynamic API resolving**: resolves the call above not as a static import but via `GetModuleHandleW(L"kernel32.dll")` + `GetProcAddress(..., decoded name)`.

## Finding: the measurement didn't come out as expected (honestly)

Checking with `dumpbin /imports` showed that **`IsDebuggerPresent` was still left in the import table**, and it was already there in the **fully unprotected baseline** (`artifacts/native-baseline/`), which never calls this function from source at all! UCRT/VCRuntime's own startup code already imports this function for internal diagnostics, so regardless of whether my code resolves it dynamically or not, this import **is always there for the CRT's own reasons**. In other words, the technique itself was implemented correctly at the source level (my call site goes through `GetProcAddress`, not a static call), but the observable evidence of "showing it disappear from the import table" was never something that could hold for this particular API in the first place, because the CRT already carries that name for an unrelated reason.

This finding is useful on its own: **a name being in the import table isn't necessarily evidence that "this program uses that function statically."** It can be CRT boilerplate, and that's indistinguishable from a program, like this one, that also uses the same name dynamically. The moment an analyst dismisses it with "that's just a common name the CRT imports anyway," how the program **actually uses that function** stays hidden regardless.

## Fix: adding a second, cleanly verifiable case

To avoid this measurement problem, added one more completely new DLL dependency that **neither this program nor the CRT already uses for any reason**: `GetSystemMetrics` from `USER32.dll`, since this is a console-only program that doesn't use `USER32.dll` at all otherwise. It's resolved only via `LoadLibraryW`+`GetProcAddress`, and the return value is discarded immediately (the same "never observably used computation" safety principle as the garbage-data/token-bloating passes).

## Verification

- Built with MSVC via `scripts/build-native-fixture-protected5.bat` (`/O2 /MT /W4`, 0 warnings).
- Compared all 335 corpus cases with `scripts/evaluate-native-protected5.py`: **335/335 match** ([logs/verify-native-protected5](../logs/verify-native-protected5/summary.json)).
- Confirmed with `dumpbin /imports` that **`USER32.dll` is entirely absent from the import table**, the same as the fully unprotected baseline (it wasn't there before and isn't there now, but it's actually loaded and called at runtime).
- Also confirmed with `dumpbin /imports` that `IsDebuggerPresent` was present from the baseline onward (the basis for the "Finding" section above).
- Ran it directly: confirmed identical output to before for normal input, `--help`, and an invalid preset.

## Limitations (honestly)

- **The `IsDebuggerPresent` case can't prove "hidden" via the import table**: as explained above, the implementation is correct at the source level, but the observable evidence never held for this particular API in the first place.
- **Dynamic resolution is itself a pattern**: a `LoadLibraryW`+`GetProcAddress` call sequence stands out immediately in a disassembly as a signal that "this program is dynamically hiding something." Tools like IDA recognize this pattern as a matter of course, and following it through to the string decoder (a limitation already acknowledged in P2) reveals exactly which function it is right away. This only blocks static grepping, not a determined analysis.
- **The `GetSystemMetrics` call serves no real purpose**: it's unrelated to the program's actual functionality and was added purely to demonstrate the technique cleanly. Noting that this is the first time this project has added code purely "to show a technique" (every other increment so far only transformed part of the actual program logic, without adding new functionality).
