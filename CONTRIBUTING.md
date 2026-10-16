# Contributing to Dysphasia

This is a defensive security research project. It builds a small, fully-specified Windows program on purpose, points an AI reverse-engineering agent ([REA](https://github.com/morluto/rea), "Reverse Engineer Anything") at it, measures exactly what comes back, and adds one obfuscation technique at a time to see what that measurement actually costs the agent. Contributions are welcome. A few rules keep the results trustworthy, though, and they're not really optional. Participation here is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

## The rules

**Every change has to stay measurable.** A new pass isn't done just because it compiles. It needs to pass the full 335-case behavioral corpus with byte-for-byte output parity against `artifacts/baseline/PixelTone.exe` (`dysob verify` on the .NET side, the matching `scripts/evaluate-native-protectedN.py` on the native side), pass `ilverify` or build with `/W4` and zero warnings, build deterministically (same seed, same input, same bytes, across repeated runs), and come with a before/after REA measurement showing what specifically changed in what REA can recover. All four, every time.

**Nothing binary-unsafe.** This project has consistently picked the memory-safe option over the cleverer one. A deliberate integer divide-by-zero caught in a `try`/`catch` instead of a null-pointer trick, for instance. Keep doing that.

**Determinism isn't optional.** Don't derive a key, seed, or offset from anything process-randomized. `string.GetHashCode()` on .NET is the specific thing that broke this once already (see [the writeup](reports/string-pass-determinism-fix.md)). Use a seeded, deterministic hash like `SHA256` instead.

**Write down what doesn't work.** Every report in `reports/` ends with a limitations section. If a change doesn't fully deliver what the technique is supposed to, say so and explain why, rather than making the headline number look better than the reality.

**Declined stays declined without a new argument.** A handful of catalogued techniques (anti-disassembly, timing checks, anti-dump, self-modifying code, JIT decryption, environmental entanglement, anti-VM/sandbox, white-box cryptography, prompt injection in code, safety-guardrail tripping, C++ template metaprogramming) were deliberately left out. See [why, in the README](README.md#declined-techniques). Reopening one needs an actual technical argument for why the original objection stopped applying, not just "it's still on the list."

## Building and running it

```powershell
# build the obfuscator CLI
Set-Location tools\obfuscator
dotnet build -c Release

# apply a policy to the baseline fixture
dotnet bin\Release\net10.0\dysob.dll protect ..\..\artifacts\baseline\PixelTone.exe `
  --policy policies\pixel-tone.full.json --out ..\..\artifacts\protected-dev

# check it against the 335-case corpus
dotnet bin\Release\net10.0\dysob.dll verify ..\..\artifacts\baseline\PixelTone.exe ..\..\artifacts\protected-dev\PixelTone.exe `
  --corpus ..\..\logs\evaluation01\corpus.json --out ..\..\logs\verify-dev
```

`dysob list-passes` prints every pass name it recognizes, grouped by category, each pointing at its report.

For the native track, use the matching `scripts\build-native-fixture-protectedN.bat` and `scripts\evaluate-native-protectedN.py` pair.

## Adding a pass

Put it in its own file under `tools/obfuscator/`, following the existing convention: `XyzPass.cs`, a `static Apply(...)` entry point, a small `XyzPassResult` to report what it did. Wire it into `Protector.cs` behind a named entry in the policy's `passes` list, in the right pipeline position (there's an ordering comment at the top of `Protect()`; some passes genuinely have to run before others, e.g. `function-inlining` before `control-flow`, or things break). Write a report at `reports/<pass-name>.md` (English) using the existing structure: background, implementation, bugs found (if any), verification, limitations. Add a row to the table in `README.md`.

## Filing an issue

What you expected, what happened, the exact command you ran, and, if it's a correctness regression, which of the 335 corpus cases fails.
