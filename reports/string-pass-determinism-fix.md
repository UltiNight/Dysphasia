# The P2 (String Encoding) Nondeterminism Bug: the "Same Seed, Same Build" Promise Was Broken

## How It Was Found

After adding the [MBA constant obfuscation](mba-constants.md) pass, I ran three consecutive builds to re-confirm that "running `dysob protect` repeatedly with the same input and the same policy should produce a byte-identical result." **Every run produced a different hash** (`MbaReplacedConstants` was also tallied differently each time: 43/45/46). Narrowing the cause down by binary-searching, removing passes one at a time, showed it only happened when `"string-encode"` (P2) was turned on.

## Cause

The XOR key derivation chain in [`StringPass.cs`](../tools/obfuscator/StringPass.cs):

```csharp
var key = KeyFor(seed, literal.GetHashCode());   // ← literal.GetHashCode()
...
private static byte KeyFor(long seed, int ordinal) =>
    (byte)(NameGenerator.Generate(seed, $"__strkey__{ordinal}", "").GetHashCode() & 0xFF);  // ← here too
```

Both places go through **a string's `GetHashCode()`**. Since .NET Core 1.0, string hash codes have been **randomly seeded per process** (the purpose is defense against hash-flooding denial-of-service attacks), meaning `"TryParse".GetHashCode()` can return a different value *even across two runs of the same program*. Since this key is used to XOR-encode each literal, **running `dysob protect` twice with the same seed and the same input produced different bytes every time**. The value (functionality) was always correct (whatever the key was, the decoder reverses it with the same key, so 335/335 always passed), but the binary itself was not reproducible.

**Scope of impact**: every build that used the `string-encode` pass: `artifacts/protected-p1p2/`, `artifacts/protected-p1p2p3/` (including the exact file that pass03 through pass07 analyzed), and the entire `protected-p1p2p3p5` family built in this session. This means that **half** (the same-seed half) of the reproducibility promise made by [P4 (per-build variation plus a mapping store)](p1-p2-measurement.md), "same seed → same build, different seed → different build," was false from the start. That said, this promise had never actually been tested in both directions: the existing measurement (the P4 section) only confirmed that "seed A and seed B produce different names," and never verified that "building seed A twice produces identical bytes." So this bug stayed hidden throughout the project, never once surfacing.

The same pattern had been copied verbatim into the `KeyFor` of [`BclCallHidingPass.cs`](../tools/obfuscator/BclCallHidingPass.cs), added in this session (because I referenced StringPass's pattern and copied it as-is). Fixed at the same time.

## Fix

In both places, I completely removed "a string's `GetHashCode()`" and changed it to hash the literal's own UTF-8 bytes directly with SHA256:

```csharp
private static byte KeyFor(long seed, string literal) =>
    System.Security.Cryptography.SHA256.HashData(
        System.Text.Encoding.UTF8.GetBytes($"strkey:{seed}:{literal}"))[0];
```

SHA256 always produces the same output for the same input bytes, regardless of platform, process, or when it runs. This is the same property this entire project already depends on (all name generation and seed derivation is SHA256-based).

## Verification

- Built **three times in a row** with the same policy (`pixel-tone.full.json`, including all 6 passes). All three produced a byte-identical SHA256 (`8010823f617b...`). Before the fix, all three differed.
- Re-verified behavior preservation at 335/335; this was always true both before and after the fix (this bug never broke functionality, only reproducibility).
- Rebuilt `artifacts/protected-p1p2p3p5/`, `protected-p1p2p3p5p6/`, and `protected-p1p2p3p5p6p7/` with the fixed pass. Re-verification at 335/335 complete. **`artifacts/protected-p1p2p3/` (the file pass03 through pass07 analyzed) was left untouched**, to preserve what bytes those reports actually analyzed.

## Limitations (honestly)

- With this fix, "same seed → same build" becomes true **from here on**. Every build made in the past that used string-encode (including `protected-p1p2p3`) is simply fixed to whatever key the process happened to pick at that time, and is not reproducible on its own. That doesn't mean those files can't be re-created; it means the assumption that "running protect again with the same policy file would produce the same bytes as back then" was wrong. Fortunately, nothing else depended on that assumption: crash-symbol reverse lookup records `OutputSha256`/`OutputMvid` in the mapping file as "the value that actually came out," so it always works regardless of reproducibility.
- I grepped all of `tools/obfuscator` to check whether `.GetHashCode()` was used anywhere else besides the two `KeyFor` methods (StringPass, BclCallHidingPass), and these two were all of them. `ControlFlowPass`'s shuffling and MBA's constant derivation were both SHA256-based from the start, so they don't have this problem.
