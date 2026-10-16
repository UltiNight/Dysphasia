# Semantic Poisoning (Deceptive Naming) + Homoglyph Injection

## Background

Two items from the user's technique list: "semantic poisoning" and "homoglyph injection." When we first
triaged these, we set them aside because the description, "disguise a malicious function under a
safe-looking name," didn't seem to fit this program (which has no malicious code). Looking again, though,
taking just **the disguise half** on its own is still a perfectly valid technique. Hiding what `ClampByte`
does and making `ClampByte` look like `SyncMetadata` so it **leads to a wrong conclusion** are two
different effects. P1's existing hash names (`m_22283830b7`) give off a feeling of "I don't know what this
is," but a plausible name gives off a feeling of "I know what this is (and I'm wrong)." Getting an analyst
to carry a wrong mental model deeper into the analysis costs more than giving them no feeling at all.

## Implementation

[`tools/obfuscator/DeceptiveNameGenerator.cs`](../tools/obfuscator/DeceptiveNameGenerator.cs). This is the
policy's `"deceptive-naming"` pass (use a plausible fake name) plus `"homoglyph-identifiers"` pass (replace
some of that name's Latin characters with Cyrillic lookalikes). It replaces P1's previous hash-based name
generation (switched conditionally within `Protector.cs`'s renaming loop).

**Plausible name pool**: `ValidateChecksum`, `SyncMetadata`, `RefreshToken`, `RegisterCallback`,
`ResolveDependency`, `AuthenticateSession`, and others. These are names that are actually common in real
code, but have nothing to do with any method in this program. They're assigned deterministically, one by
one, from a seed.

**Collision avoidance**: with only 6 methods and a pool of 15, the birthday paradox makes the collision
probability actually high (about 76% by calculation). The first implementation checked for collisions only
on **the final string after applying homoglyphs**, which resulted in `Fingerprint` and `Main` both getting
the same "InitializeCache"-family name, differing only in which homoglyph pattern was laid over it (to a
human skimming the screen, these look like two identical names). We fixed this to check for collisions on
**the base word itself** first, so that every name is lexically distinct. Homoglyphs are just extra
disguise layered on top, and the distinctness itself never depends on them.

**Homoglyphs**: a/e/o/p/c/x (including uppercase) are replaced with visually identical Cyrillic characters
(а/е/о/р/с/х), only some of them, seed-based per name and per position. **The scope is limited to private
members only**: since P1 already only renames private/non-public members, every name this pass touches is
already an internal identifier that isn't exposed externally. The real-world malicious use of homoglyph
injection (typosquatting by impersonating a package/identifier name) works by **impersonating a trusted
real name**, but here there is no "real name" to impersonate; these are already-obscured internal names
only, so that risk does not apply.

## Verification

- `artifacts/protected-p1p2p3p5p6p7/PixelTone.exe` (the full combination of 15 passes): 335/335
  ([logs/verify-p1p2p3p5p6p7](../logs/verify-p1p2p3p5p6p7/summary.json)).
- Re-verified the full build with `ilverify`: "All Classes and Methods Verified." (confirms the Unicode
  identifiers cause no problem at the CLR metadata level; IL member names are arbitrary UTF-8 strings that
  don't need to follow C# identifier grammar).
- Rebuilt with the same policy to confirm byte-for-byte identity (reproducibility).
- Ran the protected build directly: confirmed it produces the same output as before
  (`70,141,219|8167D285`).
- Confirmed that other passes' "find the target method by signature" heuristics (the integrity check and
  function inlining passes both locate `ClampByte` not by name but by the pattern "a 1-int-param method
  containing the literal 255") still work correctly after the name is changed to `SyncMetadata`. This shows
  that a design that doesn't depend on names composes correctly with this pass.
- Confirmed that REA's `inspect-managed-members` output shows the plausible fake names (`SyncMetadata`,
  `RefreshToken`, `RegisterCallback`, `ResolveDependency`, `AuthenticateSession`, etc.) exactly as given
  (`logs/deceptive-naming/after.stdout.json`).

## Limitations (honestly)

- **Plausibility breaks the moment analysis goes even a little deeper.** The instant REA shows that a
  method named `SyncMetadata` takes an `int`, returns an `int`, and contains only `255`/`0` comparisons
  internally, the mismatch between the name "metadata sync" and the actual shape becomes obvious. A name
  alone can't fool someone indefinitely; it only slows down the single analysis habit of "read the name
  first and move on."
- **Homoglyphs don't survive copy-paste or byte comparison.** If an analyst copies a member name to search
  for it, or compares two names byte by byte, "huh, this is a different character" shows up immediately. It
  only works when a human is skimming the screen visually.
- **The pool is small.** There are only 15 method names and 6 type names in the pool. This fixed source was
  small enough to be sufficient here, but a program with far more members would need a larger pool or a
  different generation rule.
