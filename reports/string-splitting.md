# String splitting/combination

## Background

The "string splitting/combination" item from the user's technique list. The existing P2 (string
encoding) encodes each literal as one contiguous span in the blob (offset, length, key) and restores
it with **a single `Decode` call**. This technique goes one step further: it splits a long literal
into **two pieces, stored separately in different spans of the blob (each using a different key)**,
and at the call site, **decodes twice and then joins them with `String.Concat`**.

## Implementation

Extends [`tools/obfuscator/StringPass.cs`](../tools/obfuscator/StringPass.cs): when
`"string-splitting"` is enabled in policy and a literal is 6 characters or longer, it's cut in two at
a seed-chosen point, and each half is encoded independently (with its own length, offset, and XOR
key). The call site becomes:

```
ldc.i4 offset1; ldc.i4 length1; ldc.i4 key1; call Decode   // first piece
ldc.i4 offset2; ldc.i4 length2; ldc.i4 key2; call Decode   // second piece
call System.String::Concat(string, string)
```

Short literals (under 6 characters) aren't split, since each piece would end up just 1-2 characters
and gain nothing, so they're encoded in one shot as before. The existing `string-encode` is a
prerequisite (it reuses the shared blob/decoder as is), and `string-splitting` is an increment on top
of it that only changes "how some literals are stored."

## Verification

- `artifacts/protected-p1p2p3p5p6p7/PixelTone.exe` (all 10 passes combined): 335/335
  ([logs/verify-p1p2p3p5p6p7](../logs/verify-p1p2p3p5p6p7/summary.json)).
- First confirmed 335/335 on a standalone build with only `rename`+`string-encode`+`string-splitting`
  turned on.
- Rebuilt repeatedly with the same policy to confirm byte-identical output (reproducibility).
- Confirmed by dump that the "two Decode calls plus Concat" pattern actually appears in 10 places.
  REA `inspect-managed-members` also catches the `String::Concat` call the same way
  (`logs/string-splitting/after.stdout.json`).

## Limitations (honestly)

- **Adds almost no additional concealment over P2**: P2 already fully encoded the literal, leaving
  no plaintext behind. Splitting only turns "one Decode call" into "two Decode calls plus a Concat."
  What an analyst ultimately has to figure out (the blob, the decoder, the key-derivation method) is
  identical either way. Static grepping is blocked by both, and direct execution/decoding breaks
  both. From a "buying time" standpoint, the extra delay added is as small as "following one more
  Concat call."
- **Fixed split point**: each literal is split only once (into two pieces). Splitting into three or
  more pieces, or shuffling piece order, wasn't done as an additional variation.
