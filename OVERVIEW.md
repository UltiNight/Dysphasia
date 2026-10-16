# What Dysphasia actually is (plain-language version)

This document explains the project without assuming any programming background. For the technical version, see [README.md](README.md).

## In one sentence

This project tests, with actual numbers, how easily an AI can look at a program and figure out what it does, and how much slower (and more error-prone) that gets once the program is deliberately made confusing.

## What is REA

[REA](https://github.com/morluto/rea) is an AI tool that takes a program and figures out what it does, without needing the original source code (the human-readable instructions a programmer wrote to build it in the first place). Work that used to take a human analyst hours can now be attempted by an AI much faster and much more cheaply. This project ran experiments against that specific AI.

## Why run this experiment

Someone's program can be copied or have its inner workings exposed by anyone who points an AI at it. There have long been ways to make a program harder to analyze, but nobody had carefully checked whether those tricks, which work against human analysts, work just as well against an AI. This project checked that directly, with measurements instead of assumptions.

## How the experiment worked

1. A small program was built on purpose. It's called "PixelTone," and all it does is take a few numbers representing a color and return a calculated result.
2. REA was pointed at the unprotected version first, with no tricks applied at all.
3. Then, one technique at a time, the program was made harder to read. Renaming variables and functions to meaningless text, hiding text messages like a cipher, and deliberately tangling the order the program runs in are examples.
4. Every time a technique was added, the first check was always whether the program still behaved exactly like the original. If the output changed, that's not protection, that's just breakage. 335 different test cases were run every single time to confirm nothing broke.
5. Then REA was pointed at the new version to see whether that technique actually made it harder for REA specifically, not just in theory.

## What do names like pass01 or pass02 mean

The project's records are full of names like pass01, pass02, protected-p1, and p1p2. They look complicated, but the idea is simple: they're just numbers marking which attempt something was. pass01 is the first analysis attempt on record. p1 is the build with only the first protection technique (renaming) applied. p1p2 adds a second technique (hiding text) on top of that. None of it is special jargon, it's just a label for keeping track of order.

## What were the results

- The unprotected program was analyzed quickly by REA.
- The protected program took more than twice as long on average, measured across five separate, independent attempts.
- Two of those five attempts didn't even get it fully right, and they made the exact same mistake in the exact same spot.
- Not every protection technique worked. Some turned out to do nothing at all, and that was written down honestly instead of being left out.

## Is this a hacking tool

No. This project isn't built to attack anyone or trick an AI into doing anything dangerous. The only target was a tiny test program built specifically for this, and the techniques that could actually cause real harm to someone else were ruled out from the start. Every technique that was deliberately left out, and why, is written down in the README.

## Where to read more

- The full technical writeup and results table are in [README.md](README.md).
- The numbers, laid out plainly, are in [BENCHMARKS.md](BENCHMARKS.md).

## A few terms that still come up

Short definitions only. See the documents above for the precise versions.

- Source code: the human-readable instructions a programmer writes to build a program.
- Binary (executable file): source code converted into a form a computer can run directly. People generally can't read it as-is.
- Reverse engineering: looking at a binary and working backward to figure out what the original source code must have looked like.
- Obfuscation: changing how a program looks, without changing what it does, so that it's harder for a person or an AI to read and understand.
- Pass: one single obfuscation technique. People say things like "the renaming pass" or "the string-hiding pass."
- Corpus: the set of test inputs used to check that a program still behaves exactly as it did before. This project used 335 of them.
- Seed: a value that, when reused, makes a process produce the exact same result every time. Think of it like pre-setting the numbers on a lottery machine ahead of the draw.
