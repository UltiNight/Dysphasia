# REA Reverse-Engineering Experiment on a Self-Made Windows Executable

2026-10-14, Dysphasia's first baseline

## Conclusion

We created an unprotected .NET executable of 5,120 bytes, built the official REA repository from source, and ran two separate static analysis passes against it. The two REA responses were completely identical. Two analysis agents, neither given the source, reimplemented the functionality in Python using the REA evidence plus separate CIL decoding, and each matched the original's stdout/stderr bytes and exit code in an independent evaluation of **335/335 cases**.

This result shows that functional reimplementation was possible for a small sample. **It is not an experiment that proves REA alone can restore the original C# source, replicate general-purpose Windows applications, or demonstrate the effectiveness of obfuscation.** Following the user's steps 1 through 5, we carried out baseline creation, reverse-engineering, repetition logging, result analysis, and planning of the obfuscation tool. Actual development of the obfuscation engine and comparison against a protected build are the next steps.

## Target and Experimental Environment

| Item | Value |
|---|---|
| Executable | `artifacts/baseline/PixelTone.exe` |
| Function | RGB channel brightness/contrast adjustment, neutral/mono/warm presets, result fingerprint |
| Form | Windows x64, PE32+ containing .NET Framework CIL, console program |
| Build | Optimizations enabled, no PDB, 6 methods, 5,120 bytes |
| SHA-256 | `b479f51478e8041f43a91a3a883238bef01a5c7d8917c65dfd3088ecb5a29c95` |
| MVID | `9d8850e2-7741-4869-8f48-b19bab20a9c1` |
| REA | 6.4.0, `500e32399a3bc827e17fb4adaa97db3bc0df29b5` |
| Analysis provider | `rea-dotnet-static`, version 1 |
| Host | Windows 11 build 26200, Node 24.13.1, npm 11.8.0 |
| Reimplementation language | Python 3.14.3 |

This is a configuration where the executable itself contains managed code, not a case of analyzing only a native-code EXE or a .NET apphost. Hopper, Ghidra, and ILSpy were not used. Dependencies were installed into the local repository; no global installation or Codex MCP configuration change was made. Detailed installation and compilation information is preserved in `reports/environment.json` and `artifacts/baseline/build-manifest.json`.

On the first build, the older Framework compiler rejected the `/deterministic` option. It succeeded after the option was removed, and that one successful binary was pinned and used for both analyses. There is no guarantee that the MVID or file hash will be the same on a rebuild.

## Procedure

1. Compiled our own `fixture/PixelTone.cs` into an optimized x64 EXE and confirmed normal execution.
2. Cloned the official `morluto/rea` and succeeded in lockfile-based dependency installation and building from source.
3. Identified the target with `inspect-managed-artifact`, then collected metadata/CIL clues with `inspect-managed-members`.
4. Repeated the same analysis on the same binary with a new CLI process. Saved all stdout/stderr, start/end times, exit codes, response hashes, and chunk-arrival logs.
5. Two independent agents, instructed not to view each other's records or the original source, first wrote a static reimplementation using each pass's evidence. Each then confirmed it with up to 8 direct execution probes. Both implementations were frozen without modification after the probes.
6. A separate evaluator ran the original and the two reimplementations against 335 inputs and compared the output bytes and exit codes. The reimplementation file hashes at the start and end of the evaluation also matched.
7. Wrote up, in `reports/obfuscator-plan.md`, the passes that could protect the exposed information, the compatibility risks, and the measurement plan.

Source non-disclosure was a **procedural separation**: each agent was given only the permitted inputs and told which paths were off-limits. It was not an isolation environment enforced by OS-level access permissions. The parent agent that wrote the sample did not write or modify the reconstruction code; it only ran the evaluation. The evaluation corpus was not disclosed to the people doing the reconstruction, but some generic boundary values may overlap with each one's 8 probes.

## What REA Actually Provided

| Observation | Quantity/Status | Interpretation |
|---|---|---|
| Managed code identification | `managed`, `cil`, x86_64 | Based on PE/CLI bytes, not the execution path or extension |
| Methods | 6 | Kept meaningful names such as `ClampByte`, `AdjustChannel` |
| Call relationships | 32 | Clues to the connections among input validation, channel processing, presets, and output |
| Strings | 11 | Exposed help text, preset names, errors, and the output format |
| Decoded CIL instructions | 292 | Provided per-method instruction counts and opcode frequency |
| CIL anchors included in the response | 115 | Selected instructions such as constants, calls, and branches; not the full sequence |
| metadata/coverage | `complete`, no issues | Completion of the static-check scope as defined by the tool |

`complete` does not mean original source restoration is complete or that all semantics have been verified. Using the body file offsets and IL hashes reported by REA, both analysts additionally decoded the EXE bytes to confirm the missing operation order. Each one's scripts and derived output are preserved under `reconstruction/pass01` and `reconstruction/pass02`. So the inputs to this reimplementation were **REA static evidence + supplementary CIL decoding + limited execution confirmation**.

REA's own static analysis never loaded or executed the target assembly. The subsequent probes and the independent evaluator did actually execute our own self-made EXE, but this was not a test of REA's dynamic analysis capability.

## Repetition Results and Timing

| Task | pass01 | pass02 |
|---|---:|---:|
| Artifact identification CLI | 9.046s | 1.455s |
| Member inspection CLI | 1.535s | 1.590s |
| Sum of the two CLI durations above | 10.581s | 3.045s |
| REA artifact response SHA-256 | Same across both passes | Same across both passes |
| REA member response SHA-256 | Same across both passes | Same across both passes |
| Independent analyst probes | 8/8 match | 8/8 match |
| Separate evaluation | 335/335 match | 335/335 match |

Each command was a fresh Node process. Since the OS cache was not cleared, the difference between the first run's 9.046s and the subsequent run's 1.455s cannot be read as a protection effect or a stable processing speed. Two observations are not used to estimate variance or general processing performance.

The analyst's initial static implementation was saved about 125 seconds after pass01's first read attempt, and about 68 seconds after pass02's first audit record. The time to the final document was about 627 seconds and 511 seconds respectively. Since the starting points are not identical, and documentation, tool waiting, and time-record corrections are all included, these are not used to rank the two sessions' speed or as a product SLA. pass02 is a lower bound because it is missing some read time from before the first audit record. That session's UTC parsing mistake was corrected with a `final_correction` field, leaving the original text in place.

CPU time, total process memory, and model token usage were not measured. The chunk log is not a log that traces every internal REA parser execution step or any private model's reasoning process.

## Independent Evaluation Composition

| Input group | Count | pass01 | pass02 |
|---|---:|---:|---:|
| Valid boundary-value combinations | 180 | 180 | 180 |
| Valid random input with a fixed seed | 120 | 120 | 120 |
| Number/preset parsing boundaries | 29 | 29 | 29 |
| Argument-count errors | 5 | 5 | 5 |
| Help | 1 | 1 | 1 |
| Total | 335 | 335 | 335 |

The comparison was not just on-screen strings; it required exact matches of stdout bytes including CRLF, stderr bytes, and exit code. It also included out-of-range values, invalid presets/casing, and signs, leading zeros, and some Unicode digits/whitespace. The result file is `logs/evaluation01/summary.json`, individual records are in `cases.jsonl`, and inputs are in `corpus.json`.

Since the corpus is now a local artifact disclosed for reproducibility, subsequent formal experiments will also need a new, undisclosed evaluation set. Passing 335 finite inputs is not a claim of equivalence across all inputs, CLR versions, and environment errors.

## Scope Confirmed by the Reimplementation

- The channel adjustment order, the 0..255 clamp, and truncation toward zero for negative integer division.
- mono's weights and rounding, and warm's channel offset and saturation handling.
- The 32-bit fingerprint calculation on the final channels and the uppercase hex output.
- Input ranges, preset case sensitivity, error priority, and exit codes.

The original comments, the developer's intent, file organization, and the original variable representations were not restored, and were never the target of restoration. The sample is a small, simple program at an analyzable scale, with `NoInlining` and similar attributes keeping function boundaries intact. It does not represent the difficulty of a large commercial program or obfuscated code.

## Decisions Reflected in the Plan

The first MVP is limited to a build tool that transforms the names, strings, and selected flow of .NET CIL. "Applies to any EXE" is not within the supported scope. Renaming alone leaves the constants and logic in place, so standalone/combined comparisons are needed. We need to measure both the preservation of correct behavior and the cost to an analyst of reimplementing the functionality.

The next experiment is to apply the same evaluation to a protected build, and to give an analyst who is forcibly isolated from the source and the answer key a new budget, to measure the delay effect. Native Windows PE and Ghidra need a baseline built as a separate track. The specific passes, exclusion rules, signature handling, and success criteria follow `obfuscator-plan.md`.

## Evidence and Sources

- Artifact evidence: `ev_b18495a6fa1885e00e264c079ae80b39fbdbaa1b55db071bc6c41298489d4d78`
- Member evidence: `ev_6a49f948b9d22f08595da7adb3ef28ec49957efedc7cfd9fc81814381d61875e`
- Raw REA results: `logs/pass01/`, `logs/pass02/`
- Measurement summary: `reports/rea-summary.json`
- Each analyst's additional decoding, judgment, and probes: `reconstruction/pass01/`, `reconstruction/pass02/`
- [Official REA repository](https://github.com/morluto/rea)
- [Managed code analysis contract for the commit used](https://github.com/morluto/rea/blob/500e32399a3bc827e17fb4adaa97db3bc0df29b5/docs/managed-code-analysis.md)

The experimental figures in this document were obtained from the local logs above; they are not figures quoted from the repository's promotional text.
