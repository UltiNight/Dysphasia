# Dysphasia: planning a tool to raise the analysis cost of Windows programs

Written as of: 2026-10-14, REA 6.4.0 / `500e32399a3bc827e17fb4adaa97db3bc0df29b5`.

## Product goal and initial scope

The goal is to raise the cost required to understand and reconstruct the implementation from a distributed build of a program one owns. Success is not defined as "REA produced an error." A legitimate user gets the same result while an analyst has to do more exploration and verification. If a feature's external inputs and outputs are public, a similar feature can be built without reconstructing the obfuscated internal implementation, so we keep separate metrics for feature mimicry versus implementation reconstruction.

This round's baseline is a small, managed .NET Framework PE for Windows x64. These results do not generalize to C/C++, Rust, NativeAOT, Unity IL2CPP, Electron, or Photoshop-scale programs. The first MVP is also limited to **post-build processing of ordinary CIL-based .NET assemblies**. It starts as a tool users apply to their own builds, and makes no promise to handle arbitrary Windows EXEs in general.

This experiment does not rule on legal infringement or whether a given feature is patented. Technically observable functionality, implementation information left in the binary, and reproduction of the original code or resources are each separate things to be evaluated.

## Attack path observed on the baseline

1. REA identifies the PE/CLI headers, SHA-256, MVID, and metadata.
2. Meaningful type/method names and strings immediately narrow down feature candidates.
3. For each method, it obtains constant/call/branch anchors, opcode counts, body file locations, and hashes.
4. The analyst can additionally decode the missing instruction order from the binary's CIL. The `complete` field in REA's output describes the scope of that tool's own contract; it does not mean the full C# source is provided.
5. Port the implementation to another language and compare it against the executable's input/output.

Even without the original PDB, the managed metadata and the CIL itself serve as clues. So stripping debug symbols alone cannot be claimed as analysis resistance. The actual figures and reconstruction accuracy are based on the accompanying `experiment-report.md`, the raw evidence, and the evaluation logs.

## MVP composition

`Input inspection -> protection exclusion rules -> transform plan -> transform -> independent output -> behavior verification -> comparison report`

| Component | Behavior | Information it must record |
|---|---|---|
| Input inspector | Checks PE/CLI and supported runtime, examines signing, resources, and dependencies | Input hash, reason supported/rejected, scope of what gets protected |
| Policy file | Specifies protection level, excluded types/members, build seed | Policy version/hash, seed, reasons for exceptions |
| Transform engine | Applies the selected passes in order | Per-pass results and the list of modified members |
| Mapping storage | Keeps the name/location correspondence table separate from the distributed build | Location/hash of the reverse-mapping file, retention policy |
| Verifier | Runs the same inputs and regression tests against the original and protected builds | stdout/stderr/exit code, file/protocol results |
| Analysis benchmark | Gives REA and additional analysis tools the same budget | Tool version, commands, evidence, reconstruction accuracy, time |
| Report | Shows protection effect and cost together | Performance, size, compatibility, unverified items |

We start by building a reproducible CLI, and add a GUI later as a thin screen that just shows this pipeline and its logs. The draft CLI commands are `inspect`, `plan`, `protect`, `verify`, `benchmark`, and `report`. The CLI and obfuscation engine described in this document are a design proposal and are not yet implemented.

The assembly-editing library will be decided between the Mono.Cecil or dnlib candidates after a separate compatibility experiment. Checking version, license, and maintenance status is a precondition for starting implementation. It generates a new output directory rather than overwriting the original, and it stops with a stated reason on any unsupported input.

## Protection pass priority

| Order | Technique | Expected effect / hypothesis to measure | Risks and constraints |
|---|---|---|---|
| P0 | Check distributed symbols, paths, and unnecessary diagnostic information | Reduces side clues such as source locations | No added effect if the information is already absent; keep internal debugging material stored separately |
| P1 | Rename non-public type/member names | Delays feature discovery via meaningful names | Must exclude/verify reflection, serialization, plugin contracts, XAML bindings |
| P2 | Transform the representation of selected strings/constants | Reduces key clues available from static string search | Plaintext remains present in the restore routine and at runtime; not a cryptographic secrecy guarantee |
| P3 | Transform the control flow of selected methods | Increases the cost of interpreting instruction order and branches | Affects JIT, exception handling, debugging, and performance; must not be applied globally |
| P4 | Manage per-build variation and mappings | Increases the cost of reusing analysis results from a previous build | Requires reproducibility for the same seed, crash reverse-mapping, and support cost |

Each pass is compared separately across **the original, the pass alone, and the cumulative combination**. Even after renaming, matching can still succeed if the constants and structure stay the same, so we don't score mere surface illegibility as an effect. Re-identification risk is also checked using REA's `compare-managed-members` and evidence tied to the new hash/MVID.

General compression/packing, anti-debugging, VM detection, antivirus evasion, and kernel drivers are not in the first MVP. This experiment did not measure the effects of those, and the hypothesis to prove first is reduced exposure of metadata and CIL. Moving core logic to a server is treated as a separate product decision, since it changes offline-capability, cost, latency, and privacy requirements.

## Compatibility and signing

- public APIs, reflection names, serializer contracts, resource names, COM/PInvoke, WPF/XAML, and library loading are managed through protection exclusion rules and regression tests.
- For files with strong-name/Authenticode signing, we do not assume the existing signature survives the transform. The MVP, which has no verifiable re-signing pipeline, rejects these outright. Keys or certificates are never included in the distributed build or logs.
- After transformation, we verify CIL integrity, exception regions, dependent-assembly loading, and both normal-exit and error paths.
- Large files, mixed mode, single-file bundles, NativeAOT, and IL2CPP are explicitly treated as unsupported at the outset.

## Evaluation design

The two sessions so far were separated procedurally to keep source out of view, but this was not enforced by file access permissions. The formal evaluation will use a separate working directory/account containing only the executable and public inputs/outputs. The analyst is not given the original source, the detailed mapping from the protection settings, the answer key, or records from other analysis sessions.

| Metric | Definition |
|---|---|
| Time to understand functionality | Time until the first well-grounded correct answer is submitted to a predetermined question |
| Time to complete reconstruction | Time until the first candidate that satisfies a fixed verification criterion is submitted |
| Reconstruction accuracy | Match rate of stdout/stderr/exit code and key results on undisclosed inputs |
| Analysis cost | Number of tool calls, execution time, tokens when usage is available; unmeasured values left blank |
| Protection cost | Throughput/latency, startup time, file size, memory, compatibility regressions |
| Persistence | How far a previous build's analysis/name-mapping can be reused on the next build |

The proposed initial pass criteria are as follows. **These are not values that have already been achieved or measured.**

- 100% pass rate on product regression tests for both the original and protected builds. This covers both valid inputs and error handling.
- The exploratory target is a 3x increase in the median reconstruction completion time across at least 5 independent sessions/conditions. Use the same budget, the same analysis tools, and unseen samples of equal difficulty, and randomize condition order.
- If reconstruction is not completed within budget, do not treat the time as infinite; report it as a censored observation. If a median cannot be computed, show only a lower bound.
- The proposed initial performance budget is within 10% throughput degradation on representative tasks and within 20% file size increase. Adjust once real user workloads are available.
- Repeating the same binary alone cannot separate the learning effect from the protection effect, so learning carryover must be controlled for. If a CIL parser errors out but the case is easily resolved by a different decompiler or by dynamic observation, count it as a failure.

## Implementation stages and completion criteria

1. **Current baseline:** the executable, two rounds of raw REA evidence, reconstruction and verification, and a limitations document. Obfuscation effect is not yet measured.
2. **Strengthen the benchmark:** add different small samples (file conversion, state persistence, etc.), enforce source isolation, fix questions/budget, and add a second analysis tool. Measure pre-protection variance first.
3. **Renaming MVP:** exclusion policy, output preservation, mapping storage, rejection of signed inputs, identical-behavior verification. Evaluate how quickly REA still tracks the logic even with new names.
4. **String/selective control-flow transforms:** experiments both standalone and in combination. Passes that exceed the performance/compatibility budget are excluded from the defaults.
5. **Native Windows track:** build a separate baseline using a small C/C++ x64 PE and a Ghidra setup. If a source/build pipeline is available, prioritize reviewing compiler IR passes first. Post-hoc rewriting of an arbitrary PE, handling relocation, unwind info, CFG, and signing, is a separate research effort.

The schedule is organized by work stage, and this is not to be taken as meaning effect verification for the native track or at commercial-app scale is complete.

## References

- [REA source pinned for the experiment](https://github.com/morluto/rea/tree/500e32399a3bc827e17fb4adaa97db3bc0df29b5)
- [Managed code analysis contract](https://github.com/morluto/rea/blob/500e32399a3bc827e17fb4adaa97db3bc0df29b5/docs/managed-code-analysis.md)
- [CLI and Evidence](https://github.com/morluto/rea/blob/500e32399a3bc827e17fb4adaa97db3bc0df29b5/docs/cli.md)

The expected effects and pass criteria are not numbers guaranteed by the documents above. They are hypotheses this project still has to verify.
