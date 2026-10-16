# Dysphasia: native Windows track, first baseline (+ REA↔IDA integration + native protection passes)

2026-10-14. First empirical measurement for step 5 of `obfuscator-plan.md` ("Native Windows track: build a separate baseline using a small C/C++ x64 PE and a Ghidra environment"). Ghidra isn't on this machine, so I used **IDA Professional 9.3** instead (already installed). After direct IDA analysis and REA↔IDA integration, I **actually applied a protection pass (source-level string obfuscation) to the native code and re-measured**.

## Conclusion

I reimplemented **the same algorithm and the same CLI contract** as `fixture/PixelTone.cs` (.NET) in C (`fixture/PixelTone.c`), built it with MSVC with optimization and no symbols, and analyzed it directly with IDA Pro (+ Hex-Rays). Even unprotected, the native build shows an exposure pattern completely different from the .NET build:

- **The function count explodes.** IDA found roughly 270+ named functions, because of the statically linked C runtime (CRT). Only 4 of those are my own logic; the rest are all internal CRT functions. The .NET side (per REA) had a baseline of 2 types and 6 methods.
- **Even so, Hex-Rays recovers my logic almost perfectly.** The decompilation of `main` shows the FNV-1a constant (`0x811C9DC5` = 2166136261), the mono weights (77/150/29), the warm offsets (+12/+3/-9), the clamp logic, and the string literals, all intact. Even without function names (`sub_140001060`, etc.), the logic itself is not hidden.
- **Integer division looks obfuscated on its own.** MSVC optimizes the `/100` operation into a magic-number multiply-and-shift (`1374389535LL * x >> 32 >> 5`), which produces a "hard to read constant" with no protection technique applied at all. Hex-Rays still recovers this back to clean C, but an analyst looking only at the disassembly needs separate knowledge to recognize that this constant means "divide by 100".
- **IDA's default string listing (`list_strings`) found none of my application strings.** Hundreds of internal CRT/RTTI strings show up, but every wide-string (`L"..."`) literal I wrote is missing, even though decompiling shows them immediately. This is a completely different kind of gap from REA's `user_strings` (which reads the managed #US heap directly).
- File size: 139,776 bytes (about 27 times the .NET build's 5,120 bytes), mostly the statically linked CRT.
- **I actually integrated REA with the native binary via IDA** (`REA_IDA_MCP_CONFIG`). `rea function ... main --json` succeeded and returned disassembly, decompilation, and call relationships, the same content as viewing it directly in IDA. But REA's own `facet_availability`, included in the response, states that **the IDA adapter cannot provide the strings/names a function references, the CFG (basic blocks), or typed reference edges at all**. In other words, a capability like REA's `user_strings` (the core weapon of the managed .NET path) **does not exist** on the native (IDA) path. Even with no protection applied at all, this particular REA capability is already blocked.
- **I actually applied two protection passes (P2, P3) to the native code.** `tools/obfuscator` (Mono.Cecil) only handles .NET IL, so it can't rewrite native machine code. So instead I rewrote the source in two stages. (P2) `fixture/PixelTone.protected.c`: XOR-encode every string literal and decode it at runtime. (P3) `fixture/PixelTone.protected2.c`: flatten the four functions that have 2 or more basic blocks into a `switch`-based state machine (the same shape as .NET's `ControlFlowPass.cs`, written by hand). Both were confirmed to preserve 335/335 behavior, and re-analysis with IDA/Hex-Rays showed the strings had become opaque references like `&xmmword_...`, and the branches had become `switch(state){...}` dispatch. See the two "Native protection pass" sections below.

## Implementation

| Item | Detail |
|---|---|
| Source | `fixture/PixelTone.c`: the same CLI contract as `fixture/PixelTone.cs` (6 arguments or `--help`), the same algorithm (clamp/channel adjustment/presets/FNV-1a fingerprint) |
| Build | `scripts/build-native-fixture.bat`: MSVC (the VC toolchain from Visual Studio 2022 Community; the "latest" VS 18 install that vswhere pointed to had no C++ workload, so I had to locate this one separately), `/O2 /MT /W4`, no PDB |
| Artifact | `artifacts/native-baseline/PixelTone.exe`, SHA-256 `69f517da...00ac08c6` |
| Analysis tool | IDA Professional 9.3 + Hex-Rays decompiler, `mrexodia/ida-pro-mcp` 1.4.0 (attached/legacy profile, already installed) |

### Why I used wchar_t/wmain

The evaluation corpus (`logs/evaluation01/corpus.json`) mixes in non-ASCII test cases: full-width digits (`１２`), Arabic-Indic digits (`١٢`), leading NBSP whitespace, and so on. A plain `char **argv` goes through the Windows ANSI code page and can corrupt these characters, so I used `wmain`/`wchar_t **argv` to receive the Unicode code units unchanged, and made `read_int` accept only ASCII digits/signs/whitespace (the same policy as the regex in the existing pass01/02 Python implementation), comparing directly against that.

### Bug found and fixed

**Duplicated CRLF.** The Windows CRT automatically converts `\n` to `\r\n` on text-mode stdout. I wrote `\r\n` directly in the source, and the CRT converted just the `\n` part again, producing `\r\r\n`. All 335 cases failed. Fixed by writing only `\n`.

## Behavior-preservation verification

Using `scripts/evaluate-native.py`, I reused the existing 335-case corpus to directly compare the native build against the .NET baseline (`artifacts/baseline/PixelTone.exe`): **335/335 exact match** (`logs/verify-native/summary.json`). Rejection of full-width/Arabic-Indic digits, disallowing NBSP, and all presets, error paths, and exit codes are identical byte for byte. This result is needed before any later comparison ("native vs. managed") can claim to be looking at "the same algorithm, a different compile target".

## IDA Pro integration: problems hit and how I solved them

The already-installed `mcp-plugin.py` (in the IDA user plugins folder) **only registers at IDA startup and does not automatically turn on the server**. Normally a person has to turn it on manually, via the `Edit > Plugins > MCP` menu or the `Ctrl-Alt-M` shortcut. This session had no screen-control tool, so I wrote an IDAPython script (`scripts/ida-start-mcp.py`) passed to IDA with the `-S` flag, and tried `idaapi.load_and_run_plugin("MCP", 0)`. That also failed (returned `False`, cause unconfirmed: it looks like the plugin isn't registered under that name). In the end I succeeded by **directly importing the plugin file and manually calling `PLUGIN_ENTRY().init()` then `.run(0)`**, which brought up the RPC server (port 13337). The full, reproducible procedure is in `scripts/ida-start-mcp.py`.

## REA↔IDA integration measurement

Everything up to this point was the result of using **IDA Pro directly**, not REA itself. I also actually connected the "REA↔IDA MCP" integration described by `docs/ida-provider.md`:

1. I created a registration file at `scripts/rea-ida-mcp-config.json` pointing to the upstream `ida-pro-mcp` server (`C:\Users\LUNES\Downloads\ida-pro-mcp-1.4.0\...\server.py`, already downloaded), exactly matching the "attached" profile example from the REA docs (`{"command": "python", "args": [".../server.py", "--ida-rpc", "http://127.0.0.1:13337"]}`).
2. I set `REA_IDA_MCP_CONFIG` and `REA_ANALYSIS_PROVIDER=ida` and ran `rea doctor --provider ida --json`: confirmed the registration was valid, via `"ida-registration":{"ok":true}`.
3. With the same IDA instance (brought up by `scripts/ida-start-mcp.py`) still running, I ran `rea function <native.exe> main --json`: **success**. REA actually called `get_function_by_name`, `disassemble_function`, `decompile_function`, `get_callers`, and `get_callees` through the upstream IDA MCP server (which self-reports as `ida-pro-mcp 1.16.0`), and wrapped the results in REA's standard Evidence format (`evidence_id`, `confidence: "observed"`, `authority: "shipped-artifact"`).

The decompilation result I got back was **exactly identical** to using IDA directly in section 1 (the same pseudocode, the same constants). However, the `facet_availability` that REA itself included in the response tells us something important:

```json
"strings_names": { "available": false, "reason": "IDA adapter does not expose function-referenced strings and names." },
"cfg":            { "available": false, "reason": "IDA adapter does not expose basic blocks." },
"references":     { "available": false, "reason": "IDA adapter does not expose typed reference edges." },
"comments":       { "available": false, "reason": "IDA adapter does not expose typed comments." }
```

(`pseudocode`, `assembly`, `callers`, and `callees` are all `available: true`.) The full raw output is at `logs/native-rea-ida/function-main.json` (evidence `ev_2616916b...`).

## Native protection pass: source-level string obfuscation

`tools/obfuscator` is a tool that edits .NET IL metadata via Mono.Cecil. It has no ability to rewrite x86-64 machine code. Building a native binary rewriter (based on a disassembler+assembler) from scratch would be a separate project beyond the scope of this turn, so instead I **applied the same idea as .NET's P2 at the source level**: in `fixture/PixelTone.protected.c`, every string literal is XOR-encoded before the build (`key=0x5A`, not a cryptographic secret, the same caveat as P2), and `init_strings()` decodes them into fixed-size buffers at program start. After that, every comparison (`wcscmp`) and output (`wprintf`) uses the decoded buffer.

| Item | Detail |
|---|---|
| Source | `fixture/PixelTone.protected.c` |
| Build | `scripts/build-native-fixture-protected.bat` → `artifacts/native-protected/PixelTone.exe` |
| Artifact | See the `scripts/evaluate-native-protected.py` run log for the SHA-256. File size 140,288 bytes (**+0.4%** versus the unprotected native build's 139,776 bytes) |

### Bug found and fixed

**Three ERROR strings were missing their newline.** While generating the byte arrays in Python for the XOR encoding, I dropped the `\n` that was present in the original for 3 strings including `"ERROR: unknown preset"`. This showed up immediately in a manual smoke test (it ran into the next shell output, like `ERROR: unknown presetexit=2`). Fixed by re-encoding all three strings with the `\n` included.

### Behavior-preservation verification

Using `scripts/evaluate-native-protected.py`, I reused the existing 335-case corpus to compare against the .NET baseline: **335/335 exact match** (`logs/verify-native-protected/summary.json`). It passed on the first try after the rebuild.

### IDA re-analysis: checking whether it actually got hidden

I analyzed the protected build again with IDA Pro (started the same way, via `scripts/ida-start-mcp.py`).

- **Application strings disappeared entirely from `list_strings`.** In the unprotected build they were simply absent (section 1); in the protected build, **unreadable fragments** appear in their place (`"ww2?6*"`, `"4=?P7545"`, etc, the XOR-encoded raw bytes happening to get picked up as a "string-like" pattern). Either way, the end result is no human-readable strings at all.
- **Decompiling `main` again with Hex-Rays, every plaintext string has turned into an opaque data reference.** For example, the unprotected build's `sub_1400014E0(L"PixelTone R G B brightness contrast preset\n")` becomes `sub_1400018F0(L"%ls", &xmmword_140021C30)` in the protected build. What it actually prints can no longer be read from the pseudocode alone. You'd have to read the bytes `xmmword_140021C30` points to directly, find `init_strings()`'s XOR loop (which shows up as `sub_140001060` in this analysis), and reconstruct the decryption formula.
- **But the numeric constants are unchanged.** The `mono` weights (77/150/29), the `warm` offsets (+12/+3/-9), and the FNV hash seed (`0x811C9DC5`) appear identically in the pseudocode before and after protection. This pass only touched strings; it didn't touch constants or control flow (the same separation as .NET's P2 being kept apart from P1 and P3).

### Interpretation

- **"Preventing string grepping" works on native code too, but the way it's applied is fundamentally different from .NET.** .NET's P2 patched the binary (the build output) after the fact, with Mono.Cecil: it could change just the build artifact while leaving the original source untouched. Native code required patching the source and recompiling. "Applying it after the fact to an existing build output" is impossible (short of a binary rewriter). This is the biggest design difference when building a native protection tool: it can't be built as a "post-build processing pipeline" the way .NET's was; it has to touch the compiler's input (source or IR).
- **Since REA's IDA path can't see strings in the first place, the value this protection pass adds against REA's resistance is close to "adding to zero."** As already confirmed in section 2, REA's IDA adapter doesn't provide `strings_names`. What this pass actually blocks isn't REA, but IDA's `list_strings`/Strings window, and an analyst who runs a generic tool like `strings.exe` directly on the binary.

## Native protection pass: source-level control-flow flattening (counterpart to .NET P3)

For the same reason (`dysob` can't handle machine code), I also applied control-flow flattening at the source level. In addition to P2 (strings), `fixture/PixelTone.protected2.c` manually flattens four functions with 2 or more basic blocks: `clamp_byte`, `apply_preset`, `fingerprint`, and `read_int`, into the same shape as `tools/obfuscator/ControlFlowPass.cs`: `state = <entry>; for(;;) { switch(state) { ... } }`, with every branch turned into "set the next state, then continue." Using the same safety rule as .NET's P3, **`wmain` (the native counterpart of Main) and `adjust_channel` (only 1 basic block, for the same reason as AdjustChannel) were left untouched.**

| Item | Detail |
|---|---|
| Source | `fixture/PixelTone.protected2.c` (P2 + P3) |
| Build | `scripts/build-native-fixture-protected2.bat` → `artifacts/native-protected2/PixelTone.exe` |
| File size | 140,800 bytes: **+0.7%** versus unprotected (139,776); versus P2 alone (140,288, +0.4%), flattening added only +512 bytes |

### Behavior-preservation verification

I reused the full 335-case corpus with `scripts/evaluate-native-protected2.py`: **335/335 exact match**, **passed on the first try** after the rebuild (compared to .NET's P2 taking a second try and P3 passing on the first, this native work was lucky on both counts. See "Unmeasured and limitations" below).

### IDA re-analysis: checking whether the flattening actually survived

- **Hex-Rays recovers the flattened structure as is.** `clamp_byte` no longer decompiles as `if(v<0) return 0; ...`; it decompiles as a state machine shaped like `switch(v1){ case 1: ...; case 2: return v2; case 3: ...; case 5: ...; case 7: ...; case 9: ...}` (raw: `logs/native-ida-protected2/clamp_byte.c`). The state constants written in the source (7, 3, 9, 1, 5, 2) show up unchanged. `read_int` likewise comes out as a switch dispatch across 14 states (17 to 43): the familiar sequential structure of "trim loop → sign → digit loop → range check" disappears, and every transition takes on the same shape (`v14 = N; continue`).
- **The compiler shuffled the state code one more time.** For example, `case 9` was `result=0; state=2;` in the source, but the decompiled result is `v1=2; goto LABEL_2`: `LABEL_2` is a point that starts with `v2=0` (= `result=0`), so the compiler noticed that "initialization on function entry" and "setting 0 in case 9" were the same code and merged them. The behavior is identical (confirmed by 335/335), but this creates one more flow shape, different from what was written in the source, adding one more path for an analyst to trace.
- **Flattening blocked inlining.** In the unprotected build, `clamp_byte` was so small (3 lines of `if/if/return`) that MSVC copied it inline into `main` 5 times (section 1, "the clamp logic... fully inlined"). The flattened version has a loop plus a switch, so the inlining cost got too high and the compiler kept it as a separate function (`sub_140001010`). This wasn't an intended protection effect, but it actually worked in favor of overall binary size (the complex dispatch code appears once instead of 5 times).
- **The numeric constants and the overall algorithm are still recoverable from pseudocode.** Following the state machine line by line (tedious but not impossible) is enough to work out that `read_int` is ASCII trim + sign + digit parsing, and that `clamp_byte` is a 0..255 clamp. As with .NET's P3, this "raises the cost of analysis," it does not "block analysis".

### Interpretation

- **.NET's and native's P3 differ in the "shape" of their output.** .NET's CIL `switch` instruction was almost invisible in REA's anchor summary (anchor count 4 → 25, with the jump table itself not exposed). Native's Hex-Rays recovers the switch **very well**. To a human reader, the decompiled switch statement on the native side may actually stand out as "this looks like a flattening pattern" more readily than .NET's CIL branching does (which could be counterproductive, in the sense that the shape draws suspicion). This means "the same technique" doesn't produce "the same level of concealment" on both platforms.
- **Source-level flattening depends on the compiler's cooperation.** If the compiler can fully prove the state variable's flow during optimization and reconstruct the original branches (theoretically possible when the states are few and the branches are simple), the flattening is nullified. That didn't happen for these 4 functions (confirmed by the Hex-Rays output), but for simpler functions there's a risk that the compiler will "optimize the flattening away." The .NET side worked **after the build**, via Cecil, so it had no such risk.

## Comparison: native vs. managed, both unprotected baselines

| Observation | .NET baseline (REA, managed path) | Native baseline (REA, via IDA) | Native baseline (IDA direct) |
|---|---|---|---|
| File size | 5,120 bytes | 139,776 bytes (27x) | (same) |
| Identified functions/types | 6 methods, 2 types | Same data, only per-function lookup available | **270+** functions (mostly CRT), my own logic is 4 |
| Function names | Meaningful (`ClampByte`, etc.) | None (`sub_140001060`, etc.) | None |
| String literals | REA directly lists 11 `user_strings` | **REA itself states "cannot provide" via `facet_availability.strings_names: false`** | 0 in the default string list; visible when decompiled |
| CFG/basic blocks | REA provides branch structure via anchors | **`facet_availability.cfg: false`** | Appears in Hex-Rays pseudocode (the block structure itself can be queried separately via the IDA API) |
| Decompilation/disassembly | (not applicable: CIL metadata provided directly) | **`pseudocode`/`assembly`: true, content exactly identical to direct IDA analysis** | Same |
| Call graph | Provided as a full aggregate via `call_edge_count` | `callers`/`callees` work per function (`available: true`) | Same |
| Constants (weights/hash seed, etc.) | Listed directly via the CIL anchor | Appear unchanged in pseudocode (`0x811C9DC5`, `77`, `150`, `29`, etc.) | Same |
| Integer division (÷100) | Plain CIL `div` instruction | MSVC magic-number optimization: extra interpretation cost even without protection | Same |

## Interpretation

- **"Unprotected" doesn't mean the same thing in the two worlds.** .NET's unprotected baseline was a "transparent" state where names, strings, and constants were almost entirely exposed in the metadata as is. Native's unprotected baseline already has no names (despite not being stripped) and is buried in CRT noise. Even so, the core constants, strings, and logic are almost entirely recovered via Hex-Rays. In other words, native code has no "name clues" by default, but it has a powerful alternative path: "deterministic decompilation".
- **The explosion in file size and function count is not a "protection effect," it's a "side effect of the linking method."** This happened because I used `/MT` (static CRT). Using `/MD` (dynamic CRT, dependent on a DLL) would make the file much smaller and reduce the function count too. These numbers shouldn't be used as evidence that "native is inherently safer." It's simply the result of a linking-option choice.
- **REA's own native path is structurally weaker than its managed path.** This isn't a "protection effect," it's a limitation of REA's IDA adapter itself: REA declares on its own that it "cannot provide strings/names/CFG/reference edges." On managed .NET, we had to build P2 (string encoding) ourselves to get this effect, but on native, **REA's IDA path itself already lacks that capability**. That doesn't mean "native is safer," though. Using IDA directly (section 1) shows the strings right there in the decompiled pseudocode, so a person simply reading the pseudocode bypasses it. Only REA's "automatic aggregation" feature is missing; the analysis itself isn't blocked.

## Unmeasured and limitations

- I only confirmed REA↔IDA integration for one command, `function` (on `main`). I did not check whether other native commands, such as `decompile`, `inspect-native-api`, and `resolve-native-call-targets`, are subject to the same `facet_availability` constraints.
- Calling `strings_names`/`cfg` "impossible" is based on **this specific IDA adapter (legacy 1.4.0, attached profile)**. REA's headless (`idalib-mcp`) profile, or a Ghidra adapter, might provide different facets. Neither was tried.
- **The native protection pass is source-level and was built manually.** It isn't a tool like `dysob` that can automatically apply to any binary; it's bytes precomputed in Python and hand-inserted into the source for this one sample. Generalizing it would need either (a) building a binary rewriter, or (b) a build tool that automatically finds and encodes strings at the compiler preprocessing/macro stage. Neither exists yet.
- ~~The protection pass only dealt with strings~~ **→ control-flow flattening (counterpart to .NET P3) was also added, at the source level** (`fixture/PixelTone.protected2.c`, see "Native protection pass: source-level control-flow flattening" above). Native renaming still hasn't been attempted (not actually needed: static functions already have no names).
- ~~REA↔IDA integration was not re-run against the protected build~~ **→ Both P2 and P2+P3 were re-run and confirmed.** Running `rea function <protected.exe> main --json` against the string-protected build (P2) (evidence `ev_908b06de...`), `facet_availability` was exactly the same as the unprotected build. **It was also re-run against the P2+P3 combined build (`native-protected2`)**: `rea function ... sub_140001010 --json` (the flattened `clamp_byte`, evidence `ev_fd2a61b2...`) returned pseudocode that was the same `switch(v1){case 1: ... case 9: ...}` state machine, **not differing by a single character** from what was seen directly with IDA in section 4. This means the flattening is preserved intact through the REA↔IDA path as well. `facet_availability` was also identical (`strings_names`/`cfg`/`references` all `false`).
- Like P2, the control-flow flattening source was also written **by hand, for only four functions**. There is no tool that automatically finds and flattens arbitrary functions. The criteria for choosing flattening targets (2 or more basic blocks, no exception handling) were applied identically to .NET's P3, but confirmed manually.
- The risk of the compiler "optimizing away" the flattening wasn't observed in these 4 functions, but whether that holds equally for other functions, other compiler versions, and other optimization levels was not checked.
- Independent analysts' reconstruction time/accuracy was not measured on the native track; there are no numbers yet comparable to pass03.
- I only looked at one combination of settings: `/O2 /MT` (static linking, optimized). Building with `/MD` (dynamic linking), without optimization, or with MinGW/Clang could change the function count and string exposure.
- Whether the workaround for the IDA MCP plugin's "doesn't auto-start" problem (directly importing the plugin module and running it manually) is a generally reproducible method was not confirmed. It was only confirmed for this specific plugin version (1.4.0).
- The function count ("270+") is a rough estimate from eyeballing IDA's `list_functions` output; it was not counted exactly.
- Ghidra was not installed. To be clear, I substituted the already-installed IDA Pro for the tool the plan originally called for.

## Evidence paths

- Native source/build (unprotected): `fixture/PixelTone.c`, `scripts/build-native-fixture.bat`, `artifacts/native-baseline/PixelTone.exe`
- Native source/build (P2, string protection): `fixture/PixelTone.protected.c`, `scripts/build-native-fixture-protected.bat`, `artifacts/native-protected/PixelTone.exe`
- Native source/build (P2+P3, string + control-flow protection): `fixture/PixelTone.protected2.c`, `scripts/build-native-fixture-protected2.bat`, `artifacts/native-protected2/PixelTone.exe`
- Behavior-preservation verification: `scripts/evaluate-native.py`/`logs/verify-native/` (unprotected), `scripts/evaluate-native-protected.py`/`logs/verify-native-protected/` (P2), `scripts/evaluate-native-protected2.py`/`logs/verify-native-protected2/` (P2+P3)
- Flattening decompilation evidence: `logs/native-ida-protected2/clamp_byte.c`
- IDA integration script: `scripts/ida-start-mcp.py`
- REA↔IDA registration file: `scripts/rea-ida-mcp-config.json`
- REA↔IDA raw responses: `logs/native-rea-ida/function-main.json` (unprotected, evidence `ev_2616916b...`), `function-main-protected.json` (P2, evidence `ev_908b06de...`), `function-main-protected2.json`+`function-clampbyte-protected2.json` (P2+P3, evidence `ev_90ee7ada...`/`ev_fd2a61b2...`)
- See also: [Experiment report](experiment-report.md) (.NET baseline), [Obfuscation tool build plan](obfuscator-plan.md) (step 5), [P1/P2/P3 first measurement](p1-p2-measurement.md) (comparison with .NET's P2)
