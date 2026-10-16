using System.Security.Cryptography;
using Mono.Cecil;

namespace Dysphasia.Obfuscator;

public sealed class ProtectResult
{
    public string OutputPath { get; set; } = "";
    public string MappingPath { get; set; } = "";
    public int RenamedTypes { get; set; }
    public int RenamedMethods { get; set; }
    public int SkippedTypes { get; set; }
    public int SkippedMethods { get; set; }
    public int EncodedStrings { get; set; }
    public int SkippedStrings { get; set; }
    public int DistinctEncodedStrings { get; set; }
    public int StringBlobBytes { get; set; }
    public int FlattenedMethods { get; set; }
    public int SkippedFlattenMethods { get; set; }
    public int HiddenBclCallSites { get; set; }
    public List<string> HiddenBclTargets { get; set; } = new();
    public int OpaquePredicatesInjected { get; set; }
    public int MbaReplacedConstants { get; set; }
    public int SplitVariables { get; set; }
    public int GarbageFields { get; set; }
    public int GarbageMethods { get; set; }
    public int OutlinedBlocks { get; set; }
    public bool IntegrityCheckInjected { get; set; }
    public string? IntegrityCheckTarget { get; set; }
    public int InlinedCallSites { get; set; }
    public string? InlinedMethod { get; set; }
    public bool AntiDebuggingInjected { get; set; }
    public int TokenBloatChainDepth { get; set; }
    public bool CodeVirtualized { get; set; }
    public string? VirtualizedMethod { get; set; }
    public int VirtualizedBytecodeLength { get; set; }
    public bool ExceptionRoutingRewired { get; set; }
    public int ExceptionRoutingChecksReplaced { get; set; }
}

/// <summary>
/// Applies the P1 rename pass and writes a protected copy. Never touches the input file
/// (reports/obfuscator-plan.draft.md: "never overwrite the original, always write to a new output directory").
/// </summary>
public static class Protector
{
    public static ProtectResult Protect(string inputExe, Policy policy, string outDir, bool force)
    {
        var inspection = Inspector.Inspect(inputExe);
        if (!inspection.Supported)
        {
            throw new InvalidOperationException(
                "Input rejected by inspector:\n - " + string.Join("\n - ", inspection.RejectionReasons));
        }

        Directory.CreateDirectory(outDir);
        var outputPath = Path.Combine(outDir, Path.GetFileName(inputExe));
        if (File.Exists(outputPath) && !force)
            throw new InvalidOperationException($"Output already exists: {outputPath} (pass --force to overwrite)");

        var readerParams = new ReaderParameters { ReadSymbols = false, InMemory = true };
        using var module = ModuleDefinition.ReadModule(inputExe, readerParams);

        var plan = RenamePlanner.BuildPlan(module, policy);
        var mapping = new MappingFile
        {
            PolicyVersion = policy.PolicyVersion,
            PolicyHash = policy.ComputeHash(),
            Seed = policy.Seed,
            SourceSha256 = inspection.Sha256,
            SourceMvid = inspection.Mvid ?? "",
            CreatedAtUtc = DateTime.UtcNow.ToString("o"),
        };

        bool deceptiveNaming = policy.Passes.Contains("deceptive-naming");
        bool homoglyphIdentifiers = policy.Passes.Contains("homoglyph-identifiers");
        var usedTypeNames = new HashSet<string>();
        var usedMethodNames = new HashSet<string>();

        var result = new ProtectResult();
        foreach (var item in plan)
        {
            if (!item.Eligible)
            {
                if (item.Kind == "type") result.SkippedTypes++;
                else result.SkippedMethods++;
                continue;
            }

            if (item.Kind == "type" && item.TypeRef is not null)
            {
                var newName = deceptiveNaming
                    ? DeceptiveNameGenerator.Generate(policy.Seed, item.OriginalFullName, true, homoglyphIdentifiers, usedTypeNames)
                    : NameGenerator.Generate(policy.Seed, item.OriginalFullName, "T");
                mapping.Entries.Add(new MappingEntry
                {
                    Kind = "type",
                    OriginalFullName = item.OriginalFullName,
                    NewName = newName,
                    MetadataToken = item.MetadataToken,
                });
                item.TypeRef.Namespace = "";
                item.TypeRef.Name = newName;
                result.RenamedTypes++;
            }
            else if (item.Kind == "method" && item.MethodRef is not null)
            {
                var newName = deceptiveNaming
                    ? DeceptiveNameGenerator.Generate(policy.Seed, item.OriginalFullName, false, homoglyphIdentifiers, usedMethodNames)
                    : NameGenerator.Generate(policy.Seed, item.OriginalFullName, "m_");
                mapping.Entries.Add(new MappingEntry
                {
                    Kind = "method",
                    OriginalFullName = item.OriginalFullName,
                    NewName = newName,
                    MetadataToken = item.MetadataToken,
                });
                item.MethodRef.Name = newName;
                result.RenamedMethods++;
            }
        }

        if (policy.Passes.Contains("exception-routing"))
        {
            // Early, on Main's cleanest/most predictable form -- before string-encode so
            // its reused "neutral"/"mono"/"warm" literals get swept into the same shared
            // blob automatically.
            var exRoutingResult = ExceptionRoutingPass.Apply(module, policy, policy.Seed);
            result.ExceptionRoutingRewired = exRoutingResult.Rewired;
            result.ExceptionRoutingChecksReplaced = exRoutingResult.ChecksReplaced;
        }

        if (policy.Passes.Contains("function-outlining"))
        {
            // Must run before split-variables/control-flow for the same reason as
            // split-variables itself: needs the fixture's own original block structure.
            var outlineResult = FunctionOutliningPass.Apply(module, policy, policy.Seed);
            result.OutlinedBlocks = outlineResult.OutlinedBlocks;
        }

        if (policy.Passes.Contains("code-virtualization"))
        {
            // Before function-inlining deliberately: both target ClampByte through the
            // same "1-int-param, literal 255" signature heuristic. If virtualization
            // runs first, inlining would copy its `ldarg; call Interpret; ret` body into
            // callers (still correct, and every inlined call site then shares the one
            // VM); running it after inlining instead would make virtualization apply to
            // an orphaned, unreferenced copy of ClampByte nobody calls anymore. Not
            // combined in pixel-tone.full.json for exactly this reason -- see
            // reports/code-virtualization.draft.md for why this is tested standalone.
            var vmResult = CodeVirtualizationPass.Apply(module, policy, policy.Seed);
            result.CodeVirtualized = vmResult.Virtualized;
            result.VirtualizedMethod = vmResult.TargetMethod;
            result.VirtualizedBytecodeLength = vmResult.BytecodeLength;
        }

        if (policy.Passes.Contains("function-inlining"))
        {
            // Right after function-outlining, before split-variables/control-flow: needs
            // the target method's original, simple branch structure (multiple early
            // `ret`s merged via one shared label), not a flattened/MBA'd copy of it.
            var inlineResult = FunctionInliningPass.Apply(module, policy, policy.Seed);
            result.InlinedCallSites = inlineResult.InlinedCallSites;
            result.InlinedMethod = inlineResult.InlinedMethod;

            // A caller that received an inlined call must never reach ControlFlowPass
            // (see FunctionInliningPass's class remark: inlining can plant branches at a
            // point where other values -- e.g. an array ref + index for `arr[i] = ...`
            // -- are already sitting on the evaluation stack across the call; flattening
            // that caller later loses them, since its dispatcher carries only the state
            // variable across block boundaries, never raw stack content). Policy's own
            // ExcludeMembers already gates ControlFlowPass per-method, so just extend it
            // in memory -- this mutation happens after mapping.PolicyHash is computed
            // above, so it never changes what that hash records.
            foreach (var caller in inlineResult.TouchedCallers)
                if (!policy.ExcludeMembers.Contains(caller))
                {
                    policy.ExcludeMembers.Add(caller);
                    policy.ExcludeReasons[caller] = "function-inlining planted branches where a call site had other values pending on the stack; control-flow flattening would lose them";
                }
        }

        if (policy.Passes.Contains("split-variables"))
        {
            // Must run before control-flow: it only sees the fixture's own original
            // locals this way, never CFF's own dispatcher state variable (ControlFlowPass.cs).
            var splitResult = VariableSplitPass.Apply(module, policy, policy.Seed);
            result.SplitVariables = splitResult.SplitVariables;
        }

        if (policy.Passes.Contains("control-flow"))
        {
            var cfResult = ControlFlowPass.Apply(module, policy, policy.Seed);
            result.FlattenedMethods = cfResult.FlattenedMethods;
            result.SkippedFlattenMethods = cfResult.SkippedMethods;
            result.OpaquePredicatesInjected = cfResult.OpaquePredicatesInjected;
        }

        if (policy.Passes.Contains("integrity-check"))
        {
            // Before string-encode, so its own injected "integrity check failed"
            // literal gets swept into the shared blob by the existing mechanism instead
            // of needing its own.
            var integrityResult = IntegrityCheckPass.Apply(module, policy, policy.Seed);
            result.IntegrityCheckInjected = integrityResult.Injected;
            result.IntegrityCheckTarget = integrityResult.TargetMethod;
        }

        if (policy.Passes.Contains("anti-debugging"))
        {
            // Same reason as integrity-check: before string-encode so its own
            // "debugger detected" literal is swept into the shared blob.
            var antiDebugResult = AntiDebuggingPass.Apply(module, policy, policy.Seed);
            result.AntiDebuggingInjected = antiDebugResult.Injected;
        }

        if (policy.Passes.Contains("string-encode"))
        {
            var stringResult = StringPass.Apply(module, policy, policy.Seed);
            result.EncodedStrings = stringResult.EncodedLiterals;
            result.SkippedStrings = stringResult.SkippedLiterals;
            result.DistinctEncodedStrings = stringResult.DistinctLiterals;
            result.StringBlobBytes = stringResult.BlobBytes;
        }

        if (policy.Passes.Contains("hide-bcl-calls"))
        {
            var bclResult = BclCallHidingPass.Apply(module, policy, policy.Seed);
            result.HiddenBclCallSites = bclResult.HiddenCallSites;
            result.HiddenBclTargets = bclResult.HiddenTargets;
        }

        if (policy.Passes.Contains("mba-constants"))
        {
            var mbaResult = MbaPass.Apply(module, policy, policy.Seed);
            result.MbaReplacedConstants = mbaResult.ReplacedConstants;
        }

        if (policy.Passes.Contains("garbage-data"))
        {
            var garbageResult = GarbageDataPass.Apply(module, policy, policy.Seed);
            result.GarbageFields = garbageResult.InjectedFields;
            result.GarbageMethods = garbageResult.InjectedMethods;
        }

        if (policy.Passes.Contains("token-bloating"))
        {
            var bloatResult = TokenBloatingPass.Apply(module, policy, policy.Seed);
            result.TokenBloatChainDepth = bloatResult.ChainDepth;
        }

        // Mono.Cecil preserves the source MVID by default, which would otherwise let
        // anyone who has analyzed the original link a "protected" build straight back to
        // it by MVID alone, without reading a single name or string
        // (obfuscator-plan.draft.md flags exactly this: check whether evidence tied to the
        // new hash/MVID could still allow re-identification). Re-issue it deterministically from the policy +
        // source hash so the same (input, policy, seed) still reproduces the same MVID.
        module.Mvid = DeriveMvid(policy, inspection.Sha256);

        module.Write(outputPath);

        // Re-read the freshly written file for its own hash/MVID so the mapping file
        // records what was actually produced, not what we intended to produce.
        var outputBytes = File.ReadAllBytes(outputPath);
        mapping.OutputSha256 = Convert.ToHexStringLower(SHA256.HashData(outputBytes));
        using (var writtenModule = ModuleDefinition.ReadModule(outputPath))
            mapping.OutputMvid = writtenModule.Mvid.ToString();

        var mappingPath = Path.Combine(outDir, "..", "mapping",
            $"{Path.GetFileNameWithoutExtension(inputExe)}.{mapping.OutputSha256[..12]}.mapping.json");
        mappingPath = Path.GetFullPath(mappingPath);
        mapping.Save(mappingPath);

        result.OutputPath = outputPath;
        result.MappingPath = mappingPath;
        return result;
    }

    private static Guid DeriveMvid(Policy policy, string sourceSha256)
    {
        var input = $"mvid:{policy.Seed}:{policy.ComputeHash()}:{sourceSha256}";
        var hash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(input));
        return new Guid(hash[..16]);
    }
}
