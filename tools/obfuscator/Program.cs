using System.Text.Json;
using Dysphasia.Obfuscator;

if (args.Length == 0)
{
    PrintUsage();
    return 1;
}

try
{
    switch (args[0])
    {
        case "inspect":
            return RunInspect(args[1..]);
        case "plan":
            return RunPlan(args[1..]);
        case "protect":
            return RunProtect(args[1..]);
        case "verify":
            return RunVerify(args[1..]);
        case "dump":
            return RunDump(args[1..]);
        case "mapping-index":
            return RunMappingIndex(args[1..]);
        case "resolve":
            return RunResolve(args[1..]);
        case "list-passes":
            return RunListPasses(args[1..]);
        default:
            PrintUsage();
            return 1;
    }
}
catch (Exception ex)
{
    Console.Error.WriteLine($"error: {ex}");
    return 1;
}

static void PrintUsage()
{
    Console.Error.WriteLine("""
        dysob -- Dysphasia IL protection CLI (18 .NET passes; see `dysob list-passes`)

        Usage:
          dysob inspect <exe>
          dysob plan <exe> --policy <policy.json>
          dysob protect <exe> --policy <policy.json> --out <dir> [--force] [--seed <n>|random]
          dysob verify <original.exe> <protected.exe> --corpus <corpus.json> [--out <results-dir>]
          dysob dump <exe> [methodNameContains]
          dysob list-passes
          dysob mapping-index --mapping-dir <dir> --out <index.json>
          dysob resolve <obfuscatedName> --mapping-dir <dir> [--sha256 <hash>] [--mvid <mvid>]
        """);
}

// Pure documentation of the pass names Protector.cs checks `policy.Passes` against
// (see tools/obfuscator/Protector.cs, ControlFlowPass.cs, StringPass.cs). Kept as a
// static list rather than reflected from Protector.cs because the pipeline has real
// ordering constraints between passes that a flat list can't express -- the paired
// report for each pass is the authority on where it actually runs; this command is a
// discoverability aid, not the source of truth.
static (string Name, string Category, string Report, string Note)[] KnownPasses() =>
[
    ("rename", "Lexical & Data", "", "Always applied; the base identifier-mangling pass."),
    ("deceptive-naming", "Lexical & Data / Anti-AI", "deceptive-naming-homoglyphs.draft.md", "Plausible-but-wrong names instead of hash-like ones."),
    ("homoglyph-identifiers", "Lexical & Data / Anti-AI", "deceptive-naming-homoglyphs.draft.md", "Cyrillic homoglyphs in already-private identifiers."),
    ("string-encode", "Lexical & Data", "bcl-call-hiding.draft.md", "XOR-encoded string blob, SHA256-derived keys."),
    ("string-splitting", "Lexical & Data", "string-splitting.draft.md", "Splits literals across two differently-keyed blob regions."),
    ("mba-constants", "Lexical & Data", "mba-constants.draft.md", "Replaces telltale constants with bitwise identities."),
    ("split-variables", "Lexical & Data", "variable-splitting.draft.md", "XOR-shares locals across two variables."),
    ("garbage-data", "Lexical & Data", "garbage-data.draft.md", "Dummy fields/methods indistinguishable from real ones."),
    ("control-flow", "Control Flow", "opaque-predicates-and-cff-fix.draft.md", "State-machine flattening."),
    ("opaque-predicates", "Control Flow", "opaque-predicates-and-cff-fix.draft.md", "Arithmetic always-true/false guards on flattening transitions."),
    ("mhop-predicates", "Control Flow / Anti-AI", "mhop-predicates.draft.md", "SHA256-gated guards -- not provable from text alone."),
    ("function-inlining", "Control Flow", "function-inlining.draft.md", "Removes a call relationship by copying the body in."),
    ("function-outlining", "Control Flow", "function-outlining.draft.md", "Extracts single-exit blocks into new methods."),
    ("exception-routing", "Control Flow", "exception-routing-dotnet.draft.md", "Routes a comparison through a caught DivideByZeroException."),
    ("hide-bcl-calls", "Control Flow", "bcl-call-hiding.draft.md", "Reflection-indirected BCL method calls."),
    ("integrity-check", "Anti-Analysis", "integrity-check.draft.md", "Behavioral self-check; FailFast on tamper."),
    ("anti-debugging", "Anti-Analysis", "anti-debugging.draft.md", "Debugger.IsAttached check; FailFast if attached."),
    ("token-bloating", "Anti-AI", "token-bloating.draft.md", "Empty inheritance chain (documented negative result vs. REA's pagination)."),
    ("code-virtualization", "Virtualization (standalone only)", "code-virtualization.draft.md", "NOT in pixel-tone.full.json -- conflicts with function-inlining's target heuristic; verify independently."),
];

static int RunListPasses(string[] rest)
{
    var passes = KnownPasses();
    foreach (var group in passes.GroupBy(p => p.Category))
    {
        Console.WriteLine($"## {group.Key}");
        foreach (var p in group)
        {
            var report = p.Report.Length > 0 ? $"reports/{p.Report}" : "(no report; see policy comment)";
            Console.WriteLine($"  {p.Name,-24} {p.Note}");
            Console.WriteLine($"  {"",-24} -> {report}");
        }
        Console.WriteLine();
    }
    Console.Error.WriteLine($"{passes.Length} known pass names. See README.md for the full catalogue including declined techniques.");
    return 0;
}

static string RequireOption(string[] args, string name)
{
    for (int i = 0; i < args.Length - 1; i++)
        if (args[i] == name) return args[i + 1];
    throw new ArgumentException($"missing required option {name}");
}

static bool HasFlag(string[] args, string name) => args.Contains(name);

static int RunInspect(string[] rest)
{
    if (rest.Length < 1) { Console.Error.WriteLine("usage: dysob inspect <exe>"); return 1; }
    var report = Inspector.Inspect(rest[0]);
    Console.WriteLine(Inspector.ToJson(report));
    return report.Supported ? 0 : 3;
}

static int RunPlan(string[] rest)
{
    if (rest.Length < 1) { Console.Error.WriteLine("usage: dysob plan <exe> --policy <policy.json>"); return 1; }
    var exe = rest[0];
    var policyPath = RequireOption(rest, "--policy");
    var policy = Policy.Load(policyPath);

    var readerParams = new Mono.Cecil.ReaderParameters { InMemory = true };
    using var module = Mono.Cecil.ModuleDefinition.ReadModule(exe, readerParams);
    var plan = RenamePlanner.BuildPlan(module, policy);

    var summary = plan.Select(p => new
    {
        p.Kind, p.OriginalFullName, p.MetadataToken, p.Eligible, p.ExcludeReason,
    });
    Console.WriteLine(JsonSerializer.Serialize(summary, new JsonSerializerOptions { WriteIndented = true }));

    var eligible = plan.Count(p => p.Eligible);
    Console.Error.WriteLine($"{eligible}/{plan.Count} entries eligible for renaming under policy '{policyPath}'.");
    return 0;
}

static int RunProtect(string[] rest)
{
    if (rest.Length < 1)
    {
        Console.Error.WriteLine(
            "usage: dysob protect <exe> --policy <p.json> --out <dir> [--force] [--seed <n>|random]");
        return 1;
    }
    var exe = rest[0];
    var policyPath = RequireOption(rest, "--policy");
    var outDir = RequireOption(rest, "--out");
    var force = HasFlag(rest, "--force");
    var policy = Policy.Load(policyPath);

    // P4 ("per-build variation and mapping management", obfuscator-plan.draft.md): overriding the seed per
    // invocation -- instead of hand-editing the policy file -- is what actually makes
    // "every release gets different names/blob layout/state ids" a one-flag build-time
    // decision rather than a manual step someone has to remember. `random` seeds from
    // the current UTC tick count so a CI pipeline can pass it with no extra state.
    if (rest.Contains("--seed"))
    {
        var seedArg = RequireOption(rest, "--seed");
        policy.Seed = seedArg.Equals("random", StringComparison.OrdinalIgnoreCase)
            ? DateTime.UtcNow.Ticks
            : long.Parse(seedArg);
        Console.Error.WriteLine($"seed override: {policy.Seed} (policy file's own seed was ignored)");
    }

    var result = Protector.Protect(exe, policy, outDir, force);
    Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
    Console.Error.WriteLine(
        $"renamed {result.RenamedTypes} types, {result.RenamedMethods} methods " +
        $"(skipped {result.SkippedTypes} types, {result.SkippedMethods} methods), seed={policy.Seed}.");
    Console.Error.WriteLine($"output:  {result.OutputPath}");
    Console.Error.WriteLine($"mapping: {result.MappingPath}");
    return 0;
}

static int RunDump(string[] rest)
{
    if (rest.Length < 1) { Console.Error.WriteLine("usage: dysob dump <exe> [methodNameContains]"); return 1; }
    var filter = rest.Length > 1 ? rest[1] : null;
    using var module = Mono.Cecil.ModuleDefinition.ReadModule(rest[0]);
    foreach (var type in module.Types)
    foreach (var method in type.Methods)
    {
        if (filter is not null && !method.Name.Contains(filter)) continue;
        Console.WriteLine($"=== {type.FullName}::{method.Name} ===");
        if (!method.HasBody) { Console.WriteLine("(no body)"); continue; }
        foreach (var instr in method.Body.Instructions)
            Console.WriteLine($"  IL_{instr.Offset:x4}: {instr.OpCode} {DescribeOperand(instr.Operand)}");
        foreach (var eh in method.Body.ExceptionHandlers)
            Console.WriteLine($"  EH try[{eh.TryStart?.Offset:x4}-{eh.TryEnd?.Offset:x4}) handler[{eh.HandlerStart?.Offset:x4}-{eh.HandlerEnd?.Offset:x4}) {eh.CatchType}");
    }
    return 0;
}

static int RunMappingIndex(string[] rest)
{
    var mappingDir = RequireOption(rest, "--mapping-dir");
    var outPath = RequireOption(rest, "--out");
    var index = MappingRepository.BuildIndex(mappingDir);
    MappingRepository.SaveIndex(index, outPath);
    Console.Error.WriteLine($"indexed {index.Count} mapping file(s) from '{mappingDir}' -> '{outPath}'.");
    foreach (var e in index)
        Console.Error.WriteLine(
            $"  {Path.GetFileName(e.MappingPath)}: seed={e.Seed}, outputSha256={e.OutputSha256[..12]}..., " +
            $"outputMvid={e.OutputMvid}, entries={e.EntryCount}, createdAtUtc={e.CreatedAtUtc}");
    return 0;
}

static int RunResolve(string[] rest)
{
    if (rest.Length < 1)
    {
        Console.Error.WriteLine(
            "usage: dysob resolve <obfuscatedName> --mapping-dir <dir> [--sha256 <hash>] [--mvid <mvid>]");
        return 1;
    }
    var obfuscatedName = rest[0];
    var mappingDir = RequireOption(rest, "--mapping-dir");
    string? sha256 = rest.Contains("--sha256") ? RequireOption(rest, "--sha256") : null;
    string? mvid = rest.Contains("--mvid") ? RequireOption(rest, "--mvid") : null;
    if (sha256 is null && mvid is null)
    {
        Console.Error.WriteLine("error: give at least one of --sha256 or --mvid to identify which build crashed.");
        return 1;
    }

    var (originalName, matchedMappingPath) = MappingRepository.Resolve(mappingDir, obfuscatedName, sha256, mvid);
    if (originalName is null)
    {
        Console.Error.WriteLine(
            $"no mapping entry found for '{obfuscatedName}' under the given build identity in '{mappingDir}'.");
        return 2;
    }

    Console.WriteLine(JsonSerializer.Serialize(new
    {
        obfuscatedName,
        originalName,
        mappingFile = matchedMappingPath,
    }, new JsonSerializerOptions { WriteIndented = true }));
    return 0;
}

static string DescribeOperand(object? operand) => operand switch
{
    Mono.Cecil.Cil.Instruction i => $"-> IL_{i.Offset:x4}",
    Mono.Cecil.Cil.VariableDefinition v => $"V_{v.Index} ({v.VariableType})",
    Mono.Cecil.MethodReference m => m.FullName,
    Mono.Cecil.FieldReference f => f.FullName,
    Mono.Cecil.TypeReference t => t.FullName,
    string s => $"\"{s}\"",
    null => "",
    _ => operand.ToString() ?? "",
};

static int RunVerify(string[] rest)
{
    if (rest.Length < 2)
    {
        Console.Error.WriteLine("usage: dysob verify <original.exe> <protected.exe> --corpus <corpus.json> [--out <dir>]");
        return 1;
    }
    var originalExe = rest[0];
    var protectedExe = rest[1];
    var corpusPath = RequireOption(rest, "--corpus");

    var (passed, total, rows) = Verifier.Verify(originalExe, protectedExe, corpusPath);

    var summary = new
    {
        original_sha256 = Verifier.Sha256OfFile(originalExe),
        protected_sha256 = Verifier.Sha256OfFile(protectedExe),
        corpus = corpusPath,
        passed,
        total,
        by_kind = rows.GroupBy(r => r.Kind).ToDictionary(
            g => g.Key, g => new { total = g.Count(), passed = g.Count(r => r.Match) }),
        failed_ids = rows.Where(r => !r.Match).Select(r => r.Id).ToList(),
    };

    string? outDirArg = rest.Contains("--out") ? RequireOption(rest, "--out") : null;
    if (outDirArg is not null)
    {
        Directory.CreateDirectory(outDirArg);
        File.WriteAllText(Path.Combine(outDirArg, "summary.json"),
            JsonSerializer.Serialize(summary, new JsonSerializerOptions { WriteIndented = true }));
        File.WriteAllText(Path.Combine(outDirArg, "cases.jsonl"),
            string.Concat(rows.Select(r => JsonSerializer.Serialize(r) + "\n")));
    }

    Console.WriteLine(JsonSerializer.Serialize(summary, new JsonSerializerOptions { WriteIndented = true }));
    return passed == total ? 0 : 2;
}
