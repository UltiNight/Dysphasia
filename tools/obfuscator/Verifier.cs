using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Dysphasia.Obfuscator;

public sealed class CorpusCase
{
    [JsonPropertyName("id")]
    public int Id { get; set; }
    [JsonPropertyName("kind")]
    public string Kind { get; set; } = "";
    [JsonPropertyName("args")]
    public List<string> Args { get; set; } = new();
}

public sealed class CaseResult
{
    public int Id { get; set; }
    public string Kind { get; set; } = "";
    public bool Match { get; set; }
    public int OriginalExit { get; set; }
    public int ProtectedExit { get; set; }
    public string? Note { get; set; }
}

/// <summary>
/// Black-box equivalence check between an original binary and a protected one, reusing
/// the same corpus format scripts/evaluate.py already produces under logs/evaluation01
/// (exact stdout bytes, stderr bytes, exit code -- see reports/obfuscator-plan.draft.md,
/// the verifier row). This is what gates whether a protection pass is allowed to ship:
/// obfuscator-plan.draft.md's pass criterion is 100% regression pass, not "looks obfuscated".
/// </summary>
public static class Verifier
{
    public static (int passed, int total, List<CaseResult> rows) Verify(
        string originalExe, string protectedExe, string corpusPath)
    {
        var cases = JsonSerializer.Deserialize<List<CorpusCase>>(File.ReadAllText(corpusPath))
            ?? throw new InvalidDataException($"Could not parse corpus '{corpusPath}'.");

        var rows = new List<CaseResult>();
        foreach (var c in cases)
        {
            var original = Invoke(originalExe, c.Args);
            var protected_ = Invoke(protectedExe, c.Args);
            bool match = original.ExitCode == protected_.ExitCode
                && original.Stdout.AsSpan().SequenceEqual(protected_.Stdout)
                && original.Stderr.AsSpan().SequenceEqual(protected_.Stderr);
            rows.Add(new CaseResult
            {
                Id = c.Id,
                Kind = c.Kind,
                Match = match,
                OriginalExit = original.ExitCode,
                ProtectedExit = protected_.ExitCode,
                Note = match ? null : "stdout/stderr/exit mismatch",
            });
        }

        return (rows.Count(r => r.Match), rows.Count, rows);
    }

    private sealed record InvokeResult(int ExitCode, byte[] Stdout, byte[] Stderr);

    private static InvokeResult Invoke(string exePath, List<string> args)
    {
        var psi = new ProcessStartInfo(exePath)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        using var process = Process.Start(psi)!;
        using var stdoutStream = new MemoryStream();
        using var stderrStream = new MemoryStream();
        var stdoutTask = process.StandardOutput.BaseStream.CopyToAsync(stdoutStream);
        var stderrTask = process.StandardError.BaseStream.CopyToAsync(stderrStream);
        bool exited = process.WaitForExit(5000);
        if (!exited)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* best effort */ }
            return new InvokeResult(-1, Array.Empty<byte>(), Array.Empty<byte>());
        }
        Task.WaitAll(stdoutTask, stderrTask);
        return new InvokeResult(process.ExitCode, stdoutStream.ToArray(), stderrStream.ToArray());
    }

    public static string Sha256OfFile(string path) =>
        Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));
}
