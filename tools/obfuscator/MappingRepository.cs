using System.Text.Json;

namespace Dysphasia.Obfuscator;

public sealed class MappingIndexEntry
{
    public string MappingPath { get; set; } = "";
    public string SourceSha256 { get; set; } = "";
    public string SourceMvid { get; set; } = "";
    public string OutputSha256 { get; set; } = "";
    public string OutputMvid { get; set; } = "";
    public long Seed { get; set; }
    public string PolicyHash { get; set; } = "";
    public string CreatedAtUtc { get; set; } = "";
    public int EntryCount { get; set; }
}

/// <summary>
/// P4's other half ("mapping management", obfuscator-plan.draft.md): a build-time seed override
/// already makes every release's names/blob/state-ids different (see
/// reports/p1-p2-measurement.draft.md's P4 measurement). What was still missing is a way to go
/// the other direction -- given a crash dump from *some* shipped build, find which
/// mapping file it came from and translate a reported obfuscated symbol back to its
/// original name, without the support engineer needing to know in advance which of
/// possibly many release mapping files applies.
/// </summary>
public static class MappingRepository
{
    public static List<MappingIndexEntry> BuildIndex(string mappingDir)
    {
        var entries = new List<MappingIndexEntry>();
        foreach (var path in Directory.EnumerateFiles(mappingDir, "*.mapping.json"))
        {
            MappingFile mapping;
            try { mapping = MappingFile.Load(path); }
            catch { continue; } // skip anything that isn't a valid mapping file
            entries.Add(new MappingIndexEntry
            {
                MappingPath = Path.GetFullPath(path),
                SourceSha256 = mapping.SourceSha256,
                SourceMvid = mapping.SourceMvid,
                OutputSha256 = mapping.OutputSha256,
                OutputMvid = mapping.OutputMvid,
                Seed = mapping.Seed,
                PolicyHash = mapping.PolicyHash,
                CreatedAtUtc = mapping.CreatedAtUtc,
                EntryCount = mapping.Entries.Count,
            });
        }
        return entries.OrderBy(e => e.CreatedAtUtc).ToList();
    }

    public static void SaveIndex(List<MappingIndexEntry> index, string outPath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outPath))!);
        File.WriteAllText(outPath, JsonSerializer.Serialize(index, new JsonSerializerOptions { WriteIndented = true }));
    }

    /// <summary>Finds the mapping file whose recorded output identity (SHA-256 or MVID)
    /// matches the crashed build, then reverses the given obfuscated name back to its
    /// original full name. Matching by MVID is what lets this work even when the exact
    /// shipped .exe bytes aren't at hand -- only a crash report's module identity is.</summary>
    public static (string? OriginalName, string? MatchedMappingPath) Resolve(
        string mappingDir, string obfuscatedName, string? sha256, string? mvid)
    {
        foreach (var path in Directory.EnumerateFiles(mappingDir, "*.mapping.json"))
        {
            MappingFile mapping;
            try { mapping = MappingFile.Load(path); }
            catch { continue; }

            bool matches =
                (sha256 is not null && string.Equals(mapping.OutputSha256, sha256, StringComparison.OrdinalIgnoreCase)) ||
                (mvid is not null && string.Equals(mapping.OutputMvid, mvid, StringComparison.OrdinalIgnoreCase));
            if (!matches) continue;

            var entry = mapping.Entries.FirstOrDefault(e =>
                string.Equals(e.NewName, obfuscatedName, StringComparison.Ordinal));
            if (entry is not null)
                return (entry.OriginalFullName, Path.GetFullPath(path));
        }
        return (null, null);
    }
}
