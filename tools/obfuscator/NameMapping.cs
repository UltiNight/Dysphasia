using System.Text.Json;
using System.Text.Json.Serialization;

namespace Dysphasia.Obfuscator;

public sealed class MappingEntry
{
    [JsonPropertyName("kind")]
    public string Kind { get; set; } = ""; // "type" | "method"

    [JsonPropertyName("originalFullName")]
    public string OriginalFullName { get; set; } = "";

    [JsonPropertyName("newName")]
    public string NewName { get; set; } = "";

    [JsonPropertyName("metadataToken")]
    public string MetadataToken { get; set; } = "";
}

/// <summary>
/// Reverse map from obfuscated names back to original names. Kept OUT of the protected
/// output directory on purpose (reports/obfuscator-plan.draft.md: mapping storage keeps the
/// name/location correspondence table separate from the distributed build).
/// Needed to read crash dumps / stack traces from the protected build.
/// </summary>
public sealed class MappingFile
{
    [JsonPropertyName("policyVersion")]
    public int PolicyVersion { get; set; }

    [JsonPropertyName("policyHash")]
    public string PolicyHash { get; set; } = "";

    [JsonPropertyName("seed")]
    public long Seed { get; set; }

    [JsonPropertyName("sourceSha256")]
    public string SourceSha256 { get; set; } = "";

    [JsonPropertyName("sourceMvid")]
    public string SourceMvid { get; set; } = "";

    [JsonPropertyName("outputSha256")]
    public string OutputSha256 { get; set; } = "";

    [JsonPropertyName("outputMvid")]
    public string OutputMvid { get; set; } = "";

    [JsonPropertyName("createdAtUtc")]
    public string CreatedAtUtc { get; set; } = "";

    [JsonPropertyName("entries")]
    public List<MappingEntry> Entries { get; set; } = new();

    public void Save(string path)
    {
        var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        File.WriteAllText(path, json);
    }

    public static MappingFile Load(string path)
    {
        var json = File.ReadAllText(path);
        return JsonSerializer.Deserialize<MappingFile>(json)
            ?? throw new InvalidDataException($"Mapping file '{path}' did not deserialize.");
    }
}
