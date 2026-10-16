using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Dysphasia.Obfuscator;

/// <summary>
/// Protection policy: what gets renamed, what is excluded and why, and the seed used
/// for deterministic name generation. See reports/obfuscator-plan.draft.md (the policy-file section).
/// </summary>
public sealed class Policy
{
    [JsonPropertyName("policyVersion")]
    public int PolicyVersion { get; set; } = 1;

    [JsonPropertyName("seed")]
    public long Seed { get; set; } = 20261014;

    /// <summary>Passes to apply. MVP only implements "rename".</summary>
    [JsonPropertyName("passes")]
    public List<string> Passes { get; set; } = new() { "rename" };

    /// <summary>Fully-qualified type names (Namespace.Type) never renamed.</summary>
    [JsonPropertyName("excludeTypes")]
    public List<string> ExcludeTypes { get; set; } = new();

    /// <summary>"Namespace.Type::Member" entries never renamed.</summary>
    [JsonPropertyName("excludeMembers")]
    public List<string> ExcludeMembers { get; set; } = new();

    /// <summary>Human-readable reason per excluded entry, required for anything added above.</summary>
    [JsonPropertyName("excludeReasons")]
    public Dictionary<string, string> ExcludeReasons { get; set; } = new();

    /// <summary>Exact literal values never passed through the P2 string-encode pass
    /// (e.g. strings a plugin contract or log-scraper matches on verbatim).</summary>
    [JsonPropertyName("excludeStrings")]
    public List<string> ExcludeStrings { get; set; } = new();

    public static Policy Load(string path)
    {
        var json = File.ReadAllText(path);
        var policy = JsonSerializer.Deserialize<Policy>(json)
            ?? throw new InvalidDataException($"Policy file '{path}' did not deserialize.");
        policy.Validate();
        return policy;
    }

    public void Validate()
    {
        foreach (var member in ExcludeMembers)
        {
            if (!ExcludeReasons.ContainsKey(member))
                throw new InvalidDataException(
                    $"excludeMembers entry '{member}' has no matching excludeReasons entry. " +
                    "Every exclusion must record why (reflection, serialization, PInvoke, ...).");
        }
        foreach (var type in ExcludeTypes)
        {
            if (!ExcludeReasons.ContainsKey(type))
                throw new InvalidDataException(
                    $"excludeTypes entry '{type}' has no matching excludeReasons entry.");
        }
    }

    public string ComputeHash()
    {
        var canonical = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = false });
        var bytes = System.Text.Encoding.UTF8.GetBytes(canonical);
        return Convert.ToHexStringLower(SHA256.HashData(bytes));
    }
}
