using System.Security.Cryptography;
using System.Text;

namespace Dysphasia.Obfuscator;

/// <summary>
/// Deterministic identifier generator: same (seed, original full name) always produces
/// the same obfuscated name, so re-running "protect" with the same policy/seed on an
/// unchanged input is reproducible (reports/obfuscator-plan.draft.md: "seed", "reproducibility").
/// Not a cryptographic secret -- the mapping file is what actually needs protecting,
/// not this derivation.
/// </summary>
public static class NameGenerator
{
    public static string Generate(long seed, string originalFullName, string prefix)
    {
        var input = $"{seed}:{originalFullName}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        var sb = new StringBuilder(prefix);
        // 10 hex chars is plenty to avoid collisions in a single small module and keeps
        // names short enough to read in IL dumps during debugging.
        for (int i = 0; i < 5; i++)
            sb.Append(hash[i].ToString("x2"));
        return sb.ToString();
    }
}
