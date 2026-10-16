using System.Security.Cryptography;
using System.Text;

namespace Dysphasia.Obfuscator;

/// <summary>
/// Two naming techniques layered on top of P1's existing hash-based rename:
///
/// Semantic poisoning: instead of a neutral-looking hash name
/// (`m_22283830b7`), pick a *plausible but wrong* name from a fixed vocabulary --
/// `ClampByte` renamed to something that reads like `ValidateChecksum` actively
/// misleads a reader's mental model, rather than just failing to help it. The
/// technique's usual framing is "disguise a malicious function as an innocent one";
/// this fixture has nothing malicious to disguise, so what's borrowed is only the
/// *deception* half -- a method doing one thing gets a name suggesting it does a
/// different, unrelated thing.
///
/// Homoglyph injection: some ASCII letters in the picked name are swapped for
/// Cyrillic look-alikes (а/е/о/р/с/х for a/e/o/p/c/x) that render identically in most
/// fonts but are different code points and different tokens to a tokenizer. Scoped
/// strictly to these already-private, already-renamed identifiers -- never applied to
/// anything that could impersonate a real trusted name, which is the actual malicious
/// use of this technique (typosquatting a package/identifier name) and exactly what
/// makes it reasonable to use here and not elsewhere.
/// </summary>
public static class DeceptiveNameGenerator
{
    private static readonly string[] MethodPool =
    {
        "ValidateChecksum", "SyncMetadata", "FlushBuffer", "InitializeCache",
        "ResolveDependency", "NormalizeEncoding", "CommitTransaction", "RefreshToken",
        "SerializeState", "DeallocateHandle", "RegisterCallback", "ThrottleRequest",
        "AuthenticateSession", "RebuildIndex", "ReconcileLedger",
    };

    private static readonly string[] TypePool =
    {
        "SessionManager", "CacheController", "TransactionBroker", "MetadataResolver",
        "ConnectionPool", "EventDispatcher",
    };

    private static readonly Dictionary<char, char> Homoglyphs = new()
    {
        ['a'] = 'а', ['e'] = 'е', ['o'] = 'о', ['p'] = 'р', ['c'] = 'с', ['x'] = 'х',
        ['A'] = 'А', ['E'] = 'Е', ['O'] = 'О', ['P'] = 'Р', ['C'] = 'С', ['X'] = 'Х',
    };

    /// <summary>Picks the first collision-free candidate from the seeded-shuffled pool
    /// order, applying homoglyphs if requested; falls back to the plain hash-based name
    /// if the whole pool is somehow already taken (shouldn't happen for this fixture's
    /// handful of renamed members against a 15/6-word pool, but fail safe rather than
    /// ever emit a duplicate identifier).</summary>
    public static string Generate(long seed, string originalFullName, bool isType, bool homoglyphs, HashSet<string> used)
    {
        var pool = isType ? TypePool : MethodPool;
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes($"deceptive:{seed}:{originalFullName}"));
        var start = (int)(BitConverter.ToUInt32(bytes, 0) % (uint)pool.Length);

        // Collision check happens on the *base* pool word, before homoglyphs -- two
        // different methods both landing on "InitializeCache" and only being told
        // apart by which letters got swapped for Cyrillic look-alikes would read, to a
        // human skimming the member list, as the same name shown twice. Each used base
        // word is reserved outright, so every picked name is lexically distinct first;
        // homoglyphs are then just an additional disguise on top of that, not what
        // establishes uniqueness.
        for (int offset = 0; offset < pool.Length; offset++)
        {
            var baseWord = pool[(start + offset) % pool.Length];
            if (!used.Add(baseWord)) continue;
            return homoglyphs ? ApplyHomoglyphs(baseWord, seed, originalFullName, offset) : baseWord;
        }

        return NameGenerator.Generate(seed, originalFullName, isType ? "T" : "m_");
    }

    private static string ApplyHomoglyphs(string name, long seed, string originalFullName, int ordinal)
    {
        var mask = SHA256.HashData(Encoding.UTF8.GetBytes($"homoglyph:{seed}:{originalFullName}:{ordinal}"));
        var chars = name.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            if (Homoglyphs.TryGetValue(chars[i], out var lookalike) && (mask[i % mask.Length] & 1) == 1)
                chars[i] = lookalike;
        }
        return new string(chars);
    }
}
