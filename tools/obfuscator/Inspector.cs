using System.Security.Cryptography;
using System.Text.Json;
using Mono.Cecil;

namespace Dysphasia.Obfuscator;

public sealed class InspectionReport
{
    public bool Supported { get; set; }
    public List<string> RejectionReasons { get; set; } = new();
    public string Sha256 { get; set; } = "";
    public string? Mvid { get; set; }
    public bool HasPdbCompanion { get; set; }
    public bool HasEmbeddedPdb { get; set; }
    public bool HasAuthenticodeSignature { get; set; }
    public bool HasStrongNameSignature { get; set; }
    public bool HasStrongNamePublicKey { get; set; }
    public int TypeCount { get; set; }
    public int MethodCount { get; set; }
    public string? EntryPoint { get; set; }
}

/// <summary>Input gate -- decides whether a binary is even eligible
/// for the rename pass, and records why not when it isn't.</summary>
public static class Inspector
{
    public static InspectionReport Inspect(string exePath)
    {
        var report = new InspectionReport();
        report.Sha256 = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(exePath)));

        var pdbPath = Path.ChangeExtension(exePath, ".pdb");
        report.HasPdbCompanion = File.Exists(pdbPath);
        report.HasAuthenticodeSignature = PeSignature.HasAuthenticodeCertificate(exePath);

        ModuleDefinition? module = null;
        try
        {
            var readerParams = new ReaderParameters { ReadSymbols = false, InMemory = true };
            module = ModuleDefinition.ReadModule(exePath, readerParams);
        }
        catch (Exception ex)
        {
            report.Supported = false;
            report.RejectionReasons.Add($"Not a readable CLI assembly: {ex.GetType().Name}: {ex.Message}");
            return report;
        }

        using (module)
        {
            report.Mvid = module.Mvid.ToString();
            report.HasEmbeddedPdb = module.HasDebugHeader && module.GetDebugHeader().Entries.Length > 0;
            report.HasStrongNameSignature = module.Attributes.HasFlag(ModuleAttributes.StrongNameSigned);
            report.HasStrongNamePublicKey = module.Assembly.Name.PublicKey is { Length: > 0 };
            report.TypeCount = module.Types.Count; // includes <Module>
            report.MethodCount = module.Types.SelectMany(t => t.Methods).Count();
            report.EntryPoint = module.EntryPoint?.FullName;

            if (!module.Kind.ToString().Contains("Console") && module.Kind != ModuleKind.Windows
                && module.Kind != ModuleKind.Console)
            {
                // Still allowed -- just recorded. Non-executable modules (DLLs) are not
                // rejected by the MVP, only flagged, since the policy only talks about
                // signature/size/mixed-mode exclusions.
            }

            if (report.HasAuthenticodeSignature)
                report.RejectionReasons.Add(
                    "Authenticode certificate present; MVP has no re-signing pipeline (obfuscator-plan.draft.md).");
            if (report.HasStrongNameSignature || report.HasStrongNamePublicKey)
                report.RejectionReasons.Add(
                    "Strong-name signed/keyed; renaming would invalidate the signature and MVP cannot re-sign.");
            if (module.Attributes.HasFlag(ModuleAttributes.ILLibrary))
                report.RejectionReasons.Add("IL-library / mixed-mode module; unsupported in MVP.");

            bool singleFileBundle = false;
            try
            {
                // A single-file apphost bundle has a bundle signature appended after the
                // PE image; Cecil would still have opened the PE part above, so detect it
                // by looking for the bundle magic near the tail of the file.
                var bytes = File.ReadAllBytes(exePath);
                var marker = System.Text.Encoding.ASCII.GetBytes(".net core bundle");
                singleFileBundle = IndexOf(bytes, marker) >= 0;
            }
            catch { /* best effort */ }
            if (singleFileBundle)
                report.RejectionReasons.Add("Single-file bundle marker detected; unsupported in MVP.");

            report.Supported = report.RejectionReasons.Count == 0;
        }

        return report;
    }

    private static int IndexOf(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0 || haystack.Length < needle.Length) return -1;
        for (int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { match = false; break; }
            }
            if (match) return i;
        }
        return -1;
    }

    public static string ToJson(InspectionReport report) =>
        JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
}
