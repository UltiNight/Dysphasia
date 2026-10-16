namespace Dysphasia.Obfuscator;

/// <summary>
/// Minimal PE header reader used only to detect an Authenticode certificate table.
/// This does not validate the signature, only whether one is present -- the MVP policy
/// (reports/obfuscator-plan.draft.md, the compatibility-and-signing section) is to reject signed inputs outright
/// because there is no re-signing pipeline yet.
/// </summary>
public static class PeSignature
{
    public static bool HasAuthenticodeCertificate(string path)
    {
        using var stream = File.OpenRead(path);
        using var reader = new BinaryReader(stream);

        if (stream.Length < 0x40) return false;
        stream.Seek(0, SeekOrigin.Begin);
        if (reader.ReadUInt16() != 0x5A4D) return false; // "MZ"

        stream.Seek(0x3C, SeekOrigin.Begin);
        uint peHeaderOffset = reader.ReadUInt32();

        stream.Seek(peHeaderOffset, SeekOrigin.Begin);
        if (reader.ReadUInt32() != 0x00004550) return false; // "PE\0\0"

        // COFF file header: Machine, NumberOfSections, TimeDateStamp, PointerToSymbolTable,
        // NumberOfSymbols, SizeOfOptionalHeader, Characteristics = 20 bytes total.
        stream.Seek(peHeaderOffset + 4 + 16, SeekOrigin.Begin); // skip to SizeOfOptionalHeader
        ushort sizeOfOptionalHeader = reader.ReadUInt16();
        if (sizeOfOptionalHeader == 0) return false;

        long optionalHeaderStart = peHeaderOffset + 4 + 20;
        stream.Seek(optionalHeaderStart, SeekOrigin.Begin);
        ushort magic = reader.ReadUInt16();

        // Data directories start right after the "standard"/"NT additional" fields.
        // PE32 (0x10B): offset 96 from optional header start. PE32+ (0x20B): offset 112.
        long dataDirectoriesStart = optionalHeaderStart + (magic == 0x20B ? 112 : 96);

        // IMAGE_DIRECTORY_ENTRY_SECURITY is index 4; each entry is 8 bytes (RVA/offset, Size).
        long securityEntryOffset = dataDirectoriesStart + 4 * 8;
        if (securityEntryOffset + 8 > stream.Length) return false;

        stream.Seek(securityEntryOffset, SeekOrigin.Begin);
        uint certTableOffset = reader.ReadUInt32();
        uint certTableSize = reader.ReadUInt32();

        return certTableOffset != 0 && certTableSize != 0;
    }
}
