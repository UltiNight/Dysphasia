using Mono.Cecil;
using Mono.Cecil.Cil;
using Mono.Cecil.Rocks;

namespace Dysphasia.Obfuscator;

public sealed class StringPassResult
{
    public int EncodedLiterals { get; set; }
    public int SkippedLiterals { get; set; }
    public int DistinctLiterals { get; set; }
    public int BlobBytes { get; set; }
    public List<string> EncodedValues { get; set; } = new();
}

/// <summary>
/// P2 pass: replaces `ldstr "literal"` with a call that XOR-decodes a slice of one shared
/// byte blob. This is deliberately NOT a cryptographic secret -- the key derivation and
/// decoder sit right next to the data in the same module (obfuscator-plan.draft.md, P2:
/// the decode routine ships with the binary and the plaintext exists in memory at
/// runtime; no cryptographic secrecy is claimed). The point is to remove
/// literal strings from static grep/string-table inspection, not from a determined
/// disassembler with an hour to spend.
///
/// v2: all distinct literals are packed into ONE blob stored via FieldRVA (the same
/// mechanism csc uses for `new byte[] { ...big literal... }`), materialized once in a
/// type initializer via `RuntimeHelpers.InitializeArray`. Each call site only pushes
/// (offset, length, key) and calls a shared decoder -- no per-byte IL at the call site.
/// v1 built a fresh array with `dup`+`ldc.i4`+`ldc.i4`+`stelem.i1` *inline at every call
/// site*, which cost roughly 12 IL bytes per source byte; see
/// reports/p1-p2-measurement.draft.md for the measured +60-70% file-size regression that
/// motivated this rewrite.
/// </summary>
public static class StringPass
{
    private sealed record LiteralSlot(int Offset, int Length, byte Key);

    private const int MinSplitLength = 6;

    public static StringPassResult Apply(ModuleDefinition module, Policy policy, long seed)
    {
        bool splitStrings = policy.Passes.Contains("string-splitting");
        var result = new StringPassResult();
        var methods = module.Types.SelectMany(FlattenNested).SelectMany(t => t.Methods)
            .Where(m => m.HasBody && m.Body.Instructions.Count > 0)
            .ToList();

        // --- 1. collect every eligible distinct literal across the whole module first,
        // so each one is stored exactly once in the shared blob regardless of how many
        // call sites use it (e.g. "mono"/"warm" each appear twice here). ---
        var eligibleLiterals = new List<string>();
        var seen = new HashSet<string>();
        foreach (var method in methods)
        {
            foreach (var instr in method.Body.Instructions)
            {
                if (instr.OpCode != OpCodes.Ldstr) continue;
                var literal = (string)instr.Operand;
                if (policy.ExcludeStrings.Contains(literal) || !IsAscii(literal)) continue;
                if (seen.Add(literal)) eligibleLiterals.Add(literal);
            }
        }

        if (eligibleLiterals.Count == 0) return result;

        var blob = new List<byte>();
        // Each literal maps to 1 slot normally, or 2 when "string-splitting" is enabled
        // and the literal is long enough for a split to mean anything (obfuscator-plan.draft.md's
        // String Splitting: shatter it into pieces and reassemble them at runtime) -- each piece gets its own offset/
        // length/key in the shared blob and is decoded independently; the call site
        // concatenates them instead of making one Decode call).
        var encodings = new Dictionary<string, LiteralSlot[]>();
        foreach (var literal in eligibleLiterals)
        {
            if (splitStrings && literal.Length >= MinSplitLength)
            {
                int cut = DeriveSplitPoint(seed, literal);
                encodings[literal] = new[]
                {
                    EncodePart(blob, seed, literal[..cut]),
                    EncodePart(blob, seed, literal[cut..]),
                };
            }
            else
            {
                encodings[literal] = new[] { EncodePart(blob, seed, literal) };
            }
        }

        var (decodeMethod, dataField) = InjectDecoder(module, seed, blob.ToArray());
        var concatMethod = BuildConcatRef(module);
        result.DistinctLiterals = encodings.Count;
        result.BlobBytes = blob.Count;

        // --- 2. rewrite every call site to pull its slice(s) out of the shared blob. ---
        foreach (var method in methods)
        {
            if (ReferenceEquals(method, decodeMethod)) continue;

            // Inserting IL at each ldstr site can push short-form branches (br.s,
            // brfalse.s, leave.s, ...) past the signed-byte offset range they can encode.
            // Expand everything to long form first so Cecil's writer never has to
            // silently truncate/mis-encode an offset.
            method.Body.SimplifyMacros();
            var il = method.Body.GetILProcessor();
            var ldstrInstructions = method.Body.Instructions
                .Where(i => i.OpCode == OpCodes.Ldstr)
                .ToList();

            foreach (var instr in ldstrInstructions)
            {
                var literal = (string)instr.Operand;
                if (!encodings.TryGetValue(literal, out var parts))
                {
                    result.SkippedLiterals++;
                    continue;
                }
                ReplaceWithDecodeCall(il, instr, parts, decodeMethod, concatMethod);
                result.EncodedLiterals++;
                result.EncodedValues.Add(literal);
            }
        }

        return result;
    }

    private static LiteralSlot EncodePart(List<byte> blob, long seed, string part)
    {
        var key = KeyFor(seed, part);
        var bytes = System.Text.Encoding.ASCII.GetBytes(part);
        var slot = new LiteralSlot(blob.Count, bytes.Length, key);
        for (int i = 0; i < bytes.Length; i++) blob.Add((byte)(bytes[i] ^ key));
        return slot;
    }

    private static int DeriveSplitPoint(long seed, string literal)
    {
        var bytes = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes($"split-point:{seed}:{literal}"));
        // keep both halves non-empty: cut in [1, length-1]
        return 1 + (int)(BitConverter.ToUInt32(bytes, 0) % (uint)(literal.Length - 1));
    }

    private static MethodReference BuildConcatRef(ModuleDefinition module)
    {
        var ts = module.TypeSystem;
        var concat = new MethodReference("Concat", ts.String, ts.String) { HasThis = false };
        concat.Parameters.Add(new ParameterDefinition(ts.String));
        concat.Parameters.Add(new ParameterDefinition(ts.String));
        return concat;
    }

    private static IEnumerable<TypeDefinition> FlattenNested(TypeDefinition type)
    {
        yield return type;
        foreach (var nested in type.NestedTypes)
            foreach (var t in FlattenNested(nested))
                yield return t;
    }

    private static bool IsAscii(string s) => s.All(c => c < 128);

    // NOTE: must not derive from string.GetHashCode() anywhere in this chain -- .NET
    // randomizes string hash codes per process by default (hash-flooding DoS hardening),
    // so a key built from one would differ across separate runs of the *same* seed and
    // input, silently breaking the "same seed -> byte-identical build" guarantee P4
    // depends on (mapping-file lookup by build identity). SHA256 over the literal's own
    // UTF-8 bytes is deterministic across processes/machines/.NET versions.
    private static byte KeyFor(long seed, string literal) =>
        System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes($"strkey:{seed}:{literal}"))[0];

    private static void ReplaceWithDecodeCall(
        ILProcessor il, Instruction ldstrInstr, LiteralSlot[] parts,
        MethodReference decodeMethod, MethodReference concatMethod)
    {
        var newInstructions = new List<Instruction>();
        foreach (var slot in parts)
        {
            newInstructions.Add(Instruction.Create(OpCodes.Ldc_I4, slot.Offset));
            newInstructions.Add(Instruction.Create(OpCodes.Ldc_I4, slot.Length));
            newInstructions.Add(Instruction.Create(OpCodes.Ldc_I4, (int)slot.Key));
            newInstructions.Add(Instruction.Create(OpCodes.Call, decodeMethod));
        }
        if (parts.Length > 1)
            newInstructions.Add(Instruction.Create(OpCodes.Call, concatMethod));

        foreach (var instr in newInstructions) il.InsertBefore(ldstrInstr, instr);
        RedirectReferences(il.Body, ldstrInstr, newInstructions[0]);
        il.Remove(ldstrInstr);
    }

    private static void RedirectReferences(MethodBody body, Instruction oldTarget, Instruction newTarget)
    {
        foreach (var instr in body.Instructions)
        {
            if (ReferenceEquals(instr.Operand, oldTarget)) instr.Operand = newTarget;
            else if (instr.Operand is Instruction[] targets)
                for (int i = 0; i < targets.Length; i++)
                    if (ReferenceEquals(targets[i], oldTarget)) targets[i] = newTarget;
        }
        foreach (var handler in body.ExceptionHandlers)
        {
            if (ReferenceEquals(handler.TryStart, oldTarget)) handler.TryStart = newTarget;
            if (ReferenceEquals(handler.TryEnd, oldTarget)) handler.TryEnd = newTarget;
            if (ReferenceEquals(handler.HandlerStart, oldTarget)) handler.HandlerStart = newTarget;
            if (ReferenceEquals(handler.HandlerEnd, oldTarget)) handler.HandlerEnd = newTarget;
            if (ReferenceEquals(handler.FilterStart, oldTarget)) handler.FilterStart = newTarget;
        }
    }

    private static TypeReference BuildTypeRef(ModuleDefinition module, string ns, string name, bool isValueType)
    {
        // module.TypeSystem has no public helper for arbitrary corlib types (only the
        // ECMA "built-in" primitives), so build the reference by hand, anchored to
        // whatever scope System.Object already resolves against -- i.e. the exact
        // corlib (old .NET Framework mscorlib, in this project's fixture) the target
        // module references, never this tool's own .NET 10 runtime assemblies.
        var scope = module.TypeSystem.Object.Scope;
        return new TypeReference(ns, name, module, scope, isValueType);
    }

    /// <summary>
    /// Packs <paramref name="blob"/> into the module as:
    ///   - a private nested value type sized exactly blob.Length, holding the raw bytes
    ///     via FieldRVA (the mechanism csc uses for `new byte[]{ big literal }`);
    ///   - a static byte[] field materialized from it once, in a type initializer, via
    ///     `RuntimeHelpers.InitializeArray` (one call, regardless of blob size);
    ///   - a decoder `string Decode(int offset, int length, byte key)` that XORs a slice
    ///     of that byte[] and builds the resulting string.
    /// Returns (decodeMethod, dataField) for call sites to reference.
    /// </summary>
    private static (MethodDefinition Decode, FieldDefinition DataField) InjectDecoder(
        ModuleDefinition module, long seed, byte[] blob)
    {
        var ts = module.TypeSystem;
        var hostName = NameGenerator.Generate(seed, "__string_host__", "T");
        var hostType = new TypeDefinition("", hostName,
            TypeAttributes.NotPublic | TypeAttributes.Abstract | TypeAttributes.Sealed, ts.Object);
        module.Types.Add(hostType);

        // --- RVA-backed raw blob, held by a fixed-size value type nested in hostType. ---
        var valueTypeBaseRef = BuildTypeRef(module, "System", "ValueType", isValueType: false);
        var blobType = new TypeDefinition("", NameGenerator.Generate(seed, "__string_blob_type__", "T"),
            TypeAttributes.NestedPrivate | TypeAttributes.Sealed | TypeAttributes.ExplicitLayout
            | TypeAttributes.AnsiClass, valueTypeBaseRef)
        {
            ClassSize = blob.Length,
            PackingSize = 1,
        };
        hostType.NestedTypes.Add(blobType);

        var rvaField = new FieldDefinition(NameGenerator.Generate(seed, "__string_rva__", "f_"),
            FieldAttributes.Static | FieldAttributes.Assembly | FieldAttributes.HasFieldRVA, blobType)
        {
            InitialValue = blob,
        };
        hostType.Fields.Add(rvaField);

        var dataField = new FieldDefinition(NameGenerator.Generate(seed, "__string_data__", "f_"),
            FieldAttributes.Static | FieldAttributes.Assembly, new ArrayType(ts.Byte));
        hostType.Fields.Add(dataField);

        // --- type initializer: materialize the byte[] from the RVA blob once. ---
        var cctor = new MethodDefinition(".cctor",
            MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName
            | MethodAttributes.RTSpecialName | MethodAttributes.HideBySig, ts.Void);
        hostType.Methods.Add(cctor);

        var initializeArray = new MethodReference("InitializeArray", ts.Void,
            BuildTypeRef(module, "System.Runtime.CompilerServices", "RuntimeHelpers", isValueType: false))
        { HasThis = false };
        initializeArray.Parameters.Add(new ParameterDefinition(BuildTypeRef(module, "System", "Array", isValueType: false)));
        initializeArray.Parameters.Add(new ParameterDefinition(BuildTypeRef(module, "System", "RuntimeFieldHandle", isValueType: true)));

        var cctorIl = cctor.Body.GetILProcessor();
        cctorIl.Append(Instruction.Create(OpCodes.Ldc_I4, blob.Length));
        cctorIl.Append(Instruction.Create(OpCodes.Newarr, ts.Byte));
        cctorIl.Append(Instruction.Create(OpCodes.Dup));
        cctorIl.Append(Instruction.Create(OpCodes.Ldtoken, rvaField));
        cctorIl.Append(Instruction.Create(OpCodes.Call, initializeArray));
        cctorIl.Append(Instruction.Create(OpCodes.Stsfld, dataField));
        cctorIl.Append(Instruction.Create(OpCodes.Ret));

        // --- decoder: string Decode(int offset, int length, byte key). ---
        var decodeName = NameGenerator.Generate(seed, "__string_decode__", "m_");
        var decode = new MethodDefinition(decodeName,
            MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig, ts.String);
        decode.Parameters.Add(new ParameterDefinition("offset", ParameterAttributes.None, ts.Int32));
        decode.Parameters.Add(new ParameterDefinition("length", ParameterAttributes.None, ts.Int32));
        decode.Parameters.Add(new ParameterDefinition("key", ParameterAttributes.None, ts.Byte));
        hostType.Methods.Add(decode);

        var body = decode.Body;
        body.InitLocals = true;
        var chars = new VariableDefinition(new ArrayType(ts.Char));
        var i = new VariableDefinition(ts.Int32);
        body.Variables.Add(chars);
        body.Variables.Add(i);

        var stringCtor = new MethodReference(".ctor", ts.Void, ts.String) { HasThis = true };
        stringCtor.Parameters.Add(new ParameterDefinition(new ArrayType(ts.Char)));

        var il = body.GetILProcessor();
        var loopStart = Instruction.Create(OpCodes.Nop);
        var loopBody = Instruction.Create(OpCodes.Nop);
        var buildString = Instruction.Create(OpCodes.Ldloc, chars);

        il.Append(Instruction.Create(OpCodes.Ldarg_1));            // length
        il.Append(Instruction.Create(OpCodes.Newarr, ts.Char));
        il.Append(Instruction.Create(OpCodes.Stloc, chars));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_0));
        il.Append(Instruction.Create(OpCodes.Stloc, i));
        il.Append(Instruction.Create(OpCodes.Br, loopStart));

        il.Append(loopBody);
        il.Append(Instruction.Create(OpCodes.Ldloc, chars));
        il.Append(Instruction.Create(OpCodes.Ldloc, i));
        il.Append(Instruction.Create(OpCodes.Ldsfld, dataField));
        il.Append(Instruction.Create(OpCodes.Ldarg_0));            // offset
        il.Append(Instruction.Create(OpCodes.Ldloc, i));
        il.Append(Instruction.Create(OpCodes.Add));
        il.Append(Instruction.Create(OpCodes.Ldelem_U1));
        il.Append(Instruction.Create(OpCodes.Ldarg_2));            // key
        il.Append(Instruction.Create(OpCodes.Xor));
        il.Append(Instruction.Create(OpCodes.Conv_U2));
        il.Append(Instruction.Create(OpCodes.Stelem_I2));
        il.Append(Instruction.Create(OpCodes.Ldloc, i));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_1));
        il.Append(Instruction.Create(OpCodes.Add));
        il.Append(Instruction.Create(OpCodes.Stloc, i));

        il.Append(loopStart);
        il.Append(Instruction.Create(OpCodes.Ldloc, i));
        il.Append(Instruction.Create(OpCodes.Ldarg_1));            // length
        il.Append(Instruction.Create(OpCodes.Blt, loopBody));

        il.Append(buildString);
        il.Append(Instruction.Create(OpCodes.Newobj, stringCtor));
        il.Append(Instruction.Create(OpCodes.Ret));

        return (decode, dataField);
    }
}
