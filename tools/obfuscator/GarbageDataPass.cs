using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Dysphasia.Obfuscator;

public sealed class GarbageDataPassResult
{
    public int InjectedFields { get; set; }
    public int InjectedMethods { get; set; }
}

/// <summary>
/// Injects fields and methods that the real program never reads, writes, or calls --
/// pure noise for anyone enumerating `inspect-managed-members` or skimming a member
/// list. Each dummy method does *some* plausible-looking arithmetic over the dummy
/// fields (not just `ret`), so it doesn't read as obviously inert at a glance; nothing
/// it computes is ever observed by real code, so it cannot affect program behavior no
/// matter what it does -- there is no call site to verify, which is itself the main
/// reason this is one of the lower-risk techniques to add: a bug here could only ever be
/// "it computes a different piece of garbage," never "it breaks correctness."
/// </summary>
public static class GarbageDataPass
{
    public static GarbageDataPassResult Apply(ModuleDefinition module, Policy policy, long seed)
    {
        var result = new GarbageDataPassResult();
        var ts = module.TypeSystem;
        var hostName = NameGenerator.Generate(seed, "__garbage_host__", "T");
        var hostType = new TypeDefinition("", hostName,
            TypeAttributes.NotPublic | TypeAttributes.Abstract | TypeAttributes.Sealed, ts.Object);
        module.Types.Add(hostType);

        const int fieldCount = 4;
        var fields = new List<FieldDefinition>();
        for (int i = 0; i < fieldCount; i++)
        {
            var field = new FieldDefinition(
                NameGenerator.Generate(seed, $"__garbage_field__{i}", "f_"),
                FieldAttributes.Static | FieldAttributes.Assembly, ts.Int32);
            hostType.Fields.Add(field);
            fields.Add(field);
            result.InjectedFields++;
        }

        // Type initializer: seed each dummy field with a distinct constant so they don't
        // all read as a suspiciously uniform block of zeros.
        var cctor = new MethodDefinition(".cctor",
            MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName
            | MethodAttributes.RTSpecialName | MethodAttributes.HideBySig, ts.Void);
        hostType.Methods.Add(cctor);
        var cctorIl = cctor.Body.GetILProcessor();
        for (int i = 0; i < fields.Count; i++)
        {
            cctorIl.Append(Instruction.Create(OpCodes.Ldc_I4, DeriveSeedValue(seed, i)));
            cctorIl.Append(Instruction.Create(OpCodes.Stsfld, fields[i]));
        }
        cctorIl.Append(Instruction.Create(OpCodes.Ret));

        const int methodCount = 6;
        for (int i = 0; i < methodCount; i++)
        {
            var method = new MethodDefinition(
                NameGenerator.Generate(seed, $"__garbage_method__{i}", "m_"),
                MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig, ts.Int32);
            method.Parameters.Add(new ParameterDefinition("x", ParameterAttributes.None, ts.Int32));
            hostType.Methods.Add(method);

            var a = fields[i % fields.Count];
            var b = fields[(i + 1) % fields.Count];
            var il = method.Body.GetILProcessor();
            // return (x ^ fieldA) + (fieldB * x) - some arithmetic that reads like it
            // belongs to a real computation, over values nothing real ever reads back.
            il.Append(Instruction.Create(OpCodes.Ldarg_0));
            il.Append(Instruction.Create(OpCodes.Ldsfld, a));
            il.Append(Instruction.Create(OpCodes.Xor));
            il.Append(Instruction.Create(OpCodes.Ldsfld, b));
            il.Append(Instruction.Create(OpCodes.Ldarg_0));
            il.Append(Instruction.Create(OpCodes.Mul));
            il.Append(Instruction.Create(OpCodes.Add));
            il.Append(Instruction.Create(OpCodes.Ret));
            result.InjectedMethods++;
        }

        return result;
    }

    private static int DeriveSeedValue(long seed, int ordinal)
    {
        var bytes = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes($"garbage-seed:{seed}:{ordinal}"));
        return BitConverter.ToInt32(bytes, 0);
    }
}
