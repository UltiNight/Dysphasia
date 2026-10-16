using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Dysphasia.Obfuscator;

public sealed class BclCallHidingResult
{
    public int HiddenCallSites { get; set; }
    public List<string> HiddenTargets { get; set; } = new();
}

/// <summary>
/// Hides specific BCL call targets from the MemberRef table by redirecting the call
/// instruction's operand to a same-module method with an *identical parameter/return
/// signature* that resolves and invokes the real BCL method via reflection at runtime.
/// Because the stack contract (arg count, arg types, return type) is unchanged, nothing
/// at the call site needs touching -- only the single instruction's Operand is swapped,
/// the same trick P1 already uses for renaming (session finding: BCL call targets were
/// showing up completely exposed -- Int32.TryParse's call site told an analyst exactly
/// what ReadInt does before they read a single renamed identifier).
///
/// The method name passed to reflection ("TryParse") is itself hidden using the same
/// XOR-blob-over-FieldRVA mechanism as P2 (StringPass), scoped to this pass's own tiny
/// host type -- deliberately not shared with StringPass's host type/blob, to keep this
/// pass self-contained and independent of string-encode's pipeline position.
///
/// Scope (first increment): Int32.TryParse(string, NumberStyles, IFormatProvider, out int),
/// the exact overload ReadInt calls and the single highest-value target identified when
/// measuring what REA's `inspect-managed-members` exposes on a fully P1-P3 protected
/// build. Other BCL targets (Console.WriteLine, ArgumentException..ctor, String equality)
/// are smaller leaks individually and are left for a follow-up increment.
/// </summary>
public static class BclCallHidingPass
{
    private const int BindingFlagsPublicStaticInvokeMethod = 280; // Public(16)|Static(8)|InvokeMethod(256)

    public static BclCallHidingResult Apply(ModuleDefinition module, Policy policy, long seed)
    {
        var result = new BclCallHidingResult();
        var methods = module.Types.SelectMany(FlattenNested).SelectMany(t => t.Methods)
            .Where(m => m.HasBody && m.Body.Instructions.Count > 0)
            .ToList();

        var callSites = new List<(MethodDefinition Method, Instruction Instr)>();
        foreach (var method in methods)
        foreach (var instr in method.Body.Instructions)
        {
            if (instr.OpCode != OpCodes.Call) continue;
            if (instr.Operand is not MethodReference mr) continue;
            if (IsInt32TryParse(mr)) callSites.Add((method, instr));
        }

        if (callSites.Count == 0) return result;

        var hiddenTryParse = InjectHiddenTryParse(module, seed);
        foreach (var (method, instr) in callSites)
        {
            instr.Operand = hiddenTryParse;
            result.HiddenCallSites++;
        }
        result.HiddenTargets.Add("System.Int32::TryParse(System.String,System.Globalization.NumberStyles,System.IFormatProvider,System.Int32&)");

        return result;
    }

    private static IEnumerable<TypeDefinition> FlattenNested(TypeDefinition type)
    {
        yield return type;
        foreach (var nested in type.NestedTypes)
            foreach (var t in FlattenNested(nested))
                yield return t;
    }

    private static bool IsInt32TryParse(MethodReference mr) =>
        mr.Name == "TryParse" &&
        mr.DeclaringType.FullName == "System.Int32" &&
        mr.Parameters.Count == 4 &&
        mr.Parameters[0].ParameterType.FullName == "System.String" &&
        mr.Parameters[1].ParameterType.FullName == "System.Globalization.NumberStyles" &&
        mr.Parameters[2].ParameterType.FullName == "System.IFormatProvider" &&
        mr.Parameters[3].ParameterType is ByReferenceType brt && brt.ElementType.FullName == "System.Int32";

    private static TypeReference BuildTypeRef(ModuleDefinition module, string ns, string name, bool isValueType)
    {
        var scope = module.TypeSystem.Object.Scope;
        return new TypeReference(ns, name, module, scope, isValueType);
    }

    // See StringPass.KeyFor: never derive from string.GetHashCode() -- .NET randomizes
    // string hash codes per process, which would make this key (and therefore this
    // pass's output bytes) different across separate runs of the same seed and input.
    private static byte KeyFor(long seed, string tag) =>
        System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes($"bclkey:{seed}:{tag}"))[0];

    /// <summary>
    /// Injects a tiny private host type holding:
    ///   - a one-string XOR blob (just "TryParse", same FieldRVA + InitializeArray
    ///     pattern as StringPass) and its decoder;
    ///   - HiddenTryParse(string, NumberStyles, IFormatProvider, out int) : bool, which
    ///     resolves System.Int32 via ldtoken/GetTypeFromHandle (the *type* isn't hidden,
    ///     only the method name is -- knowing "something touches Int32" is far less
    ///     revealing than knowing "it calls TryParse with these flags") and invokes the
    ///     decoded method name through Type.InvokeMember, which also deals with the
    ///     `out int` parameter by writing the result back into the boxed args[3] slot.
    /// Call sites are never touched beyond retargeting the call instruction's Operand to
    /// this method -- the parameter list is pixel-identical to Int32.TryParse's, so the
    /// existing arg-pushing IL already satisfies it.
    /// </summary>
    private static MethodDefinition InjectHiddenTryParse(ModuleDefinition module, long seed)
    {
        var ts = module.TypeSystem;
        var hostName = NameGenerator.Generate(seed, "__bcl_host__", "T");
        var hostType = new TypeDefinition("", hostName,
            TypeAttributes.NotPublic | TypeAttributes.Abstract | TypeAttributes.Sealed, ts.Object);
        module.Types.Add(hostType);

        var methodNameBytes = System.Text.Encoding.ASCII.GetBytes("TryParse");
        var key = KeyFor(seed, "TryParse");
        var blob = methodNameBytes.Select(b => (byte)(b ^ key)).ToArray();

        var (decodeMethod, _) = InjectBlobAndDecoder(module, hostType, seed, blob);

        var numberStylesRef = BuildTypeRef(module, "System.Globalization", "NumberStyles", isValueType: true);
        var formatProviderRef = BuildTypeRef(module, "System", "IFormatProvider", isValueType: false);
        var typeRef = BuildTypeRef(module, "System", "Type", isValueType: false);
        var runtimeTypeHandleRef = BuildTypeRef(module, "System", "RuntimeTypeHandle", isValueType: true);
        var bindingFlagsRef = BuildTypeRef(module, "System.Reflection", "BindingFlags", isValueType: true);
        var binderRef = BuildTypeRef(module, "System.Reflection", "Binder", isValueType: false);
        var int32Ref = BuildTypeRef(module, "System", "Int32", isValueType: true);

        var method = new MethodDefinition(
            NameGenerator.Generate(seed, "__hidden_tryparse__", "m_"),
            MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig,
            ts.Boolean);
        method.Parameters.Add(new ParameterDefinition("s", ParameterAttributes.None, ts.String));
        method.Parameters.Add(new ParameterDefinition("style", ParameterAttributes.None, numberStylesRef));
        method.Parameters.Add(new ParameterDefinition("provider", ParameterAttributes.None, formatProviderRef));
        method.Parameters.Add(new ParameterDefinition("result", ParameterAttributes.Out, new ByReferenceType(ts.Int32)));
        hostType.Methods.Add(method);

        var invokeMember = new MethodReference("InvokeMember", ts.Object, typeRef) { HasThis = true };
        invokeMember.Parameters.Add(new ParameterDefinition(ts.String));
        invokeMember.Parameters.Add(new ParameterDefinition(bindingFlagsRef));
        invokeMember.Parameters.Add(new ParameterDefinition(binderRef));
        invokeMember.Parameters.Add(new ParameterDefinition(ts.Object));
        invokeMember.Parameters.Add(new ParameterDefinition(new ArrayType(ts.Object)));

        var getTypeFromHandle = new MethodReference("GetTypeFromHandle", typeRef, typeRef) { HasThis = false };
        getTypeFromHandle.Parameters.Add(new ParameterDefinition(runtimeTypeHandleRef));

        var body = method.Body;
        body.InitLocals = true;
        var argsLocal = new VariableDefinition(new ArrayType(ts.Object));
        var typeLocal = new VariableDefinition(typeRef);
        var retLocal = new VariableDefinition(ts.Object);
        body.Variables.Add(argsLocal);
        body.Variables.Add(typeLocal);
        body.Variables.Add(retLocal);

        var il = body.GetILProcessor();

        // args = new object[4]
        il.Append(Instruction.Create(OpCodes.Ldc_I4_4));
        il.Append(Instruction.Create(OpCodes.Newarr, ts.Object));
        il.Append(Instruction.Create(OpCodes.Stloc, argsLocal));

        // args[0] = s
        il.Append(Instruction.Create(OpCodes.Ldloc, argsLocal));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_0));
        il.Append(Instruction.Create(OpCodes.Ldarg_0));
        il.Append(Instruction.Create(OpCodes.Stelem_Ref));

        // args[1] = box(style)
        il.Append(Instruction.Create(OpCodes.Ldloc, argsLocal));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_1));
        il.Append(Instruction.Create(OpCodes.Ldarg_1));
        il.Append(Instruction.Create(OpCodes.Box, numberStylesRef));
        il.Append(Instruction.Create(OpCodes.Stelem_Ref));

        // args[2] = provider (reference type already -- no boxing)
        il.Append(Instruction.Create(OpCodes.Ldloc, argsLocal));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_2));
        il.Append(Instruction.Create(OpCodes.Ldarg_2));
        il.Append(Instruction.Create(OpCodes.Stelem_Ref));

        // args[3] = box(0)  -- placeholder slot InvokeMember will overwrite for the out param
        il.Append(Instruction.Create(OpCodes.Ldloc, argsLocal));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_3));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_0));
        il.Append(Instruction.Create(OpCodes.Box, ts.Int32));
        il.Append(Instruction.Create(OpCodes.Stelem_Ref));

        // typeLocal = Type.GetTypeFromHandle(typeof(int).TypeHandle)
        il.Append(Instruction.Create(OpCodes.Ldtoken, int32Ref));
        il.Append(Instruction.Create(OpCodes.Call, getTypeFromHandle));
        il.Append(Instruction.Create(OpCodes.Stloc, typeLocal));

        // retLocal = typeLocal.InvokeMember(Decode(...), Public|Static|InvokeMethod, null, null, argsLocal)
        il.Append(Instruction.Create(OpCodes.Ldloc, typeLocal));
        il.Append(Instruction.Create(OpCodes.Ldc_I4, 0));
        il.Append(Instruction.Create(OpCodes.Ldc_I4, methodNameBytes.Length));
        il.Append(Instruction.Create(OpCodes.Ldc_I4, (int)key));
        il.Append(Instruction.Create(OpCodes.Call, decodeMethod));
        il.Append(Instruction.Create(OpCodes.Ldc_I4, BindingFlagsPublicStaticInvokeMethod));
        il.Append(Instruction.Create(OpCodes.Ldnull));
        il.Append(Instruction.Create(OpCodes.Ldnull));
        il.Append(Instruction.Create(OpCodes.Ldloc, argsLocal));
        il.Append(Instruction.Create(OpCodes.Callvirt, invokeMember));
        il.Append(Instruction.Create(OpCodes.Stloc, retLocal));

        // *result = (int)args[3]
        il.Append(Instruction.Create(OpCodes.Ldarg_3));
        il.Append(Instruction.Create(OpCodes.Ldloc, argsLocal));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_3));
        il.Append(Instruction.Create(OpCodes.Ldelem_Ref));
        il.Append(Instruction.Create(OpCodes.Unbox_Any, ts.Int32));
        il.Append(Instruction.Create(OpCodes.Stind_I4));

        // return (bool)retLocal
        il.Append(Instruction.Create(OpCodes.Ldloc, retLocal));
        il.Append(Instruction.Create(OpCodes.Unbox_Any, ts.Boolean));
        il.Append(Instruction.Create(OpCodes.Ret));

        return method;
    }

    /// <summary>
    /// Same FieldRVA + RuntimeHelpers.InitializeArray + XOR decoder pattern as
    /// StringPass.InjectDecoder, trimmed to this pass's single-string need and nested
    /// under the caller's own host type instead of creating a second top-level type.
    /// </summary>
    private static (MethodDefinition Decode, FieldDefinition DataField) InjectBlobAndDecoder(
        ModuleDefinition module, TypeDefinition hostType, long seed, byte[] blob)
    {
        var ts = module.TypeSystem;
        var valueTypeBaseRef = BuildTypeRef(module, "System", "ValueType", isValueType: false);
        var blobType = new TypeDefinition("", NameGenerator.Generate(seed, "__bcl_blob_type__", "T"),
            TypeAttributes.NestedPrivate | TypeAttributes.Sealed | TypeAttributes.ExplicitLayout
            | TypeAttributes.AnsiClass, valueTypeBaseRef)
        {
            ClassSize = blob.Length,
            PackingSize = 1,
        };
        hostType.NestedTypes.Add(blobType);

        var rvaField = new FieldDefinition(NameGenerator.Generate(seed, "__bcl_rva__", "f_"),
            FieldAttributes.Static | FieldAttributes.Assembly | FieldAttributes.HasFieldRVA, blobType)
        {
            InitialValue = blob,
        };
        hostType.Fields.Add(rvaField);

        var dataField = new FieldDefinition(NameGenerator.Generate(seed, "__bcl_data__", "f_"),
            FieldAttributes.Static | FieldAttributes.Assembly, new ArrayType(ts.Byte));
        hostType.Fields.Add(dataField);

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

        var decodeName = NameGenerator.Generate(seed, "__bcl_decode__", "m_");
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

        il.Append(Instruction.Create(OpCodes.Ldarg_1));
        il.Append(Instruction.Create(OpCodes.Newarr, ts.Char));
        il.Append(Instruction.Create(OpCodes.Stloc, chars));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_0));
        il.Append(Instruction.Create(OpCodes.Stloc, i));
        il.Append(Instruction.Create(OpCodes.Br, loopStart));

        il.Append(loopBody);
        il.Append(Instruction.Create(OpCodes.Ldloc, chars));
        il.Append(Instruction.Create(OpCodes.Ldloc, i));
        il.Append(Instruction.Create(OpCodes.Ldsfld, dataField));
        il.Append(Instruction.Create(OpCodes.Ldarg_0));
        il.Append(Instruction.Create(OpCodes.Ldloc, i));
        il.Append(Instruction.Create(OpCodes.Add));
        il.Append(Instruction.Create(OpCodes.Ldelem_U1));
        il.Append(Instruction.Create(OpCodes.Ldarg_2));
        il.Append(Instruction.Create(OpCodes.Xor));
        il.Append(Instruction.Create(OpCodes.Conv_U2));
        il.Append(Instruction.Create(OpCodes.Stelem_I2));
        il.Append(Instruction.Create(OpCodes.Ldloc, i));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_1));
        il.Append(Instruction.Create(OpCodes.Add));
        il.Append(Instruction.Create(OpCodes.Stloc, i));

        il.Append(loopStart);
        il.Append(Instruction.Create(OpCodes.Ldloc, i));
        il.Append(Instruction.Create(OpCodes.Ldarg_1));
        il.Append(Instruction.Create(OpCodes.Blt, loopBody));

        il.Append(buildString);
        il.Append(Instruction.Create(OpCodes.Newobj, stringCtor));
        il.Append(Instruction.Create(OpCodes.Ret));

        return (decode, dataField);
    }
}
