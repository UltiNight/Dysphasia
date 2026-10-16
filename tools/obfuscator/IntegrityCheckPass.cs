using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Dysphasia.Obfuscator;

public sealed class IntegrityCheckPassResult
{
    public bool Injected { get; set; }
    public string? TargetMethod { get; set; }
}

/// <summary>
/// Injects a lightweight *behavioral* self-test, not a whole-file hash. A true
/// self-hash (verify the running binary's own bytes match an embedded checksum) needs
/// the checksum field's own bytes excluded from what it covers, patched into the
/// already-written file at its exact PE file offset after the fact -- real, but the
/// riskiest kind of binary surgery this project does (one off-by-one in the RVA-to-
/// file-offset math corrupts the PE). That is deliberately out of scope for this
/// increment; see reports/integrity-check.draft.md for the trade-off this choice makes.
///
/// Instead: call the target method (here, ClampByte) with a handful of known
/// (input, expected-output) pairs *derived from the algorithm's own specification*, not
/// from the build's own bytes -- so there is no chicken-and-egg problem to solve at all.
/// If a patch changes ClampByte's behavior for any of those inputs (including a patch
/// aimed at a completely different protection pass that happens to also touch this
/// shared, heavily-depended-on function), the check fails and the process terminates via
/// `Environment.FailFast` before Main's real body ever runs.
/// </summary>
public static class IntegrityCheckPass
{
    private static readonly (int Input, int Expected)[] TestVectors =
    {
        (-50, 0), (300, 255), (100, 100), (0, 0), (255, 255),
    };

    public static IntegrityCheckPassResult Apply(ModuleDefinition module, Policy policy, long seed)
    {
        var result = new IntegrityCheckPassResult();
        var ts = module.TypeSystem;

        var mainType = module.EntryPoint?.DeclaringType;
        var entryMethod = module.EntryPoint;
        var clampByte = mainType?.Methods.FirstOrDefault(m =>
            m.Parameters.Count == 1 && m.ReturnType.FullName == "System.Int32"
            && m.Parameters[0].ParameterType.FullName == "System.Int32" && !ReferenceEquals(m, entryMethod)
            && m.Body is not null && LooksLikeClamp(m));
        if (entryMethod is null || clampByte is null) return result;

        var selfCheck = new MethodDefinition(
            NameGenerator.Generate(seed, "__integrity_selfcheck__", "m_"),
            MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig, ts.Boolean);
        mainType!.Methods.Add(selfCheck);
        selfCheck.Body.InitLocals = true;

        var il = selfCheck.Body.GetILProcessor();
        var fail = Instruction.Create(OpCodes.Ldc_I4_0);
        foreach (var (input, expected) in TestVectors)
        {
            il.Append(Instruction.Create(OpCodes.Ldc_I4, input));
            il.Append(Instruction.Create(OpCodes.Call, clampByte));
            il.Append(Instruction.Create(OpCodes.Ldc_I4, expected));
            il.Append(Instruction.Create(OpCodes.Bne_Un, fail));
        }
        il.Append(Instruction.Create(OpCodes.Ldc_I4_1));
        il.Append(Instruction.Create(OpCodes.Ret));
        il.Append(fail);
        il.Append(Instruction.Create(OpCodes.Ret));

        // Prepend to Main: if the self-check fails, terminate before any real work runs.
        var failFast = new MethodReference("FailFast", ts.Void,
            BuildTypeRef(module, "System", "Environment", isValueType: false)) { HasThis = false };
        failFast.Parameters.Add(new ParameterDefinition(ts.String));

        var mainBody = entryMethod.Body;
        var mainIl = mainBody.GetILProcessor();
        var originalFirst = mainBody.Instructions[0];
        var continueLabel = originalFirst;

        var prelude = new List<Instruction>
        {
            Instruction.Create(OpCodes.Call, selfCheck),
            Instruction.Create(OpCodes.Brtrue, continueLabel),
            Instruction.Create(OpCodes.Ldstr, "integrity check failed"),
            Instruction.Create(OpCodes.Call, failFast),
        };
        foreach (var instr in prelude) mainIl.InsertBefore(originalFirst, instr);

        result.Injected = true;
        result.TargetMethod = clampByte.FullName;
        return result;
    }

    /// <summary>Heuristic: ClampByte's body contains a comparison against 255 --
    /// distinguishes it from the other int-&gt;int helper shapes in this fixture without
    /// hardcoding a name that renaming has already replaced by the time this pass could
    /// run. Deliberately no instruction-count ceiling: this pass runs after control-flow
    /// flattening, whose dispatcher overhead alone pushes even this tiny method well
    /// past any "short method" threshold that looked reasonable pre-flattening.</summary>
    private static bool LooksLikeClamp(MethodDefinition m) =>
        m.Body.Instructions.Any(i => i.OpCode == OpCodes.Ldc_I4 && i.Operand is 255);

    private static TypeReference BuildTypeRef(ModuleDefinition module, string ns, string name, bool isValueType)
    {
        var scope = module.TypeSystem.Object.Scope;
        return new TypeReference(ns, name, module, scope, isValueType);
    }
}
