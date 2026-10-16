using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Dysphasia.Obfuscator;

public sealed class AntiDebuggingPassResult
{
    public bool Injected { get; set; }
}

/// <summary>
/// Prepends a `System.Diagnostics.Debugger.IsAttached` check to Main, terminating via
/// `Environment.FailFast` before any real work runs if a debugger is already attached.
/// Same injection shape as IntegrityCheckPass (check; branch past a FailFast on failure)
/// -- deliberately reused rather than invented fresh, since that shape is already
/// verified safe to splice into Main ahead of whatever its current first instruction is.
///
/// Why this doesn't collide with this project's own verification pipeline: Verifier.cs
/// launches the protected exe via a plain `Process.Start`, never under a debugger, so
/// `IsAttached` is false for every one of the 335 corpus cases -- this check has zero
/// interaction with how this project measures correctness. It would, however, interrupt
/// someone attaching IDA/dnSpy/a managed debugger to step through the protected build
/// directly (a real technique, not a reason to avoid it: the goal is exactly to cost an
/// analyst more time, see obfuscator-plan.draft.md's "time-fight" framing).
/// </summary>
public static class AntiDebuggingPass
{
    public static AntiDebuggingPassResult Apply(ModuleDefinition module, Policy policy, long seed)
    {
        var result = new AntiDebuggingPassResult();
        var entryMethod = module.EntryPoint;
        if (entryMethod?.Body is null || entryMethod.Body.Instructions.Count == 0) return result;

        var ts = module.TypeSystem;
        var debuggerType = BuildTypeRef(module, "System.Diagnostics", "Debugger", isValueType: false);
        var isAttached = new MethodReference("get_IsAttached", ts.Boolean, debuggerType) { HasThis = false };

        var failFast = new MethodReference("FailFast", ts.Void,
            BuildTypeRef(module, "System", "Environment", isValueType: false)) { HasThis = false };
        failFast.Parameters.Add(new ParameterDefinition(ts.String));

        var mainBody = entryMethod.Body;
        var il = mainBody.GetILProcessor();
        var originalFirst = mainBody.Instructions[0];

        var prelude = new List<Instruction>
        {
            Instruction.Create(OpCodes.Call, isAttached),
            Instruction.Create(OpCodes.Brfalse, originalFirst), // not attached -> continue normally
            Instruction.Create(OpCodes.Ldstr, "debugger detected"),
            Instruction.Create(OpCodes.Call, failFast),
        };
        foreach (var instr in prelude) il.InsertBefore(originalFirst, instr);

        result.Injected = true;
        return result;
    }

    private static TypeReference BuildTypeRef(ModuleDefinition module, string ns, string name, bool isValueType)
    {
        var scope = module.TypeSystem.Object.Scope;
        return new TypeReference(ns, name, module, scope, isValueType);
    }
}
