using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Dysphasia.Obfuscator;

public sealed class ExceptionRoutingPassResult
{
    public bool Rewired { get; set; }
    public int ChecksReplaced { get; set; }
}

/// <summary>
/// The managed-code mirror of the native track's exception-based routing
/// (reports/native-exception-routing.draft.md): replaces a chain of
/// `ldloc; ldstr; call op_Inequality; brfalse` checks (Main's preset validation --
/// "preset != neutral &amp;&amp; preset != mono &amp;&amp; preset != warm") with the *same*
/// outcome reached by deliberately dividing by zero inside a try/catch instead of
/// branching on a boolean directly. Same memory-safety choice as the native version:
/// `DivideByZeroException` is a well-defined managed exception with no unsafe memory
/// access behind it, never something like a null-reference trick.
///
/// Targets Main specifically by searching for the exact literal "unknown preset" (the
/// argument to the `ArgumentException` the original chain throws on failure) and
/// walking backward through the chain of checks that lead into it -- not a general
/// "find any if/else and convert it" pass, the same one-off, hand-targeted scope every
/// other pass in this project uses for a specific, well-understood check.
///
/// The new try/catch nests entirely inside Main's own pre-existing outer try/catch
/// (which already wraps this whole region to turn ArgumentException into the
/// "ERROR: {message}" / exit 2 behavior) -- ordinary, fully-supported nested exception
/// regions, not a new invariant this project hasn't relied on before.
/// </summary>
public static class ExceptionRoutingPass
{
    public static ExceptionRoutingPassResult Apply(ModuleDefinition module, Policy policy, long seed)
    {
        var result = new ExceptionRoutingPassResult();
        var entry = module.EntryPoint;
        if (entry?.Body is null) return result;

        var instructions = entry.Body.Instructions;
        var marker = instructions.FirstOrDefault(i => i.OpCode == OpCodes.Ldstr && (string)i.Operand == "unknown preset");
        if (marker is null) return result;
        int markerIndex = instructions.IndexOf(marker);

        // Walk backward collecting consecutive 4-instruction groups:
        // ldloc(.s) V; ldstr "..."; call op_Inequality; brfalse(.s) -> commonTarget
        var groups = new List<(Instruction LdlocV, Instruction LdstrLit, Instruction CallIneq, Instruction Brfalse)>();
        VariableDefinition? sharedVar = null;
        Instruction? commonTarget = null;
        int cursor = markerIndex;

        while (cursor >= 4)
        {
            var brfalse = instructions[cursor - 1];
            var callIneq = instructions[cursor - 2];
            var ldstrLit = instructions[cursor - 3];
            var ldlocV = instructions[cursor - 4];

            bool isBrfalse = brfalse.OpCode == OpCodes.Brfalse || brfalse.OpCode == OpCodes.Brfalse_S;
            bool isCall = callIneq.OpCode == OpCodes.Call && callIneq.Operand is MethodReference mr
                && mr.Name == "op_Inequality";
            bool isLdstr = ldstrLit.OpCode == OpCodes.Ldstr;
            bool isLdlocV = (ldlocV.OpCode == OpCodes.Ldloc || ldlocV.OpCode == OpCodes.Ldloc_S)
                && ldlocV.Operand is VariableDefinition;

            if (!isBrfalse || !isCall || !isLdstr || !isLdlocV) break;
            if (commonTarget is null) commonTarget = (Instruction)brfalse.Operand;
            else if (!ReferenceEquals(commonTarget, brfalse.Operand)) break;

            var v = (VariableDefinition)ldlocV.Operand;
            if (sharedVar is null) sharedVar = v;
            else if (!ReferenceEquals(sharedVar, v)) break;

            groups.Insert(0, (ldlocV, ldstrLit, callIneq, brfalse));
            cursor -= 4;
        }

        if (groups.Count == 0 || sharedVar is null || commonTarget is null) return result;

        var ts = module.TypeSystem;
        var body = entry.Body;
        var il = body.GetILProcessor();
        var denomVar = new VariableDefinition(ts.Int32);
        body.Variables.Add(denomVar);

        var opEquality = new MethodReference("op_Equality", ts.Boolean, ts.String) { HasThis = false };
        opEquality.Parameters.Add(new ParameterDefinition(ts.String));
        opEquality.Parameters.Add(new ParameterDefinition(ts.String));

        var newInstructions = new List<Instruction>();
        for (int g = 0; g < groups.Count; g++)
        {
            var (_, ldstrLit, _, _) = groups[g];
            newInstructions.Add(Instruction.Create(OpCodes.Ldloc, sharedVar));
            newInstructions.Add(Instruction.Create(OpCodes.Ldstr, (string)ldstrLit.Operand));
            newInstructions.Add(Instruction.Create(OpCodes.Call, opEquality));
            if (g > 0) newInstructions.Add(Instruction.Create(OpCodes.Or));
        }
        newInstructions.Add(Instruction.Create(OpCodes.Stloc, denomVar));

        var tryStart = Instruction.Create(OpCodes.Ldc_I4, 100);
        newInstructions.Add(tryStart);
        newInstructions.Add(Instruction.Create(OpCodes.Ldloc, denomVar));
        newInstructions.Add(Instruction.Create(OpCodes.Div));
        newInstructions.Add(Instruction.Create(OpCodes.Pop));
        var afterTry = Instruction.Create(OpCodes.Br, commonTarget);
        newInstructions.Add(Instruction.Create(OpCodes.Leave, afterTry));

        var handlerStart = Instruction.Create(OpCodes.Pop); // discard the DivideByZeroException instance
        newInstructions.Add(handlerStart);
        newInstructions.Add(Instruction.Create(OpCodes.Leave, marker)); // -> original "throw unknown preset" block
        var handlerEnd = afterTry; // exclusive end: first instruction after the handler

        newInstructions.Add(afterTry);

        var firstOld = groups[0].LdlocV;
        var lastOld = groups[^1].Brfalse;
        int firstIdx = instructions.IndexOf(firstOld);
        int lastIdx = instructions.IndexOf(lastOld);
        // Captured as objects, not indices: InsertBefore below shifts every index from
        // firstIdx onward, so removing "by index" afterward (even descending) deletes
        // the wrong slice -- the tail of what was just inserted, not the old chain
        // (caught empirically: the old comparison chain survived untouched while half
        // of the new OR-chain got deleted instead, producing a build that always fell
        // through to the "invalid" path regardless of the actual preset).
        var toRemove = instructions.Skip(firstIdx).Take(lastIdx - firstIdx + 1).ToList();

        foreach (var instr in newInstructions) il.InsertBefore(firstOld, instr);
        RedirectReferences(body, firstOld, newInstructions[0]);
        foreach (var instr in toRemove) il.Remove(instr);

        // ECMA-335 II.25.4.6 requires nested exception handler entries to be listed
        // innermost-first. This new handler nests entirely inside Main's own
        // pre-existing outer try/catch, which is already in body.ExceptionHandlers --
        // Insert(0, ...) rather than Add() so it precedes that outer entry (caught via
        // InvalidProgramException at runtime despite ILVerify reporting this module as
        // fully verifiable; ILVerify doesn't check EH table ordering the same way the
        // real CLR loader does).
        body.ExceptionHandlers.Insert(0, new ExceptionHandler(ExceptionHandlerType.Catch)
        {
            TryStart = tryStart,
            TryEnd = handlerStart,
            HandlerStart = handlerStart,
            HandlerEnd = handlerEnd,
            CatchType = BuildTypeRef(module, "System", "DivideByZeroException", isValueType: false),
        });

        result.Rewired = true;
        result.ChecksReplaced = groups.Count;
        return result;
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
        var scope = module.TypeSystem.Object.Scope;
        return new TypeReference(ns, name, module, scope, isValueType);
    }
}
