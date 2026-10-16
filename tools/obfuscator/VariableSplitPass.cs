using Mono.Cecil;
using Mono.Cecil.Cil;
using Mono.Cecil.Rocks;

namespace Dysphasia.Obfuscator;

public sealed class VariableSplitPassResult
{
    public int SplitVariables { get; set; }
    public int SkippedAddressTaken { get; set; }
}

/// <summary>
/// Splits each eligible int32/uint32 local into two "shares" that XOR back to the real
/// value -- `v == shareA ^ shareB` -- instead of storing it directly. Every `stloc v`
/// becomes "stash the value, re-derive a fresh mask, store value^mask and mask into the
/// two shares"; every `ldloc v` becomes "load both shares, xor them back together". A
/// data-flow tracer that doesn't actually execute the method (or an analyst skimming
/// locals rather than tracing every xor) no longer sees a single variable carrying a
/// meaningful running value -- just two numbers that separately mean nothing.
///
/// Deliberately runs *before* ControlFlowPass in the pipeline (Protector.cs), so it only
/// ever sees the fixture's own original locals -- never CFF's own dispatcher state
/// variable, which would otherwise balloon every single state transition for no benefit
/// (the state id is already a meaningless shuffled int; splitting it further buys nothing).
///
/// Safety: a local is skipped whenever its address is taken anywhere in the method
/// (`ldloca`/`ldloca.s`) -- e.g. ReadInt's out-parameter target -- since splitting it into
/// two separate locals makes "the address of v" meaningless; there is no single memory
/// location left to point at.
/// </summary>
public static class VariableSplitPass
{
    public static VariableSplitPassResult Apply(ModuleDefinition module, Policy policy, long seed)
    {
        var result = new VariableSplitPassResult();
        var methods = module.Types.SelectMany(FlattenNested).SelectMany(t => t.Methods)
            .Where(m => m.HasBody && m.Body.Instructions.Count > 0)
            .ToList();

        foreach (var method in methods)
        {
            method.Body.SimplifyMacros();
            SplitMethod(method, seed, result);
        }

        return result;
    }

    private static IEnumerable<TypeDefinition> FlattenNested(TypeDefinition type)
    {
        yield return type;
        foreach (var nested in type.NestedTypes)
            foreach (var t in FlattenNested(nested))
                yield return t;
    }

    private static bool IsSplittableType(TypeReference t) =>
        t.FullName is "System.Int32" or "System.UInt32";

    private static void SplitMethod(MethodDefinition method, long seed, VariableSplitPassResult result)
    {
        var body = method.Body;
        var addressTaken = new HashSet<VariableDefinition>();
        foreach (var instr in body.Instructions)
        {
            if ((instr.OpCode == OpCodes.Ldloca || instr.OpCode == OpCodes.Ldloca_S)
                && instr.Operand is VariableDefinition v)
                addressTaken.Add(v);
        }

        var candidates = body.Variables
            .Where(v => IsSplittableType(v.VariableType) && !addressTaken.Contains(v))
            .ToList();
        result.SkippedAddressTaken += body.Variables.Count(v => IsSplittableType(v.VariableType)) - candidates.Count;
        if (candidates.Count == 0) return;

        var il = body.GetILProcessor();
        int ordinal = 0;
        foreach (var original in candidates)
        {
            var shareA = new VariableDefinition(original.VariableType);
            var shareB = new VariableDefinition(original.VariableType);
            var tmp = new VariableDefinition(original.VariableType);
            body.Variables.Add(shareA);
            body.Variables.Add(shareB);
            body.Variables.Add(tmp);

            var stores = body.Instructions
                .Where(i => (i.OpCode == OpCodes.Stloc || i.OpCode == OpCodes.Stloc_S)
                    && ReferenceEquals(i.Operand, original))
                .ToList();
            var loads = body.Instructions
                .Where(i => (i.OpCode == OpCodes.Ldloc || i.OpCode == OpCodes.Ldloc_S)
                    && ReferenceEquals(i.Operand, original))
                .ToList();

            foreach (var instr in stores)
            {
                int mask = DeriveMask(seed, method.FullName, ordinal++);
                var newInstructions = new List<Instruction>
                {
                    Instruction.Create(OpCodes.Stloc, tmp),
                    Instruction.Create(OpCodes.Ldloc, tmp),
                    Instruction.Create(OpCodes.Ldc_I4, mask),
                    Instruction.Create(OpCodes.Xor),
                    Instruction.Create(OpCodes.Stloc, shareA),
                    Instruction.Create(OpCodes.Ldc_I4, mask),
                    Instruction.Create(OpCodes.Stloc, shareB),
                };
                foreach (var ni in newInstructions) il.InsertBefore(instr, ni);
                RedirectReferences(body, instr, newInstructions[0]);
                il.Remove(instr);
            }

            foreach (var instr in loads)
            {
                var newInstructions = new List<Instruction>
                {
                    Instruction.Create(OpCodes.Ldloc, shareA),
                    Instruction.Create(OpCodes.Ldloc, shareB),
                    Instruction.Create(OpCodes.Xor),
                };
                foreach (var ni in newInstructions) il.InsertBefore(instr, ni);
                RedirectReferences(body, instr, newInstructions[0]);
                il.Remove(instr);
            }

            body.Variables.Remove(original);
            result.SplitVariables++;
        }
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

    private static int DeriveMask(long seed, string label, int ordinal)
    {
        var bytes = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes($"varsplit:{seed}:{label}:{ordinal}"));
        return BitConverter.ToInt32(bytes, 0);
    }
}
