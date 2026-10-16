using Mono.Cecil;
using Mono.Cecil.Cil;
using Mono.Cecil.Rocks;

namespace Dysphasia.Obfuscator;

public sealed class MbaPassResult
{
    public int ReplacedConstants { get; set; }
    public int SkippedSmallConstants { get; set; }
}

/// <summary>
/// Replaces "interesting" `ldc.i4 V` loads with an equivalent Mixed Boolean-Arithmetic
/// expression: `a + b == (a ^ b) + 2 * (a &amp; b)` holds for *any* two int32 values under
/// ordinary two's-complement wraparound (it's the standard full-adder identity: xor gives
/// the sum without carry, `2*(a&amp;b)` gives the carry), so for seeded `a` and
/// `b = unchecked(V - a)` the sequence below always leaves exactly V on the stack --
/// nothing downstream needs to change, the same "operand swap, stack contract untouched"
/// principle as BclCallHidingPass and ControlFlowPass's opaque predicates.
///
/// Target: constants that *identify an algorithm* on sight. `16777619` and `-2128831035`
/// in Fingerprint are the FNV-1a prime and offset basis -- recognizing either one tells an
/// analyst "this is FNV-1a" before they've read a single renamed identifier or traced a
/// single branch. Small constants (array indices, loop bounds like 0/1/2/3) are skipped: a
/// human or REA reading `(a^b)+2*(a&amp;b)` for the literal `1` gains nothing by hiding it
/// and it would bloat every array index/loop increment in the module for no payoff.
/// </summary>
public static class MbaPass
{
    private const int MagnitudeThreshold = 20;

    public static MbaPassResult Apply(ModuleDefinition module, Policy policy, long seed)
    {
        var result = new MbaPassResult();
        var methods = module.Types.SelectMany(FlattenNested).SelectMany(t => t.Methods)
            .Where(m => m.HasBody && m.Body.Instructions.Count > 0)
            .ToList();

        foreach (var method in methods)
        {
            method.Body.SimplifyMacros(); // normalize ldc.i4.0/.s/etc and short branches to long form first
            var il = method.Body.GetILProcessor();
            var targets = method.Body.Instructions
                .Where(i => i.OpCode == OpCodes.Ldc_I4 && Math.Abs((int)i.Operand) > MagnitudeThreshold)
                .ToList();

            int ordinal = 0;
            foreach (var instr in targets)
            {
                ReplaceWithMba(il, instr, seed, method.FullName, ordinal++);
                result.ReplacedConstants++;
            }
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

    private static void ReplaceWithMba(ILProcessor il, Instruction ldcInstr, long seed, string label, int ordinal)
    {
        int value = (int)ldcInstr.Operand;
        int a = DeriveA(seed, label, ordinal);
        int b = unchecked(value - a); // a + b == value regardless of wraparound

        var newInstructions = new List<Instruction>
        {
            Instruction.Create(OpCodes.Ldc_I4, a),
            Instruction.Create(OpCodes.Ldc_I4, b),
            Instruction.Create(OpCodes.Xor),
            Instruction.Create(OpCodes.Ldc_I4, a),
            Instruction.Create(OpCodes.Ldc_I4, b),
            Instruction.Create(OpCodes.And),
            Instruction.Create(OpCodes.Ldc_I4_2),
            Instruction.Create(OpCodes.Mul),
            Instruction.Create(OpCodes.Add),
        };

        foreach (var instr in newInstructions) il.InsertBefore(ldcInstr, instr);
        RedirectReferences(il.Body, ldcInstr, newInstructions[0]);
        il.Remove(ldcInstr);
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

    private static int DeriveA(long seed, string label, int ordinal)
    {
        var bytes = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes($"mba-a:{seed}:{label}:{ordinal}"));
        return BitConverter.ToInt32(bytes, 0);
    }
}
