using Mono.Cecil;
using Mono.Cecil.Cil;
using Mono.Cecil.Rocks;

namespace Dysphasia.Obfuscator;

public sealed class FunctionOutliningPassResult
{
    public int OutlinedBlocks { get; set; }
}

/// <summary>
/// Extracts terminal (`ret`-ending) basic blocks into standalone static methods, so one
/// coherent function becomes several smaller ones joined by calls -- e.g. ApplyPreset's
/// three preset branches each become their own method instead of three inline array
/// builds, multiplying the number of members/call edges an analyst has to stitch back
/// together without changing what any of them compute.
///
/// Deliberately conservative, mirroring VariableSplitPass's placement and safety style:
///   - runs *before* control-flow/string-encode/variable-splitting, so it only ever sees
///     the fixture's own original blocks -- never CFF's dispatcher, never a split
///     variable's two shares.
///   - only touches blocks that are a single straight run ending in `ret` (never `throw`
///     -- exception control flow is out of scope here) inside a *static* method.
///   - only touches blocks whose every instruction is on an explicit allowlist of
///     side-effect-irrelevant opcodes (arithmetic, array/element ops, calls, locals/args).
///     Anything else in the block (branches, `ldloca`, `starg`, ...) means the block is
///     skipped outright -- fail closed, not best-effort.
///   - skipped unless the block is at least <see cref="MinBlockInstructions"/> long, so a
///     bare `ret`/`ldc.i4 N; ret` isn't "extracted" into a call for no benefit.
/// </summary>
public static class FunctionOutliningPass
{
    private const int MinBlockInstructions = 5;

    private static readonly HashSet<Code> AllowedOpcodes = new()
    {
        Code.Ldarg, Code.Ldarg_S, Code.Ldloc, Code.Ldloc_S, Code.Stloc, Code.Stloc_S,
        Code.Ldc_I4, Code.Ldc_I4_S, Code.Ldc_I4_0, Code.Ldc_I4_1, Code.Ldc_I4_2, Code.Ldc_I4_3,
        Code.Ldc_I4_4, Code.Ldc_I4_5, Code.Ldc_I4_6, Code.Ldc_I4_7, Code.Ldc_I4_8,
        Code.Ldc_I4_M1, Code.Ldc_I8, Code.Ldc_R4, Code.Ldc_R8, Code.Ldstr,
        Code.Call, Code.Newobj, Code.Newarr, Code.Ldlen,
        Code.Ldelem_I4, Code.Ldelem_Ref, Code.Ldelem_U1, Code.Stelem_I4, Code.Stelem_Ref, Code.Stelem_I2, Code.Stelem_I1,
        Code.Add, Code.Sub, Code.Mul, Code.Div, Code.Rem, Code.And, Code.Or, Code.Xor, Code.Not, Code.Neg,
        Code.Conv_I4, Code.Conv_U4, Code.Conv_I8, Code.Conv_U2, Code.Dup, Code.Pop, Code.Ret,
    };

    public static FunctionOutliningPassResult Apply(ModuleDefinition module, Policy policy, long seed)
    {
        var result = new FunctionOutliningPassResult();
        var methods = module.Types.SelectMany(FlattenNested).SelectMany(t => t.Methods)
            .Where(m => m.HasBody && m.IsStatic && m.Body.Instructions.Count > 0)
            .ToList();

        foreach (var method in methods)
        {
            method.Body.SimplifyMacros();
            OutlineMethod(method, method.DeclaringType, seed, result);
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

    private sealed record Dependency(bool IsArg, ParameterDefinition? Param, VariableDefinition? Local, TypeReference Type);

    private static void OutlineMethod(
        MethodDefinition method, TypeDefinition hostType, long seed, FunctionOutliningPassResult result)
    {
        var body = method.Body;
        int ordinal = 0;
        // Re-derive blocks on each outer iteration since outlining one block changes
        // instruction identity for the rest; simplest safe approach is to repeat until a
        // full pass finds nothing left to extract. Capped defensively: every successful
        // extraction should strictly shrink the set of qualifying blocks, so this should
        // never come close to the cap -- hitting it means something is wrong, not slow.
        bool changed = true;
        int safetyIterations = 0;
        while (changed)
        {
            if (++safetyIterations > 200)
                throw new InvalidOperationException(
                    $"{method.FullName}: function-outlining exceeded 200 iterations -- likely stuck, not just slow.");
            changed = false;
            var original = body.Instructions.ToList();
            if (original.Count == 0) break;

            var positionOf = new Dictionary<Instruction, int>();
            for (int i = 0; i < original.Count; i++) positionOf[original[i]] = i;

            var starts = new SortedSet<int> { 0 };
            for (int i = 0; i < original.Count; i++)
            {
                var instr = original[i];
                switch (instr.Operand)
                {
                    case Instruction target: starts.Add(positionOf[target]); break;
                    case Instruction[] targets: foreach (var t in targets) starts.Add(positionOf[t]); break;
                }
                var flow = instr.OpCode.FlowControl;
                if ((flow is FlowControl.Branch or FlowControl.Cond_Branch or FlowControl.Return or FlowControl.Throw)
                    && i + 1 < original.Count)
                    starts.Add(i + 1);
            }
            var startList = starts.ToList();

            for (int bi = 0; bi < startList.Count; bi++)
            {
                int s = startList[bi];
                int e = bi + 1 < startList.Count ? startList[bi + 1] : original.Count;
                if (e - s < MinBlockInstructions) continue;
                var last = original[e - 1];
                if (last.OpCode != OpCodes.Ret) continue; // only terminal ret-ending blocks

                var slice = original.GetRange(s, e - s);
                if (!slice.All(i => AllowedOpcodes.Contains(i.OpCode.Code))) continue;

                var deps = ComputeExternalDependencies(slice);
                if (deps is null) continue; // encountered something we couldn't safely map

                // The replacement is `deps.Count` loads + call + ret. Require the block
                // being replaced to be strictly bigger than that, or a block with enough
                // distinct dependencies (deps.Count + 2 >= MinBlockInstructions) would
                // regenerate an equally "qualifying" wrapper-of-a-wrapper every pass,
                // looping forever instead of shrinking (caught empirically: AdjustChannel
                // has 3 params, so its first extraction's own replacement -- 3 loads + call
                // + ret = 5 instructions -- met the flat MinBlockInstructions threshold and
                // kept re-extracting itself).
                if (e - s <= deps.Count + 2) continue;

                ExtractBlock(method, hostType, original, s, e, deps, seed, ordinal++);
                result.OutlinedBlocks++;
                changed = true;
                break; // instruction list is now stale; recompute blocks from scratch
            }
        }
    }

    /// <summary>
    /// Walks the slice tracking which locals the block itself defines (via `stloc`)
    /// before they're read -- those are block-local scratch, not dependencies. Any
    /// `ldarg`/`ldloc` read before the corresponding local is ever defined within the
    /// slice becomes an ordered, deduplicated external dependency (a parameter of the
    /// new method). Returns null if the slice contains anything else.
    /// </summary>
    private static List<Dependency>? ComputeExternalDependencies(List<Instruction> slice)
    {
        var definedLocally = new HashSet<VariableDefinition>();
        var seen = new HashSet<object>();
        var deps = new List<Dependency>();

        foreach (var instr in slice)
        {
            switch (instr.OpCode.Code)
            {
                case Code.Ldarg or Code.Ldarg_S:
                    if (instr.Operand is not ParameterDefinition p) return null;
                    if (seen.Add(p)) deps.Add(new Dependency(true, p, null, p.ParameterType));
                    break;
                case Code.Ldloc or Code.Ldloc_S:
                    if (instr.Operand is not VariableDefinition vRead) return null;
                    if (!definedLocally.Contains(vRead) && seen.Add(vRead))
                        deps.Add(new Dependency(false, null, vRead, vRead.VariableType));
                    break;
                case Code.Stloc or Code.Stloc_S:
                    if (instr.Operand is not VariableDefinition vWrite) return null;
                    definedLocally.Add(vWrite);
                    break;
            }
        }
        return deps;
    }

    private static void ExtractBlock(
        MethodDefinition sourceMethod, TypeDefinition hostType, List<Instruction> original,
        int s, int e, List<Dependency> deps, long seed, int ordinal)
    {
        var ts = sourceMethod.Module.TypeSystem;
        var newMethod = new MethodDefinition(
            NameGenerator.Generate(seed, $"__outline__{sourceMethod.FullName}__{ordinal}", "m_"),
            MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig,
            sourceMethod.ReturnType);
        foreach (var dep in deps)
            newMethod.Parameters.Add(new ParameterDefinition(dep.Type));
        hostType.Methods.Add(newMethod);
        // Cecil defaults a freshly-created MethodBody to InitLocals=false; every
        // compiler-emitted method with locals actually sets this (.locals init), and
        // ILVerify flags its absence as a hard verifiability error.
        newMethod.Body.InitLocals = true;

        // Locals the slice defines for its own scratch use (e.g. the array it builds and
        // returns) still need to exist in the new method's own body.
        var localRemap = new Dictionary<VariableDefinition, VariableDefinition>();
        foreach (var instr in original.GetRange(s, e - s))
        {
            if (instr.Operand is VariableDefinition v && !localRemap.ContainsKey(v)
                && !deps.Any(d => !d.IsArg && d.Local == v))
            {
                var clone = new VariableDefinition(v.VariableType);
                newMethod.Body.Variables.Add(clone);
                localRemap[v] = clone;
            }
        }
        // Dependency locals become parameters in the new method; map them to the
        // matching parameter's position so ldloc inside the copy becomes ldarg instead.
        var depParamIndex = new Dictionary<object, int>();
        for (int i = 0; i < deps.Count; i++)
            depParamIndex[(deps[i].IsArg ? (object)deps[i].Param! : deps[i].Local!)] = i;

        var newIl = newMethod.Body.GetILProcessor();
        foreach (var instr in original.GetRange(s, e - s))
        {
            Instruction copy;
            switch (instr.OpCode.Code)
            {
                case Code.Ldarg or Code.Ldarg_S when instr.Operand is ParameterDefinition pArg:
                    copy = Instruction.Create(OpCodes.Ldarg, newMethod.Parameters[depParamIndex[pArg]]);
                    break;
                case Code.Ldloc or Code.Ldloc_S when instr.Operand is VariableDefinition vLoad:
                    copy = depParamIndex.TryGetValue(vLoad, out var pIdx)
                        ? Instruction.Create(OpCodes.Ldarg, newMethod.Parameters[pIdx])
                        : Instruction.Create(OpCodes.Ldloc, localRemap[vLoad]);
                    break;
                case Code.Stloc or Code.Stloc_S when instr.Operand is VariableDefinition vStore:
                    copy = Instruction.Create(OpCodes.Stloc, localRemap[vStore]);
                    break;
                default:
                    copy = CloneSimple(instr);
                    break;
            }
            newIl.Append(copy);
        }

        // Replace the original block with: push each dependency, call the new method, ret.
        var il = sourceMethod.Body.GetILProcessor();
        var oldFirst = original[s];
        var replacement = new List<Instruction>();
        foreach (var dep in deps)
            replacement.Add(dep.IsArg
                ? Instruction.Create(OpCodes.Ldarg, dep.Param!)
                : Instruction.Create(OpCodes.Ldloc, dep.Local!));
        replacement.Add(Instruction.Create(OpCodes.Call, newMethod));
        replacement.Add(Instruction.Create(OpCodes.Ret));

        foreach (var ni in replacement) il.InsertBefore(oldFirst, ni);
        RedirectReferences(sourceMethod.Body, oldFirst, replacement[0]);
        for (int k = s; k < e; k++) il.Remove(original[k]);
    }

    /// <summary>Clones an instruction whose opcode/operand needs no remapping (constants,
    /// calls, array ops, arithmetic, ret, ...).</summary>
    private static Instruction CloneSimple(Instruction instr) => instr.Operand switch
    {
        null => Instruction.Create(instr.OpCode),
        sbyte sb => Instruction.Create(instr.OpCode, sb),
        byte b => Instruction.Create(instr.OpCode, b),
        int i => Instruction.Create(instr.OpCode, i),
        long l => Instruction.Create(instr.OpCode, l),
        float f => Instruction.Create(instr.OpCode, f),
        double d => Instruction.Create(instr.OpCode, d),
        string s => Instruction.Create(instr.OpCode, s),
        TypeReference t => Instruction.Create(instr.OpCode, t),
        MethodReference m => Instruction.Create(instr.OpCode, m),
        FieldReference fr => Instruction.Create(instr.OpCode, fr),
        _ => throw new InvalidOperationException($"unexpected operand type {instr.Operand.GetType()} for {instr.OpCode}"),
    };

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
}
