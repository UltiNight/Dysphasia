using Mono.Cecil;
using Mono.Cecil.Cil;
using Mono.Cecil.Rocks;

namespace Dysphasia.Obfuscator;

public sealed class FunctionInliningPassResult
{
    public int InlinedCallSites { get; set; }
    public string? InlinedMethod { get; set; }

    /// <summary>"DeclaringType::MethodName" for every caller touched -- callers must
    /// never be handed to ControlFlowPass afterward (see the class-level remark on why).</summary>
    public HashSet<string> TouchedCallers { get; } = new();
}

/// <summary>
/// The mirror image of FunctionOutliningPass: instead of pulling a block *out* into its
/// own method, this splices a whole method's body *into* every call site, so the call
/// graph edge disappears entirely -- no `call ClampByte`, just ClampByte's logic sitting
/// inline wherever it used to be invoked from. Scoped to a single, hand-picked target
/// (ClampByte: small, pure, side-effect-free beyond its return value, called from
/// several places) rather than a general "inline anything" pass -- inlining is far more
/// failure-prone to generalize safely than outlining was (multiple `ret` points need a
/// shared merge label, every local needs cloning, every internal branch target needs
/// remapping to the *cloned* instruction, not the original).
///
/// Runs right after function-outlining and before every other structural pass, so it
/// only ever deals with ClampByte's original, simple branch structure -- never a
/// flattened/opaque-predicated/MBA'd copy of it.
///
/// Every touched caller is recorded and must be excluded from ControlFlowPass
/// afterward (Protector.cs adds them to policy.ExcludeMembers before running it).
/// Reason, found empirically: a call site like `arr[i] = ClampByte(x)` has the array
/// reference and index *already sitting on the evaluation stack* when the call happens;
/// that's fine for a real `call` (one atomic instruction, no block boundary). Once
/// inlined, ClampByte's own internal branches become part of the caller's own
/// instruction stream *at that same point* -- and control-flow flattening later treats
/// each of those branches as a block boundary. Flattening's dispatcher carries nothing
/// but its state variable across block boundaries, so the array+index that were
/// "waiting" on the stack across where the branches now live are silently lost, corrupting
/// the stack (caught via ILVerify: "Stack underflow" at the `stelem.i4` that expected
/// them still there). AdjustChannel's own call site (`return ClampByte(x)`, nothing else
/// pending on the stack across it) never hit this, which is why it was the one place in
/// this fixture inlining looked safe before this was found.
/// </summary>
public static class FunctionInliningPass
{
    public static FunctionInliningPassResult Apply(ModuleDefinition module, Policy policy, long seed)
    {
        var result = new FunctionInliningPassResult();
        var allMethods = module.Types.SelectMany(FlattenNested).SelectMany(t => t.Methods)
            .Where(m => m.HasBody && m.Body.Instructions.Count > 0)
            .ToList();

        var target = allMethods.FirstOrDefault(m =>
            m.IsStatic && m.Parameters.Count == 1 && m.ReturnType.FullName == "System.Int32"
            && m.Parameters[0].ParameterType.FullName == "System.Int32"
            && !ReferenceEquals(m, module.EntryPoint)
            && m.Body.Instructions.Any(i => i.OpCode == OpCodes.Ldc_I4 && i.Operand is 255));
        if (target is null) return result;
        result.InlinedMethod = target.FullName;

        // Must normalize the *target*'s own short-form opcodes (ldarg.0, ldloc.1, ...)
        // to their explicit-operand long forms first -- the remapping switch in
        // InlineAt matches Code.Ldarg/Ldloc/Stloc specifically, not the half-dozen
        // Ldarg_0/Ldloc_1/Stloc_S/... macro variants Roslyn actually emits, and an
        // unmatched one would fall through to CloneSimple and get copied *unchanged*,
        // silently keeping a reference to the callee's own parameter/locals instead of
        // the caller's temp (caught empirically: inlined ClampByte read `ldarg.0`
        // straight through instead of the caller's stashed argument, breaking 306 of
        // 335 corpus cases).
        target.Body.SimplifyMacros();

        foreach (var caller in allMethods)
        {
            if (ReferenceEquals(caller, target)) continue; // no self-recursive inlining
            // Splicing a whole method's body in at a call site can push a short-form
            // branch elsewhere in the caller past the signed-byte offset it can encode
            // (same hazard StringPass/MbaPass guard against the same way).
            caller.Body.SimplifyMacros();
            var il = caller.Body.GetILProcessor();
            var callSites = caller.Body.Instructions
                .Where(i => i.OpCode == OpCodes.Call && ReferenceEquals(i.Operand, target))
                .ToList();
            foreach (var call in callSites)
            {
                InlineAt(caller, il, call, target, seed);
                result.InlinedCallSites++;
                result.TouchedCallers.Add($"{caller.DeclaringType.FullName}::{caller.Name}");
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

    private static void InlineAt(
        MethodDefinition caller, ILProcessor il, Instruction call, MethodDefinition target, long seed)
    {
        var body = caller.Body;
        // The single argument is already on the stack from the caller's own code; stash
        // it in a fresh temp so the cloned body can reference it (possibly) more than
        // once via ldarg -> ldloc remapping.
        var argLocal = new VariableDefinition(target.Parameters[0].ParameterType);
        body.Variables.Add(argLocal);
        // Every `ret` path's value is stashed here instead of being left on the
        // evaluation stack across the branch to mergeLabel -- a later control-flow-
        // flattening pass assumes every block boundary has an *empty* stack (only the
        // dispatcher's state variable crosses block boundaries), so a bare `br` carrying
        // a pending value would silently leave it unconsumed once that pass rewrites
        // this branch into a state transition (caught empirically: 306/335 corpus
        // failures once control-flow ran on an inlined+outlined method).
        var resultLocal = new VariableDefinition(target.ReturnType);
        body.Variables.Add(resultLocal);

        var localMap = new Dictionary<VariableDefinition, VariableDefinition>();
        foreach (var v in target.Body.Variables)
        {
            var clone = new VariableDefinition(v.VariableType);
            body.Variables.Add(clone);
            localMap[v] = clone;
        }

        var mergeLabel = Instruction.Create(OpCodes.Ldloc, resultLocal);

        // First pass: clone every instruction with its "simple" operand (if any),
        // remapping ldarg (the single parameter) to the temp local and each `ret` to
        // "stash the value, branch to the shared merge point" instead of a bare branch.
        var instrMap = new Dictionary<Instruction, Instruction>();
        var cloned = new List<Instruction>();
        foreach (var instr in target.Body.Instructions)
        {
            if (instr.OpCode.Code == Code.Ret)
            {
                var store = Instruction.Create(OpCodes.Stloc, resultLocal);
                instrMap[instr] = store;
                cloned.Add(store);
                cloned.Add(Instruction.Create(OpCodes.Br, mergeLabel));
                continue;
            }
            Instruction copy = instr.OpCode.Code switch
            {
                Code.Ldarg or Code.Ldarg_S => Instruction.Create(OpCodes.Ldloc, argLocal),
                Code.Ldloc or Code.Ldloc_S => Instruction.Create(OpCodes.Ldloc, localMap[(VariableDefinition)instr.Operand!]),
                Code.Stloc or Code.Stloc_S => Instruction.Create(OpCodes.Stloc, localMap[(VariableDefinition)instr.Operand!]),
                _ => CloneSimple(instr),
            };
            instrMap[instr] = copy;
            cloned.Add(copy);
        }
        // Second pass: fix up any branch operand that pointed at an instruction *within
        // the callee's own body* (its internal if/else structure) to point at the
        // corresponding cloned instruction instead of the original. Looked up through
        // instrMap, not by parallel index -- a `ret` now expands to two instructions, so
        // the clone list is no longer the same length/order as the original.
        foreach (var original in target.Body.Instructions)
        {
            if (original.Operand is Instruction oldTarget && instrMap.TryGetValue(oldTarget, out var newTarget)
                && instrMap.TryGetValue(original, out var copyOfOriginal))
                copyOfOriginal.Operand = newTarget;
        }

        var argStore = Instruction.Create(OpCodes.Stloc, argLocal);
        il.InsertBefore(call, argStore);
        foreach (var c in cloned) il.InsertBefore(call, c);
        il.InsertBefore(call, mergeLabel);

        // argStore is unambiguously the first instruction of the whole inlined sequence
        // (captured directly, not re-derived by scanning -- the cloned body can contain
        // its own stloc instructions, which a "find the nearest stloc" search would have
        // matched instead).
        RedirectReferences(body, call, argStore);
        il.Remove(call);
    }

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
        // Branch target: same opcode, placeholder operand (itself) -- overwritten by the
        // second fix-up pass in InlineAt once every original->clone mapping is known.
        Instruction => Instruction.Create(instr.OpCode, instr),
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
