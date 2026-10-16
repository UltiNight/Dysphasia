using System.Security.Cryptography;
using System.Text;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Mono.Cecil.Rocks;

namespace Dysphasia.Obfuscator;

public sealed class ControlFlowPassResult
{
    public int FlattenedMethods { get; set; }
    public int SkippedMethods { get; set; }
    public List<string> SkippedReasons { get; set; } = new();
    public int OpaquePredicatesInjected { get; set; }
}

/// <summary>
/// P3 pass: rewrites a method's basic blocks into a single dispatcher loop
/// (`while(true) switch(state) { case k: ...; state = next; continue; }`), so every
/// inter-block jump becomes the same generic "set state, jump to dispatcher" shape
/// instead of a typed branch (blt/bgt/brfalse/...) whose opcode and operand already told
/// an analyst what the branch meant. State ids are a seeded shuffle of 0..N-1, so the
/// physical/textual block order no longer matches execution order either.
///
/// Deliberately conservative (obfuscator-plan.draft.md P3: never apply it globally): only
/// methods with NO exception handlers are flattened. In this module that
/// means the five leaf computation methods qualify but `Main` (which holds the only
/// try/catch) is automatically left untouched -- the riskiest transform skips the
/// riskiest method by construction, not by a hand-picked exclusion list.
/// </summary>
public static class ControlFlowPass
{
    public static ControlFlowPassResult Apply(ModuleDefinition module, Policy policy, long seed)
    {
        var result = new ControlFlowPassResult();
        var methods = module.Types.SelectMany(FlattenNested).SelectMany(t => t.Methods).ToList();

        // "opaque-predicates": wraps every *unconditional* and *fallthrough* state
        // transition in a tautology (n*n+n is always even, so (state*state+state)%2==0
        // regardless of state's actual runtime value) whose "false" side is harmless
        // dead-but-plausible arithmetic instead of empty space -- see EmitTransition.
        // Scoped to this increment: NOT applied to Conditional exits, which already carry
        // the method's real branch logic; wrapping those too is a reasonable follow-up.
        bool opaquePredicates = policy.Passes.Contains("opaque-predicates");
        // "mhop-predicates" (needs opaque-predicates too, nests inside the same guard):
        // for a seeded-chosen half of the guarded transitions, swap the arithmetic
        // tautology for a cryptographic one -- SHA256(fixed bytes)[0] == <the one byte
        // value it actually hashes to> is just as unconditionally true, but "run the
        // hash and look" is the only way to know that; `n*(n+1)` is checkable by eye in
        // seconds, denying exactly the easy-mental-math shortcut MHOP targets.
        bool mhopPredicates = policy.Passes.Contains("mhop-predicates");

        foreach (var method in methods)
        {
            var qualified = $"{method.DeclaringType.FullName}::{method.Name}";
            if (policy.ExcludeMembers.Contains(qualified))
            {
                result.SkippedMethods++;
                result.SkippedReasons.Add($"{qualified}: listed in policy.excludeMembers");
                continue;
            }
            if (!method.HasBody)
            {
                result.SkippedMethods++;
                continue;
            }
            if (method.Body.HasExceptionHandlers)
            {
                result.SkippedMethods++;
                result.SkippedReasons.Add($"{qualified}: has exception handler(s); flattening across try/catch boundaries is out of scope for this pass");
                continue;
            }
            var injected = FlattenMethod(method, seed, opaquePredicates, mhopPredicates);
            if (injected < 0)
            {
                result.SkippedMethods++;
                result.SkippedReasons.Add($"{qualified}: single basic block; nothing to flatten");
                continue;
            }
            result.FlattenedMethods++;
            result.OpaquePredicatesInjected += injected;
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

    private enum ExitKind { Terminal, Unconditional, Conditional, Fallthrough }

    private sealed record ExitInfo(ExitKind Kind, int Target = -1, int Fallthrough = -1)
    {
        public static ExitInfo Terminal() => new(ExitKind.Terminal);
        public static ExitInfo Unconditional(int target) => new(ExitKind.Unconditional, target);
        public static ExitInfo Conditional(int target, int fallthrough) => new(ExitKind.Conditional, target, fallthrough);
        public static ExitInfo FallsThrough(int next) => new(ExitKind.Fallthrough, Fallthrough: next);
    }

    private static int FlattenMethod(MethodDefinition method, long seed, bool opaquePredicates, bool mhopPredicates)
    {
        method.Body.SimplifyMacros(); // normalize every branch to its long (4-byte offset) form first
        var body = method.Body;
        var original = body.Instructions.ToList(); // snapshot; we rebuild Instructions below
        if (original.Count == 0) return -1;

        // --- 1. basic blocks: split at every branch target and right after every
        // branch/return/throw (control can't fall past those in the original flow). ---
        var positionOf = new Dictionary<Instruction, int>();
        for (int i = 0; i < original.Count; i++) positionOf[original[i]] = i;

        var starts = new SortedSet<int> { 0 };
        for (int i = 0; i < original.Count; i++)
        {
            var instr = original[i];
            switch (instr.Operand)
            {
                case Instruction target:
                    starts.Add(positionOf[target]);
                    break;
                case Instruction[] targets:
                    foreach (var t in targets) starts.Add(positionOf[t]);
                    break;
            }
            var flow = instr.OpCode.FlowControl;
            if ((flow is FlowControl.Branch or FlowControl.Cond_Branch or FlowControl.Return or FlowControl.Throw)
                && i + 1 < original.Count)
                starts.Add(i + 1);
        }
        var startList = starts.ToList();
        var blocks = new List<(int start, int end)>();
        for (int i = 0; i < startList.Count; i++)
        {
            int s = startList[i];
            int e = i + 1 < startList.Count ? startList[i + 1] : original.Count;
            blocks.Add((s, e));
        }
        if (blocks.Count <= 1) return -1; // single basic block: flattening would be a pure no-op

        var blockIndexOfFirstInstr = new Dictionary<Instruction, int>();
        for (int bi = 0; bi < blocks.Count; bi++) blockIndexOfFirstInstr[original[blocks[bi].start]] = bi;

        // --- 2. classify each block's exit using its ORIGINAL last instruction. ---
        var exits = new ExitInfo[blocks.Count];
        for (int bi = 0; bi < blocks.Count; bi++)
        {
            var (s, e) = blocks[bi];
            var last = original[e - 1];
            var flow = last.OpCode.FlowControl;
            exits[bi] = flow switch
            {
                FlowControl.Return or FlowControl.Throw => ExitInfo.Terminal(),
                FlowControl.Branch => ExitInfo.Unconditional(blockIndexOfFirstInstr[(Instruction)last.Operand!]),
                FlowControl.Cond_Branch => ExitInfo.Conditional(
                    blockIndexOfFirstInstr[(Instruction)last.Operand!],
                    bi + 1 < blocks.Count ? bi + 1 : throw new InvalidOperationException(
                        "conditional branch has no fallthrough successor; method body is not well-formed")),
                _ => ExitInfo.FallsThrough(bi + 1 < blocks.Count ? bi + 1 : throw new InvalidOperationException(
                        "block has no terminal instruction and no successor; method body is not well-formed")),
            };
        }

        // --- 3. seeded shuffle: state id assigned to each block, independent of its
        // position in the method so textual/offset order no longer matches execution order. ---
        var ids = ShuffledIds(blocks.Count, seed, method.FullName);

        // --- 4. rebuild the body as: set state; dispatch: load state; switch; (per block: body, then a
        // state-transition tail instead of the original typed branch). ---
        body.Instructions.Clear();
        var il = body.GetILProcessor();
        var stateVar = new VariableDefinition(method.Module.TypeSystem.Int32);
        body.Variables.Add(stateVar);
        // A method with zero original locals (e.g. ClampByte) can have InitLocals still
        // false going in -- harmless with no locals to init, but stateVar is now its
        // first one. Same class of gap as FunctionOutliningPass's newly-created methods.
        body.InitLocals = true;

        var dispatch = Instruction.Create(OpCodes.Nop);
        il.Append(Instruction.Create(OpCodes.Ldc_I4, ids[0]));
        il.Append(Instruction.Create(OpCodes.Stloc, stateVar));
        il.Append(dispatch);
        il.Append(Instruction.Create(OpCodes.Ldloc, stateVar));
        var switchTargets = new Instruction[blocks.Count];
        il.Append(Instruction.Create(OpCodes.Switch, switchTargets));
        il.Append(Instruction.Create(OpCodes.Br, dispatch)); // unreachable: switch covers every valid state

        var firstEmitted = new Instruction?[blocks.Count];
        int opaqueOrdinal = 0;
        int opaqueInjected = 0;
        for (int bi = 0; bi < blocks.Count; bi++)
        {
            var (s, e) = blocks[bi];
            var exit = exits[bi];
            int copyEnd = exit.Kind == ExitKind.Unconditional ? e - 1 : e; // drop the old `br`; keep ret/throw/cond-branch

            for (int k = s; k < copyEnd; k++)
            {
                il.Append(original[k]);
                firstEmitted[bi] ??= original[k];
            }

            switch (exit.Kind)
            {
                case ExitKind.Terminal:
                    break; // ret/throw already copied as the block's last instruction
                case ExitKind.Unconditional:
                {
                    // NOTE: EmitTransition must be called unconditionally here -- it has
                    // the side effect of appending the actual transition IL. Using
                    // `firstEmitted[bi] ??= EmitTransition(...)` directly would short-
                    // circuit (and skip calling EmitTransition entirely) whenever the
                    // block already copied at least one real instruction above, silently
                    // leaving this block with NO transition tail at all -- it would just
                    // fall through into whatever block happens to sit next in *textual*
                    // order instead of jumping to its real (shuffled-id) target. Call
                    // EmitTransition first, unconditionally, then only use `??=` to decide
                    // what firstEmitted[bi] itself should point to.
                    var transitionFirst = EmitTransition(
                        il, stateVar, dispatch, ids[exit.Target], opaquePredicates, mhopPredicates, seed, method.FullName, opaqueOrdinal++);
                    firstEmitted[bi] ??= transitionFirst;
                    if (opaquePredicates) opaqueInjected++;
                    break;
                }
                case ExitKind.Conditional:
                {
                    // Deliberately unguarded (opaquePredicates: false) -- these transitions
                    // sit right after the method's own real conditional branch, which
                    // already supplies genuine divergent control flow.
                    var condBranch = original[e - 1]; // already copied above (copyEnd == e for Conditional)
                    EmitTransition(il, stateVar, dispatch, ids[exit.Fallthrough], false, false, seed, method.FullName, 0);
                    var takenFirst = EmitTransition(il, stateVar, dispatch, ids[exit.Target], false, false, seed, method.FullName, 0);
                    condBranch.Operand = takenFirst;
                    break;
                }
                case ExitKind.Fallthrough:
                {
                    // Same hazard as Unconditional above -- call unconditionally first.
                    var transitionFirst = EmitTransition(
                        il, stateVar, dispatch, ids[exit.Fallthrough], opaquePredicates, mhopPredicates, seed, method.FullName, opaqueOrdinal++);
                    firstEmitted[bi] ??= transitionFirst;
                    if (opaquePredicates) opaqueInjected++;
                    break;
                }
            }
        }

        for (int bi = 0; bi < blocks.Count; bi++)
            switchTargets[ids[bi]] = firstEmitted[bi]
                ?? throw new InvalidOperationException($"block {bi} emitted no instructions");

        return opaqueInjected;
    }

    /// <summary>
    /// Unguarded: the plain "set state, jump to dispatch" tail P3 always emitted.
    /// Guarded (opaquePredicates): wraps that same tail behind a tautology --
    /// (state*state + state) % 2 == 0 holds for *every* integer state (n*(n+1) is always
    /// the product of two consecutive integers, hence always even) -- so the "true" exit
    /// is taken unconditionally at runtime, but statically a reader sees a real-looking
    /// conditional branch over a second, distinct-looking arithmetic path, not an
    /// obviously inert one. That second path is a discarded multiply, not empty space,
    /// so even a bug in the predicate's math would still leave the program correct, just
    /// slower -- the "false" side converges on the exact same transition instructions
    /// rather than diverging to different code (bogus-control-flow, made safe-by-construction).
    /// </summary>
    private static Instruction EmitTransition(
        ILProcessor il, VariableDefinition stateVar, Instruction dispatch, int targetStateId,
        bool guarded, bool mhop, long seed, string label, int ordinal)
    {
        if (!guarded)
        {
            var first = Instruction.Create(OpCodes.Ldc_I4, targetStateId);
            il.Append(first);
            il.Append(Instruction.Create(OpCodes.Stloc, stateVar));
            il.Append(Instruction.Create(OpCodes.Br, dispatch));
            return first;
        }

        if (mhop && DeriveUseMhop(seed, label, ordinal))
            return EmitMhopGuard(il, stateVar, dispatch, targetStateId, seed, label, ordinal);

        var realLabel = Instruction.Create(OpCodes.Ldc_I4, targetStateId);

        var guardFirst = Instruction.Create(OpCodes.Ldloc, stateVar);
        il.Append(guardFirst);
        il.Append(Instruction.Create(OpCodes.Ldloc, stateVar));
        il.Append(Instruction.Create(OpCodes.Mul));
        il.Append(Instruction.Create(OpCodes.Ldloc, stateVar));
        il.Append(Instruction.Create(OpCodes.Add));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_2));
        il.Append(Instruction.Create(OpCodes.Rem));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_0));
        il.Append(Instruction.Create(OpCodes.Ceq));
        il.Append(Instruction.Create(OpCodes.Brtrue, realLabel));

        var dummyConst = DeriveDummyConst(seed, label, ordinal);
        il.Append(Instruction.Create(OpCodes.Ldloc, stateVar));
        il.Append(Instruction.Create(OpCodes.Ldc_I4, dummyConst));
        il.Append(Instruction.Create(OpCodes.Mul));
        il.Append(Instruction.Create(OpCodes.Pop));

        il.Append(realLabel);
        il.Append(Instruction.Create(OpCodes.Stloc, stateVar));
        il.Append(Instruction.Create(OpCodes.Br, dispatch));
        return guardFirst;
    }

    private static int DeriveDummyConst(long seed, string label, int ordinal)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes($"opaque-const:{seed}:{label}:{ordinal}"));
        return (int)(BitConverter.ToUInt32(bytes, 0) & 0x7FFF) + 1;
    }

    private static bool DeriveUseMhop(long seed, string label, int ordinal)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes($"mhop-choice:{seed}:{label}:{ordinal}"));
        return (bytes[0] & 1) == 1;
    }

    /// <summary>
    /// MHOP guard: `SHA256(fixedInput)[0] == expected` is a tautology by construction --
    /// `expected` is computed from the *same* fixed bytes at obfuscation time -- but
    /// unlike the arithmetic guard's `n*(n+1)` (checkable by eye), confirming it holds
    /// means actually running SHA256, not reasoning about it from the source text alone.
    /// SHA256 is a deterministic, standardized algorithm with no platform variation (the
    /// opposite of the string.GetHashCode() pitfall StringPass's own history already ran
    /// into -- see reports/string-pass-determinism-fix.draft.md), so a digest computed here
    /// with this tool's own (.NET 10) runtime always matches what the fixture's older
    /// .NET Framework runtime computes for the same input bytes at execution time.
    /// Uses `SHA256.Create()` + `HashAlgorithm.ComputeHash(byte[])` rather than the
    /// newer static `SHA256.HashData(byte[])` convenience method -- that one doesn't
    /// exist on the older corlib this fixture's own build targets (confirmed via
    /// reports/environment.json: built with the legacy `csc` compiler against .NET
    /// Framework's mscorlib), even though it's available and used elsewhere in this
    /// tool's *own* .NET 10 code without issue.
    /// </summary>
    private static Instruction EmitMhopGuard(
        ILProcessor il, VariableDefinition stateVar, Instruction dispatch, int targetStateId,
        long seed, string label, int ordinal)
    {
        var module = stateVar.VariableType.Module;
        var ts = module.TypeSystem;
        var body = il.Body;

        var sha256Type = BuildTypeRef(module, "System.Security.Cryptography", "SHA256", isValueType: false);
        var hashAlgType = BuildTypeRef(module, "System.Security.Cryptography", "HashAlgorithm", isValueType: false);
        var create = new MethodReference("Create", sha256Type, sha256Type) { HasThis = false };
        var computeHash = new MethodReference("ComputeHash", new ArrayType(ts.Byte), hashAlgType) { HasThis = true };
        computeHash.Parameters.Add(new ParameterDefinition(new ArrayType(ts.Byte)));

        var inputArray = new VariableDefinition(new ArrayType(ts.Byte));
        var hasher = new VariableDefinition(sha256Type);
        body.Variables.Add(inputArray);
        body.Variables.Add(hasher);

        var (inputBytes, expected) = DeriveMhopConstants(seed, label, ordinal);
        var realLabel = Instruction.Create(OpCodes.Ldc_I4, targetStateId);

        var first = Instruction.Create(OpCodes.Ldc_I4_4);
        il.Append(first);
        il.Append(Instruction.Create(OpCodes.Newarr, ts.Byte));
        for (int i = 0; i < 4; i++)
        {
            il.Append(Instruction.Create(OpCodes.Dup));
            il.Append(Instruction.Create(OpCodes.Ldc_I4, i));
            il.Append(Instruction.Create(OpCodes.Ldc_I4, (int)inputBytes[i]));
            il.Append(Instruction.Create(OpCodes.Stelem_I1));
        }
        il.Append(Instruction.Create(OpCodes.Stloc, inputArray));

        il.Append(Instruction.Create(OpCodes.Call, create));
        il.Append(Instruction.Create(OpCodes.Stloc, hasher));

        il.Append(Instruction.Create(OpCodes.Ldloc, hasher));
        il.Append(Instruction.Create(OpCodes.Ldloc, inputArray));
        il.Append(Instruction.Create(OpCodes.Callvirt, computeHash));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_0));
        il.Append(Instruction.Create(OpCodes.Ldelem_U1));
        il.Append(Instruction.Create(OpCodes.Ldc_I4, (int)expected));
        il.Append(Instruction.Create(OpCodes.Ceq));
        il.Append(Instruction.Create(OpCodes.Brtrue, realLabel));

        // False side: still safe-by-construction -- rehash the same bytes and discard
        // the result, rather than diverging to different code.
        il.Append(Instruction.Create(OpCodes.Ldloc, hasher));
        il.Append(Instruction.Create(OpCodes.Ldloc, inputArray));
        il.Append(Instruction.Create(OpCodes.Callvirt, computeHash));
        il.Append(Instruction.Create(OpCodes.Pop));

        il.Append(realLabel);
        il.Append(Instruction.Create(OpCodes.Stloc, stateVar));
        il.Append(Instruction.Create(OpCodes.Br, dispatch));
        return first;
    }

    private static (byte[] InputBytes, byte Expected) DeriveMhopConstants(long seed, string label, int ordinal)
    {
        var inputBytes = SHA256.HashData(Encoding.UTF8.GetBytes($"mhop-input:{seed}:{label}:{ordinal}"))[..4];
        var digest = SHA256.HashData(inputBytes);
        return (inputBytes, digest[0]);
    }

    private static TypeReference BuildTypeRef(ModuleDefinition module, string ns, string name, bool isValueType)
    {
        var scope = module.TypeSystem.Object.Scope;
        return new TypeReference(ns, name, module, scope, isValueType);
    }

    private static List<int> ShuffledIds(int count, long seed, string label)
    {
        var ids = Enumerable.Range(0, count).ToList();
        var bytes = DeriveBytes(seed, label, count * 4 + 16);
        int ptr = 0;
        for (int i = count - 1; i > 0; i--)
        {
            uint r = BitConverter.ToUInt32(bytes, ptr);
            ptr += 4;
            int j = (int)(r % (uint)(i + 1));
            (ids[i], ids[j]) = (ids[j], ids[i]);
        }
        return ids;
    }

    private static byte[] DeriveBytes(long seed, string label, int needed)
    {
        var result = new List<byte>(needed + 32);
        int counter = 0;
        while (result.Count < needed)
        {
            result.AddRange(SHA256.HashData(Encoding.UTF8.GetBytes($"cf:{seed}:{label}:{counter}")));
            counter++;
        }
        return result.Take(needed).ToArray();
    }
}
