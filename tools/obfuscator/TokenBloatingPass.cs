using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Dysphasia.Obfuscator;

public sealed class TokenBloatingPassResult
{
    public int ChainDepth { get; set; }
}

/// <summary>
/// Token bloating: a linear chain of empty classes, each inheriting from the last
/// (A20 : A19 : ... : A1 : Object), never instantiated and never referenced by any real
/// code. Distinct from GarbageDataPass (dummy fields/methods that compute something) --
/// this is purely declarative metadata bloat, literally the "meaningless infinite class
/// inheritance" the technique names, scaled to a finite depth a 115-line fixture can plausibly carry.
///
/// Zero runtime risk by construction: nothing ever calls `new` on any of these types, so
/// even a mistake in how the constructor chain calls its base constructor can only ever
/// be *unreachable* dead metadata, never something that executes and misbehaves.
///
/// Honest framing (see reports/token-bloating.draft.md): REA's own CLI exposes
/// `--token-limit`/`--token-offset` for paginating through large outputs, so "exhaust
/// REA's context window" specifically is not what this demonstrates -- it is still a
/// real increase in the member list surface anything skimming this module by eye (or
/// without pagination) has to wade through.
/// </summary>
public static class TokenBloatingPass
{
    private const int ChainDepth = 20;

    public static TokenBloatingPassResult Apply(ModuleDefinition module, Policy policy, long seed)
    {
        var ts = module.TypeSystem;
        TypeReference baseTypeRef = ts.Object;
        MethodReference baseCtorRef = new MethodReference(".ctor", ts.Void, ts.Object) { HasThis = true };

        int created = 0;
        for (int i = 0; i < ChainDepth; i++)
        {
            var type = new TypeDefinition("", NameGenerator.Generate(seed, $"__bloat_chain__{i}", "T"),
                TypeAttributes.NotPublic | TypeAttributes.Sealed, baseTypeRef);
            module.Types.Add(type);

            var ctor = new MethodDefinition(".ctor",
                MethodAttributes.Assembly | MethodAttributes.HideBySig
                | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, ts.Void);
            var il = ctor.Body.GetILProcessor();
            il.Append(Instruction.Create(OpCodes.Ldarg_0));
            il.Append(Instruction.Create(OpCodes.Call, baseCtorRef));
            il.Append(Instruction.Create(OpCodes.Ret));
            type.Methods.Add(ctor);

            baseTypeRef = type;
            baseCtorRef = ctor;
            created++;
        }

        return new TokenBloatingPassResult { ChainDepth = created };
    }
}
