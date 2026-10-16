using Mono.Cecil;

namespace Dysphasia.Obfuscator;

public sealed class PlanItem
{
    public string Kind { get; init; } = ""; // "type" | "method"
    public string OriginalFullName { get; init; } = "";
    public string MetadataToken { get; init; } = "";
    public bool Eligible { get; init; }
    public string? ExcludeReason { get; init; }
    public string? NewName { get; set; }

    // Not serialized -- only used inside the same process run to apply the plan.
    public TypeDefinition? TypeRef;
    public MethodDefinition? MethodRef;
}

/// <summary>
/// Decides which types/members are candidates for the P1 rename pass, and records why
/// anything is excluded (reports/obfuscator-plan.draft.md, "P1" row and the compatibility section).
/// This is a general-purpose eligibility policy, not specific to the PixelTone fixture --
/// the project's own stated goal is a tool users apply to their own builds.
/// </summary>
public static class RenamePlanner
{
    private static readonly string[] SerializationAttributeNames =
    {
        "SerializableAttribute", "DataContractAttribute", "XmlRootAttribute", "XmlTypeAttribute",
    };

    private static readonly string[] InteropAttributeNames =
    {
        "ComVisibleAttribute", "GuidAttribute", "DllImportAttribute", "StructLayoutAttribute",
    };

    public static List<PlanItem> BuildPlan(ModuleDefinition module, Policy policy)
    {
        var items = new List<PlanItem>();

        foreach (var type in module.Types)
        {
            if (type.Name == "<Module>") continue; // pseudo-type, nothing to rename

            var fullName = type.FullName;
            var (eligible, reason) = EvaluateType(type, policy);
            items.Add(new PlanItem
            {
                Kind = "type",
                OriginalFullName = fullName,
                MetadataToken = $"0x{type.MetadataToken.ToUInt32():x8}",
                Eligible = eligible,
                ExcludeReason = reason,
                TypeRef = type,
            });

            foreach (var method in type.Methods)
            {
                var methodFullName = $"{fullName}::{method.Name}";
                var (methodEligible, methodReason) = EvaluateMethod(method, policy);
                items.Add(new PlanItem
                {
                    Kind = "method",
                    OriginalFullName = methodFullName,
                    MetadataToken = $"0x{method.MetadataToken.ToUInt32():x8}",
                    Eligible = methodEligible,
                    ExcludeReason = methodReason,
                    MethodRef = method,
                });
            }
        }

        return items;
    }

    private static (bool eligible, string? reason) EvaluateType(TypeDefinition type, Policy policy)
    {
        var fullName = type.FullName;
        if (policy.ExcludeTypes.Contains(fullName))
            return (false, policy.ExcludeReasons.GetValueOrDefault(fullName, "listed in policy.excludeTypes"));

        if (type.Name.StartsWith('<'))
            return (false, "compiler-generated type (closure/state machine); out of scope for rename MVP");

        if (type.IsPublic || type.IsNestedPublic)
            return (false, "externally visible type; renaming would break the public API surface");

        if (type.HasCustomAttributes &&
            type.CustomAttributes.Any(a => SerializationAttributeNames.Contains(a.AttributeType.Name)))
            return (false, "serialization attribute present; (de)serializers may depend on the type name");

        if (type.HasCustomAttributes &&
            type.CustomAttributes.Any(a => InteropAttributeNames.Contains(a.AttributeType.Name)))
            return (false, "interop/layout attribute present; COM or native callers may depend on the name/layout");

        if (type.HasInterfaces && type.Interfaces.Any(i => i.InterfaceType.Resolve() is null))
            return (false, "implements an interface this tool cannot resolve; renaming risk unknown");

        return (true, null);
    }

    private static (bool eligible, string? reason) EvaluateMethod(MethodDefinition method, Policy policy)
    {
        var owner = method.DeclaringType.FullName;
        var qualified = $"{owner}::{method.Name}";
        if (policy.ExcludeMembers.Contains(qualified))
            return (false, policy.ExcludeReasons.GetValueOrDefault(qualified, "listed in policy.excludeMembers"));

        if (method.IsConstructor)
            return (false, "constructor; name is reserved (.ctor/.cctor)");

        if (method.Name.StartsWith('<'))
            return (false, "compiler-generated method; out of scope for rename MVP");

        if (method.IsPublic || method.IsFamily || method.IsFamilyOrAssembly)
            return (false, "externally visible method; renaming would break the public API surface");

        if (method.IsVirtual || method.IsAbstract)
            return (false, "virtual/abstract method; may override a base member or interface contract");

        if (method.HasOverrides)
            return (false, "explicit interface implementation; name is part of the contract");

        if (method.HasCustomAttributes &&
            method.CustomAttributes.Any(a => InteropAttributeNames.Contains(a.AttributeType.Name)))
            return (false, "interop attribute present; native callers may depend on the name");

        return (true, null);
    }
}
