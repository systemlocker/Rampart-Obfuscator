using System.Security.Cryptography;
using System.Text;
using Mono.Cecil;
using Rampart.Config;

namespace Rampart.Managed;

internal sealed class ManagedRenaming
{
    private readonly Dictionary<string, string> names = new(StringComparer.Ordinal);
    private readonly List<(IMetadataTokenProvider Subject, int Token, string Original, string Protected, string Kind)> entries = [];
    private readonly Dictionary<IMetadataTokenProvider, List<MemberReference>> aliases = [];
    private readonly HashSet<string> ambiguous = new(StringComparer.Ordinal);
    private readonly ModuleDefinition module;
    private readonly ManagedContractAnalysis contracts;
    private readonly string[] keeps;
    private readonly bool friend, xaml;
    internal ManagedRenaming(ModuleDefinition module, ManagedContractAnalysis contracts, string[] keeps)
    {
        this.module = module; this.contracts = contracts; this.keeps = keeps;
        friend = module.Assembly.CustomAttributes.Any(attribute => attribute.AttributeType.FullName == "System.Runtime.CompilerServices.InternalsVisibleToAttribute");
        xaml = module.Resources.Any(resource => resource.Name.EndsWith(".baml", StringComparison.OrdinalIgnoreCase) || resource.Name.EndsWith(".xaml", StringComparison.OrdinalIgnoreCase) || resource.Name.EndsWith(".g.resources", StringComparison.OrdinalIgnoreCase));
        // Imported references may be distinct Cecil objects from their local
        // definitions. Bind them before any name changes; never resolve external
        // assemblies implicitly from the machine running protection.
        var definitions = new Dictionary<string, MemberReference>(StringComparer.Ordinal);
        foreach (var member in module.GetTypes().SelectMany(type => new MemberReference[] { type }.Concat(type.Methods).Concat(type.Fields)))
        {
            if (!definitions.TryAdd(member.FullName, member)) ambiguous.Add(member.FullName);
        }
        foreach (var duplicate in ambiguous) definitions.Remove(duplicate);
        foreach (var reference in module.GetTypeReferences().Cast<MemberReference>().Concat(module.GetMemberReferences()))
        {
            var scope = reference is TypeReference type ? type.Scope : reference.DeclaringType.Scope;
            if (scope != module && (scope is not AssemblyNameReference assembly || assembly.FullName != module.Assembly.Name.FullName)) continue;
            if (!definitions.TryGetValue(reference.FullName, out var target) || ReferenceEquals(target, reference)) continue;
            if (!aliases.TryGetValue(target, out var references)) aliases.Add(target, references = []);
            references.Add(reference);
        }
    }
    internal string Normalize(string value)
    {
        foreach (var name in names) value = value.Replace(name.Key, name.Value, StringComparison.Ordinal);
        return value;
    }
    internal string? MethodReason(MethodDefinition method, ManagedMethodIdentity identity)
    {
        if (contracts.Reason(method) is { } reason) return reason;
        if (ambiguous.Contains(identity.Signature)) return "ambiguous-member-signature";
        if (xaml) return "xaml-resource-contract";
        if (!(method.IsPrivate || method.IsAssembly && !friend)) return "external-visibility";
        if (method.IsConstructor || method.IsVirtual || method.IsPInvokeImpl || method.IsUnmanagedExport || method.IsSpecialName || method.HasOverrides
            || method.HasGenericParameters || method.DeclaringType.HasGenericParameters) return "runtime-method-contract";
        if (HasNameContractAttributes(method) || HasEnclosingNameContractAttributes(method.DeclaringType) || identity.GeneratedCode) return "attributed-or-generated-contract";
        if (method.DeclaringType.IsInterface || method.DeclaringType.IsSerializable || method.DeclaringType.IsExplicitLayout || method.DeclaringType.IsSequentialLayout) return "type-layout-or-serialization-contract";
        if (keeps.Any(pattern => ManagedPolicy.Matches(pattern, identity.Signature) || ManagedPolicy.Matches(pattern, identity.Type))) return "keep-policy";
        return null;
    }
    internal void RenameMethod(MethodDefinition method, ManagedMethodIdentity identity, long seed) => Rename(method, identity.Signature, method.Name, "method", seed, name => method.Name = name);
    internal void Apply(long seed, ManagedProtectionOptions options)
    {
        foreach (var type in module.GetTypes().ToArray())
        {
            var original = Normalize(type.FullName);
            if (!ManagedPolicy.AllowsTypeRename(type, original, options)) continue;
            if (xaml || ambiguous.Contains(original) || contracts.Reason(type) is not null || HasEnclosingNameContractAttributes(type)
                || ManagedPolicy.IsCompilerGenerated(type) || type.HasGenericParameters || type.HasInterfaces
                || type.IsInterface || type.IsValueType || type.IsSerializable || type.IsSequentialLayout || type.IsExplicitLayout || type.Name.StartsWith('<')
                || type.BaseType?.FullName != "System.Object" || keeps.Any(pattern => ManagedPolicy.Matches(pattern, original))) continue;
            foreach (var field in type.Fields)
            {
                var fieldName = Normalize(field.FullName);
                if (ambiguous.Contains(fieldName) || contracts.Reason(field) is not null || !(field.IsPrivate || field.IsAssembly && !friend) || field.IsLiteral || field.IsSpecialName
                    || HasNameContractAttributes(field) || field.HasMarshalInfo || field.RVA != 0
                    || keeps.Any(pattern => ManagedPolicy.Matches(pattern, fieldName))) continue;
                Rename(field, fieldName, field.Name, "field", seed, name => field.Name = name);
            }
            if (contracts.TypeNameReason(type) is null && (type.IsNotPublic && !friend || type.IsNestedPrivate || type.IsNestedAssembly && !friend)
                && !module.Resources.Any(resource => resource.Name.Contains(original, StringComparison.Ordinal))
                && !AttributeTypeArguments(module).Any(reference => reference.FullName == type.FullName))
                Rename(type, original, type.Name, "type", seed, name => type.Name = name);
        }
    }
    private static bool HasEnclosingNameContractAttributes(TypeDefinition? type)
    {
        for (var current = type; current is not null; current = current.DeclaringType)
            if (HasNameContractAttributes(current)) return true;
        return false;
    }
    private static bool HasNameContractAttributes(ICustomAttributeProvider provider) => provider.CustomAttributes.Any(attribute =>
        // These compiler annotations contain nullability flags, not identifiers.
        // Preserve their blobs while allowing otherwise eligible declarations to
        // change names. Unknown, generated, debugger and serialization attributes
        // retain the conservative name boundary.
        attribute.AttributeType.FullName is not "System.Runtime.CompilerServices.NullableAttribute"
            and not "System.Runtime.CompilerServices.NullableContextAttribute"
            and not "System.Runtime.CompilerServices.NullablePublicOnlyAttribute");
    internal static IEnumerable<CustomAttribute> AllCustomAttributes(ModuleDefinition module)
    {
        var providers = new ICustomAttributeProvider[] { module, module.Assembly }.Concat(module.GetTypes().SelectMany(type => new ICustomAttributeProvider[] { type }
            .Concat(type.Fields).Concat(type.Properties).Concat(type.Events).Concat(type.Methods)
            .Concat(type.Interfaces).Concat(type.GenericParameters).Concat(type.GenericParameters.SelectMany(parameter => parameter.Constraints))
            .Concat(type.Methods.SelectMany(method => method.Parameters)).Concat(type.Methods.Select(method => method.MethodReturnType))
            .Concat(type.Methods.SelectMany(method => method.GenericParameters)).Concat(type.Methods.SelectMany(method => method.GenericParameters).SelectMany(parameter => parameter.Constraints))));
        return providers.SelectMany(provider => provider.CustomAttributes);
    }
    internal static IEnumerable<TypeReference> AttributeTypeArguments(ModuleDefinition module)
    {
        IEnumerable<TypeReference> Values(CustomAttributeArgument argument) => argument.Value switch
        { TypeReference type => [type], CustomAttributeArgument nested => Values(nested), CustomAttributeArgument[] array => array.SelectMany(Values), _ => [] };
        return AllCustomAttributes(module).SelectMany(attribute => attribute.ConstructorArguments
            .Concat(attribute.Fields.Select(field => field.Argument)).Concat(attribute.Properties.Select(property => property.Argument))).SelectMany(Values);
    }
    private void Rename(IMetadataTokenProvider subject, string fullName, string oldName, string kind, long seed, Action<string> rename)
    {
        var next = "r_" + kind + "_" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(fullName + "|" + seed)))[..20];
        names.Add(next, oldName); var token = subject.MetadataToken.ToInt32(); rename(next);
        if (aliases.TryGetValue(subject, out var references)) foreach (var reference in references) reference.Name = next;
        entries.Add((subject, token, fullName, next, kind));
    }
    internal IReadOnlyList<ManagedRenameEvidence> Evidence() => entries.Select(entry => new ManagedRenameEvidence(entry.Token, entry.Subject.MetadataToken.ToInt32(),
        entry.Original, entry.Protected, entry.Kind, "local-metadata-references-and-analyzed-name-contracts")).ToArray();
}
