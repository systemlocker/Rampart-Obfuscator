using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Rampart.Managed;

internal static class ManagedHelperInjector
{
    internal static TypeDefinition Inject(ModuleDefinition module, string suffix, bool framework = false, bool hardened = false)
    {
        using var sourceModule = ModuleDefinition.ReadModule(typeof(RuntimeTemplate).Assembly.Location);
        var source = sourceModule.GetType(typeof(RuntimeTemplate).FullName!);
        var sourceMethods = source.Methods.Select(method => hardened && method.Name == "Decode"
            ? sourceModule.GetType(typeof(RuntimeHardenedTemplate).FullName!).Methods.Single(candidate => candidate.Name == "Decode")
            : framework && method.Name == "Verify"
                ? sourceModule.GetType(typeof(FrameworkIntegrityTemplate).FullName!).Methods.Single(candidate => candidate.Name == "Verify") : method).ToArray();
        TypeReference ImportType(TypeReference type) => framework ? ImportFrameworkType(module, type) : ImportModernType(module, type);
        MethodReference ImportMethod(MethodReference reference)
        {
            if (reference.HasGenericParameters || reference is GenericInstanceMethod)
                throw new ManagedProtectionException("MANAGED_HELPER_REFERENCE", "The runtime helper has an unsupported generic reference.");
            var imported = new MethodReference(reference.Name, ImportType(reference.ReturnType), ImportType(reference.DeclaringType))
            { HasThis = reference.HasThis, ExplicitThis = reference.ExplicitThis, CallingConvention = reference.CallingConvention };
            foreach (var parameter in reference.Parameters) imported.Parameters.Add(new ParameterDefinition(ImportType(parameter.ParameterType)));
            return imported;
        }
        var target = new TypeDefinition("", "<Rampart_" + suffix + ">", TypeAttributes.NotPublic | TypeAttributes.Abstract | TypeAttributes.Sealed,
            module.TypeSystem.Object);
        module.Types.Add(target);
        var fields = new Dictionary<FieldDefinition, FieldDefinition>();
        foreach (var field in source.Fields)
        {
            var copy = new FieldDefinition(field.Name, field.Attributes, ImportType(field.FieldType));
            foreach (var attribute in field.CustomAttributes)
                if (attribute.AttributeType.FullName == "System.ThreadStaticAttribute")
                    copy.CustomAttributes.Add(new CustomAttribute(ImportMethod(attribute.Constructor)));
            target.Fields.Add(copy); fields.Add(field, copy);
        }
        var methods = new Dictionary<MethodDefinition, MethodDefinition>();
        foreach (var method in sourceMethods)
        {
            var copy = new MethodDefinition(method.Name, method.Attributes, ImportType(method.ReturnType));
            foreach (var parameter in method.Parameters)
                copy.Parameters.Add(new ParameterDefinition(parameter.Name, parameter.Attributes, ImportType(parameter.ParameterType)));
            target.Methods.Add(copy);
            methods.Add(method, copy);
        }
        foreach (var method in sourceMethods)
        {
            var copy = methods[method];
            copy.Body.InitLocals = method.Body.InitLocals;
            copy.Body.MaxStackSize = method.Body.MaxStackSize;
            foreach (var variable in method.Body.Variables)
                copy.Body.Variables.Add(new VariableDefinition(ImportType(variable.VariableType)));
            var instructions = method.Body.Instructions.ToDictionary(i => i, _ => Instruction.Create(OpCodes.Nop));
            foreach (var instruction in method.Body.Instructions)
            {
                var cloned = instructions[instruction];
                cloned.OpCode = instruction.OpCode;
                cloned.Operand = instruction.Operand switch
                {
                    Instruction branch => instructions[branch],
                    Instruction[] branches => branches.Select(b => instructions[b]).ToArray(),
                    VariableDefinition variable => copy.Body.Variables[variable.Index],
                    ParameterDefinition parameter => copy.Parameters[parameter.Index],
                    MethodDefinition definition when methods.TryGetValue(definition, out var own) => own,
                    MethodReference reference => ImportMethod(reference),
                    FieldDefinition field when fields.TryGetValue(field, out var ownField) => ownField,
                    FieldReference field => new FieldReference(field.Name, ImportType(field.FieldType), ImportType(field.DeclaringType)),
                    TypeReference type => ImportType(type),
                    _ => instruction.Operand
                };
                copy.Body.Instructions.Add(cloned);
            }
            foreach (var region in method.Body.ExceptionHandlers)
                copy.Body.ExceptionHandlers.Add(new ExceptionHandler(region.HandlerType)
                {
                    TryStart = instructions[region.TryStart],
                    TryEnd = region.TryEnd is null ? null : instructions[region.TryEnd],
                    HandlerStart = instructions[region.HandlerStart],
                    HandlerEnd = region.HandlerEnd is null ? null : instructions[region.HandlerEnd],
                    FilterStart = region.FilterStart is null ? null : instructions[region.FilterStart],
                    CatchType = region.CatchType is null ? null : ImportType(region.CatchType)
                });
        }
        return target;
    }

    private static TypeReference ImportModernType(ModuleDefinition module, TypeReference type)
    {
        if (type is ArrayType array) return new ArrayType(ImportModernType(module, array.ElementType), array.Rank);
        if (type is ByReferenceType reference) return new ByReferenceType(ImportModernType(module, reference.ElementType));
        var primitive = type.MetadataType switch
        {
            MetadataType.Void => module.TypeSystem.Void,
            MetadataType.Boolean => module.TypeSystem.Boolean,
            MetadataType.Byte => module.TypeSystem.Byte,
            MetadataType.Char => module.TypeSystem.Char,
            MetadataType.Int32 => module.TypeSystem.Int32,
            MetadataType.Int64 => module.TypeSystem.Int64,
            MetadataType.String => module.TypeSystem.String,
            MetadataType.Object => module.TypeSystem.Object,
            _ => null
        };
        if (primitive is not null) return primitive;
        if (type.Scope is not AssemblyNameReference source || source.Name is not ("System.Runtime" or "System.Security.Cryptography"))
            throw new ManagedProtectionException("MANAGED_HELPER_REFERENCE", "The runtime helper has an unsupported platform reference.");
        // The helper is compiled with Rampart's net8 target. Importing those
        // references verbatim leaks net8 facades into net9/net10 applications.
        // Bind the small, closed helper API surface to the application's own TFM.
        Version version = module.AssemblyReferences.FirstOrDefault(reference => reference.Name == "System.Runtime" && reference.Version.Major >= 8)?.Version
            ?? module.AssemblyReferences.FirstOrDefault(reference => reference.Name == "System.Private.CoreLib" && reference.Version.Major >= 8)?.Version
            ?? source.Version;
        var scope = module.AssemblyReferences.FirstOrDefault(reference => reference.Name == source.Name && reference.Version == version
            && reference.PublicKeyToken.AsSpan().SequenceEqual(source.PublicKeyToken));
        if (scope is null)
        {
            scope = new AssemblyNameReference(source.Name, version) { PublicKeyToken = source.PublicKeyToken.ToArray(), Culture = source.Culture };
            module.AssemblyReferences.Add(scope);
        }
        return new TypeReference(type.Namespace, type.Name, module, scope, type.IsValueType);
    }

    private static TypeReference ImportFrameworkType(ModuleDefinition module, TypeReference type)
    {
        if (type is ArrayType array) return new ArrayType(ImportFrameworkType(module, array.ElementType), array.Rank);
        if (type is ByReferenceType reference) return new ByReferenceType(ImportFrameworkType(module, reference.ElementType));
        var primitive = type.MetadataType switch
        {
            MetadataType.Void => module.TypeSystem.Void,
            MetadataType.Boolean => module.TypeSystem.Boolean,
            MetadataType.Byte => module.TypeSystem.Byte,
            MetadataType.Char => module.TypeSystem.Char,
            MetadataType.Int32 => module.TypeSystem.Int32,
            MetadataType.Int64 => module.TypeSystem.Int64,
            MetadataType.String => module.TypeSystem.String,
            MetadataType.Object => module.TypeSystem.Object,
            _ => null
        };
        if (primitive is not null) return primitive;
        // This closed list is the helper's complete CLR 4 dependency surface.
        // New helper APIs must acquire Framework fixtures before entering it.
        if (type.FullName is not ("System.IO.Stream" or "System.Reflection.Assembly" or "System.IDisposable"
            or "System.Security.Cryptography.SHA256" or "System.Security.Cryptography.HashAlgorithm"
            or "System.Convert" or "System.BitConverter" or "System.IO.InvalidDataException" or "System.Array" or "System.ThreadStaticAttribute"))
            throw new ManagedProtectionException("MANAGED_HELPER_REFERENCE", "The runtime helper has an unsupported Framework reference.");
        IMetadataScope scope = module.TypeSystem.CoreLibrary;
        if (type.FullName == "System.IO.InvalidDataException")
        {
            var system = module.AssemblyReferences.FirstOrDefault(reference => reference.Name == "System" && reference.Version.Major == 4);
            if (system is null)
            {
                system = new AssemblyNameReference("System", new Version(4, 0, 0, 0)) { PublicKeyToken = Convert.FromHexString("B77A5C561934E089") };
                module.AssemblyReferences.Add(system);
            }
            scope = system;
        }
        return new TypeReference(type.Namespace, type.Name, module, scope, type.IsValueType);
    }
}
