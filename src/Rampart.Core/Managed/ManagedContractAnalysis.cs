using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Rampart.Managed;

// Argument provenance is intentionally block-local. A value crossing a join,
// exception edge, address-taking operation, or an unknown call is not a proof.
// Losing precision preserves names; it never turns an unknown into a local type.
internal sealed class ManagedContractAnalysis
{
    private readonly ModuleDefinition module;
    private readonly Dictionary<string, TypeDefinition> localTypes;
    private readonly Dictionary<TypeDefinition, string> types = [];
    private readonly Dictionary<IMetadataTokenProvider, string> members = [];
    private readonly Dictionary<Instruction, string> strings = [];
    private readonly List<string> unresolved = [];
    private readonly HashSet<TypeDefinition> graphs = [];
    internal IReadOnlyList<string> Unresolved => unresolved;
    internal string? Reason(IMetadataTokenProvider subject) => unresolved.Count != 0 ? "unresolved-contract:" + unresolved[0]
        : subject is TypeDefinition type ? types.GetValueOrDefault(type)
        : members.GetValueOrDefault(subject) ?? (subject is MemberReference member ? Local(member.DeclaringType) is { } owner ? types.GetValueOrDefault(owner) : null : null);
    internal string? StringReason(Instruction instruction) => strings.GetValueOrDefault(instruction);
    internal static ManagedContractAnalysis Analyze(ModuleDefinition module)
    {
        var analysis = new ManagedContractAnalysis(module);
        foreach (var type in ManagedRenaming.AttributeTypeArguments(module))
        { analysis.Preserve(type, "attribute-type-contract", true); analysis.PreserveTypeName(type, "attribute-type-contract"); }
        foreach (var method in module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody)) analysis.Analyze(method);
        return analysis;
    }
    private ManagedContractAnalysis(ModuleDefinition module)
    { this.module = module; localTypes = module.GetTypes().ToDictionary(type => type.FullName, StringComparer.Ordinal); }
    private sealed record Value(TypeReference? Type = null, bool IsType = false, Instruction? Literal = null, IMetadataTokenProvider? Token = null)
    { internal static readonly Value Unknown = new(); }
    private TypeDefinition? Local(TypeReference? reference)
    {
        if (reference is null) return null;
        while (reference is TypeSpecification specification) reference = specification.ElementType;
        if (reference is TypeDefinition definition) return definition.Module == module ? definition : null;
        if (reference.Scope != module && (reference.Scope is not AssemblyNameReference assembly || assembly.FullName != module.Assembly.Name.FullName)) return null;
        return localTypes.GetValueOrDefault(reference.FullName);
    }
    private void Unknown(MethodDefinition caller, Instruction site, string consumer)
    {
        var reason = $"{caller.FullName}@IL_{site.Offset:X4}:{consumer}";
        if (!unresolved.Contains(reason, StringComparer.Ordinal)) unresolved.Add(reason);
    }
    private void Preserve(TypeReference? reference, string reason, bool graph = false)
    {
        if (reference is GenericInstanceType instance) foreach (var argument in instance.GenericArguments) Preserve(argument, reason, graph);
        var type = Local(reference);
        if (type is null) return;
        types.TryAdd(type, reason);
        // Serializer and DI roots can expose inherited or nested object contracts.
        // Their local field/property graph is closed conservatively, including
        // possible local derived implementations. External types are not renamed.
        if (!graph || !graphs.Add(type)) return;
        Preserve(type.BaseType, reason, true);
        foreach (var field in type.Fields) Preserve(field.FieldType, reason, true);
        foreach (var property in type.Properties) Preserve(property.PropertyType, reason, true);
        foreach (var candidate in module.GetTypes())
            if (Local(candidate.BaseType) == type || candidate.Interfaces.Any(item => Local(item.InterfaceType) == type)) Preserve(candidate, reason, true);
    }
    private void PreserveName(TypeReference? reference, string? name, string reason)
    {
        var type = Local(reference);
        if (type is null) return;
        // Keep the containing type as well: MemberInfo.DeclaringType and names
        // derived from it are part of the same observed reflection contract.
        PreserveTypeName(type, reason);
        // BindingFlags may be assembled dynamically. Preserve case variants too
        // instead of assuming that a known literal implies case-sensitive lookup.
        foreach (var method in type.Methods.Where(method => name is null || string.Equals(method.Name, name, StringComparison.OrdinalIgnoreCase))) members.TryAdd(method, reason);
        foreach (var field in type.Fields.Where(field => name is null || string.Equals(field.Name, name, StringComparison.OrdinalIgnoreCase))) members.TryAdd(field, reason);
        foreach (var property in type.Properties.Where(property => name is null || string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase)))
        { members.TryAdd(property, reason); if (property.GetMethod is { } getter) members.TryAdd(getter, reason); if (property.SetMethod is { } setter) members.TryAdd(setter, reason); }
        foreach (var item in type.Events.Where(item => name is null || string.Equals(item.Name, name, StringComparison.OrdinalIgnoreCase))) members.TryAdd(item, reason);
        if (type.BaseType is { } parent) PreserveName(parent, name, reason);
    }
    internal string? TypeNameReason(TypeDefinition type) => Reason(type) ?? members.GetValueOrDefault(type);
    private void PreserveTypeName(TypeReference? reference, string reason)
    {
        for (var type = Local(reference); type is not null; type = type.DeclaringType) members.TryAdd(type, reason);
    }
    private void PreserveString(Value value, string reason)
    { if (value.Literal is { } literal) strings.TryAdd(literal, reason); }

    private void Analyze(MethodDefinition method)
    {
        var boundaries = method.Body.Instructions.SelectMany(instruction => instruction.Operand switch
        { Instruction target => new[] { target }, Instruction[] targets => targets, _ => [] }).ToHashSet();
        foreach (var region in method.Body.ExceptionHandlers)
        { boundaries.Add(region.HandlerStart); if (region.FilterStart is { } filter) boundaries.Add(filter); boundaries.Add(region.TryStart); }
        var stack = new List<Value>(); var locals = new Dictionary<int, Value>();
        var trackLocals = !method.Body.HasExceptionHandlers && !method.Body.Instructions.Any(instruction => instruction.OpCode.Code is Code.Ldloca or Code.Ldloca_S);
        foreach (var instruction in method.Body.Instructions)
        {
            if (boundaries.Contains(instruction)) { stack.Clear(); locals.Clear(); }
            Value Pop() { if (stack.Count == 0) return Value.Unknown; var value = stack[^1]; stack.RemoveAt(stack.Count - 1); return value; }
            var code = instruction.OpCode.Code;
            if (code is Code.Ldftn or Code.Ldvirtftn or Code.Ldtoken && instruction.Operand is MethodReference indirect
                && (indirect.DeclaringType.Namespace.StartsWith("System.Reflection", StringComparison.Ordinal)
                    || indirect.DeclaringType.FullName is "System.Type" or "System.Activator"
                    || indirect.DeclaringType.Namespace.StartsWith("System.Text.Json", StringComparison.Ordinal)
                    || indirect.DeclaringType.Namespace.StartsWith("Newtonsoft.Json", StringComparison.Ordinal)))
                Unknown(method, instruction, "indirect-contract-consumer");
            if (code == Code.Ldstr) stack.Add(new(Literal: instruction));
            else if (code == Code.Ldtoken) stack.Add(instruction.Operand is TypeReference type ? new(Type: type, IsType: true) : new(Token: instruction.Operand as IMetadataTokenProvider));
            else if (code == Code.Dup) { var value = Pop(); stack.Add(value); stack.Add(value); }
            else if (code is Code.Ldarg or Code.Ldarg_S or Code.Ldarg_0 or Code.Ldarg_1 or Code.Ldarg_2 or Code.Ldarg_3)
            {
                var index = code switch { Code.Ldarg_0 => 0, Code.Ldarg_1 => 1, Code.Ldarg_2 => 2, Code.Ldarg_3 => 3, _ => ((ParameterDefinition)instruction.Operand).Index + (method.HasThis ? 1 : 0) };
                var type = method.HasThis && index == 0 ? method.DeclaringType : method.Parameters[index - (method.HasThis ? 1 : 0)].ParameterType;
                stack.Add(Local(type) is { IsSealed: true } ? new(Type: type) : Value.Unknown);
            }
            else if (code is Code.Ldloc or Code.Ldloc_S or Code.Ldloc_0 or Code.Ldloc_1 or Code.Ldloc_2 or Code.Ldloc_3) stack.Add(trackLocals ? locals.GetValueOrDefault(LocalIndex(instruction), Value.Unknown) : Value.Unknown);
            else if (code is Code.Stloc or Code.Stloc_S or Code.Stloc_0 or Code.Stloc_1 or Code.Stloc_2 or Code.Stloc_3) locals[LocalIndex(instruction)] = Pop();
            else if (instruction.Operand is MethodReference callee && code is Code.Call or Code.Callvirt or Code.Newobj)
            {
                var arguments = new Value[callee.Parameters.Count];
                for (var index = arguments.Length - 1; index >= 0; index--) arguments[index] = Pop();
                var receiver = callee.HasThis && code != Code.Newobj ? Pop() : Value.Unknown;
                var result = Call(method, instruction, callee, receiver, arguments);
                if (code == Code.Newobj) stack.Add(new(Type: callee.DeclaringType));
                else if (callee.ReturnType.MetadataType != MetadataType.Void) stack.Add(result);
            }
            else
            {
                if (code == Code.Ret && stack.Count != 0 && stack[^1].Type is { } escaped
                    && (method.IsPublic || method.IsFamily || method.IsFamilyOrAssembly)) Preserve(escaped, "public-returned-object-contract", true);
                var pop = PopCount(method, instruction, stack.Count);
                for (var index = 0; index < pop; index++) _ = Pop();
                var push = instruction.OpCode.StackBehaviourPush switch { StackBehaviour.Push0 => 0, StackBehaviour.Push1_push1 => 2, StackBehaviour.Varpush => instruction.Operand is CallSite site && site.ReturnType.MetadataType != MetadataType.Void ? 1 : 0, _ => 1 };
                for (var index = 0; index < push; index++) stack.Add(Value.Unknown);
            }
            if (instruction.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch or FlowControl.Return or FlowControl.Throw)
            { stack.Clear(); locals.Clear(); }
        }
    }
    private Value Call(MethodDefinition caller, Instruction site, MethodReference callee, Value receiver, Value[] arguments)
    {
        var owner = callee.DeclaringType.FullName; var name = callee.Name;
        if (owner == "System.Type" && name == "GetTypeFromHandle") return arguments.FirstOrDefault() ?? Value.Unknown;
        if (owner == "System.Object" && name == "GetType")
        {
            if (receiver.Type is { } objectType) return new(Type: objectType, IsType: true);
            Unknown(caller, site, "runtime-type-unresolved"); return Value.Unknown;
        }
        if ((owner == "System.Type" || owner == "System.Reflection.Assembly") && name == "GetType")
        {
            var literal = arguments.FirstOrDefault(value => value.Literal is not null);
            if (literal?.Literal?.Operand is string text)
            {
                PreserveString(literal, "strings:reflection-name");
                var pieces = text.Split(',', 2); var requested = pieces[0].Trim().Replace('+', '/');
                var local = pieces.Length == 1 || pieces[1].Trim().Split(',')[0] == module.Assembly.Name.Name
                    ? module.GetTypes().FirstOrDefault(type => type.FullName == requested) : null;
                if (local is not null) { PreserveTypeName(local, "reflection-type-name"); return new(Type: local, IsType: true); }
                // An explicitly different assembly cannot name one of our types.
                if (pieces.Length == 2 && pieces[1].Trim().Split(',')[0] != module.Assembly.Name.Name)
                    return new(Type: new TypeReference("", requested, module, new AssemblyNameReference(pieces[1].Trim().Split(',')[0], new Version())), IsType: true);
            }
            Unknown(caller, site, "reflection-type-name-unresolved"); return Value.Unknown;
        }
        if (owner == "System.Type" && (name.StartsWith("Get", StringComparison.Ordinal) || name == "InvokeMember" || name is "get_Name" or "get_FullName" or "get_AssemblyQualifiedName"))
        {
            var literal = arguments.FirstOrDefault(value => value.Literal is not null);
            if (literal is not null) PreserveString(literal, "strings:reflection-name");
            if (!receiver.IsType || receiver.Type is null || receiver.Type.ContainsGenericParameter) Unknown(caller, site, "reflection-receiver-unresolved");
            else
            {
                // A known receiver plus an unknown member name still confines the
                // contract to that receiver. Preserve every possible local member.
                PreserveName(receiver.Type, literal?.Literal?.Operand as string, "reflection-member-name");
                if (name is "GetNestedType" or "GetNestedTypes" && Local(receiver.Type) is { } parent)
                {
                    var nested = parent.NestedTypes.Where(type => name == "GetNestedTypes" || literal is null
                        || string.Equals(type.Name, literal.Literal!.Operand as string, StringComparison.OrdinalIgnoreCase)).ToArray();
                    foreach (var target in nested) { Preserve(target, "reflection-nested-type"); PreserveTypeName(target, "reflection-nested-type"); }
                    if (name == "GetNestedType" && nested.Length == 1) return new(Type: nested[0], IsType: true);
                }
            }
            return Value.Unknown;
        }
        if (owner == "System.Reflection.Assembly" && name is "GetTypes" or "GetExportedTypes" or "CreateInstance") Unknown(caller, site, "assembly-reflection-enumeration");
        if (owner == "System.Reflection.MethodBase" && name == "GetCurrentMethod")
        { members.TryAdd(caller, "reflection-current-method"); PreserveTypeName(caller.DeclaringType, "reflection-current-method"); }
        if (owner == "System.Reflection.MethodBase" && name == "GetMethodFromHandle")
        {
            if (arguments.FirstOrDefault()?.Token is MethodDefinition target) { members.TryAdd(target, "reflection-method-handle"); PreserveTypeName(target.DeclaringType, "reflection-method-handle"); }
            else Unknown(caller, site, "reflection-method-handle-unresolved");
        }
        if (callee.DeclaringType.Namespace.StartsWith("System.Reflection", StringComparison.Ordinal)
            && !(owner == "System.Reflection.Assembly" && name is "GetTypes" or "GetExportedTypes" or "CreateInstance" or "GetExecutingAssembly" or "GetCallingAssembly" or "GetEntryAssembly")
            && !(owner == "System.Reflection.MethodBase" && name is "GetCurrentMethod" or "GetMethodFromHandle" or "Invoke")
            && !(owner is "System.Reflection.MethodInfo" or "System.Reflection.ConstructorInfo" && name is "Invoke" or "MakeGenericMethod"))
            Unknown(caller, site, "reflection-api-unresolved:" + owner + "." + name);
        var serializer = (callee.DeclaringType.Namespace.StartsWith("System.Text.Json", StringComparison.Ordinal)
            || callee.DeclaringType.Namespace.StartsWith("Newtonsoft.Json", StringComparison.Ordinal))
            && (name.Contains("Serialize", StringComparison.Ordinal) || name.Contains("Deserialize", StringComparison.Ordinal) || name == "PopulateObject")
            || owner is "System.Xml.Serialization.XmlSerializer" or "System.Runtime.Serialization.DataContractSerializer" or "System.Runtime.Serialization.Json.DataContractJsonSerializer" && name == ".ctor";
        var dependencyInjection = callee.DeclaringType.Namespace.StartsWith("Microsoft.Extensions.DependencyInjection", StringComparison.Ordinal)
            && (name.StartsWith("Add", StringComparison.Ordinal) || name is ".ctor" or "Describe" or "CreateInstance" or "GetServiceOrCreateInstance")
            && (callee is GenericInstanceMethod || callee.Parameters.Any(parameter => parameter.ParameterType.FullName == "System.Type"));
        var activation = owner == "System.Activator" && name.StartsWith("CreateInstance", StringComparison.Ordinal);
        if (serializer || dependencyInjection || activation)
        {
            var roots = new List<TypeReference>(); var uncertain = false;
            if (callee is GenericInstanceMethod generic) roots.AddRange(generic.GenericArguments);
            for (var index = 0; index < callee.Parameters.Count; index++)
                if (callee.Parameters[index].ParameterType.FullName == "System.Type")
                { if (arguments[index].IsType && arguments[index].Type is { } target) roots.Add(target); else uncertain = true; }
            if (roots.Count == 0 && serializer)
                for (var index = 0; index < callee.Parameters.Count; index++)
                    if (callee.Parameters[index].ParameterType.FullName == "System.Object" && arguments[index].Type is { } target) roots.Add(target);
            if (uncertain || roots.Count == 0 || roots.Any(type => type.ContainsGenericParameter || type.FullName == "System.Object")) Unknown(caller, site, serializer ? "serializer-target-unresolved" : dependencyInjection ? "dependency-injection-target-unresolved" : "activation-target-unresolved");
            else foreach (var root in roots) Preserve(root, serializer ? "serializer-contract" : dependencyInjection ? "dependency-injection-contract" : "activation-contract", true);
        }
        if (owner == "System.Delegate" && name == "CreateDelegate" && callee.Parameters.Any(parameter => parameter.ParameterType.MetadataType == MetadataType.String)) Unknown(caller, site, "delegate-name-unresolved");
        if (ManagedStringPolicy.IsMetadataOwnedConsumer(callee)) foreach (var argument in arguments) PreserveString(argument, "strings:metadata-owned-consumer");
        // Passing a local instance or Type to an unmodeled external consumer may
        // expose its default ToString, serializer conventions, or reflection names.
        // Bound that uncertainty to the known local object graph when possible.
        if (!serializer && !dependencyInjection && !activation && Local(callee.DeclaringType) is null
            && !(owner == "System.Object" && name == ".ctor") && !callee.DeclaringType.Namespace.StartsWith("System.Reflection", StringComparison.Ordinal))
            foreach (var value in arguments.Prepend(receiver)) if (value.Type is { } escaped) Preserve(escaped, "external-consumer-object-contract", true);
        return Local(callee.ReturnType) is { IsSealed: true } ? new(Type: callee.ReturnType) : Value.Unknown;
    }
    private static int LocalIndex(Instruction instruction) => instruction.OpCode.Code switch
    { Code.Ldloc_0 or Code.Stloc_0 => 0, Code.Ldloc_1 or Code.Stloc_1 => 1, Code.Ldloc_2 or Code.Stloc_2 => 2, Code.Ldloc_3 or Code.Stloc_3 => 3, _ => ((VariableDefinition)instruction.Operand).Index };
    private static int PopCount(MethodDefinition method, Instruction instruction, int height) => instruction.OpCode.StackBehaviourPop switch
    {
        StackBehaviour.Pop0 => 0,
        StackBehaviour.Pop1 or StackBehaviour.Popi or StackBehaviour.Popref => 1,
        StackBehaviour.Pop1_pop1 or StackBehaviour.Popi_pop1 or StackBehaviour.Popi_popi or StackBehaviour.Popi_popi8 or StackBehaviour.Popi_popr4 or StackBehaviour.Popi_popr8 or StackBehaviour.Popref_pop1 or StackBehaviour.Popref_popi => 2,
        StackBehaviour.Popi_popi_popi or StackBehaviour.Popref_popi_popi or StackBehaviour.Popref_popi_popi8 or StackBehaviour.Popref_popi_popr4 or StackBehaviour.Popref_popi_popr8 or StackBehaviour.Popref_popi_popref => 3,
        StackBehaviour.PopAll => height,
        StackBehaviour.Varpop when instruction.OpCode.Code == Code.Ret => method.ReturnType.MetadataType == MetadataType.Void ? 0 : 1,
        StackBehaviour.Varpop when instruction.Operand is CallSite site => site.Parameters.Count + (site.HasThis ? 1 : 0) + 1,
        _ => height
    };
}
