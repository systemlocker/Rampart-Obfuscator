using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Rampart.Managed;

internal static class ManagedIlVerifier
{
    // A worklist proves stack heights, branch ownership, and EH entry contracts. Typed
    // transformations additionally use the int32 lifter or preserve existing stack edges.
    internal static void Validate(MethodDefinition method)
    {
        try { ValidateCore(method); }
        catch (ManagedProtectionException error) when (error.ReasonCode.StartsWith("MANAGED_STACK", StringComparison.Ordinal))
        { throw new ManagedProtectionException(error.ReasonCode, $"Method 0x{method.MetadataToken.ToInt32():X8} failed evaluation-stack validation."); }
    }
    private static void ValidateCore(MethodDefinition method)
    {
        if (!method.HasBody) return;
        var body = method.Body;
        if (body.Instructions.Count == 0) Fail();
        var owned = body.Instructions.ToHashSet();
        var heights = new Dictionary<Instruction, int>();
        var pending = new Queue<(Instruction Instruction, int Height)>();
        pending.Enqueue((body.Instructions[0], 0));
        foreach (var region in body.ExceptionHandlers)
        {
            if (!owned.Contains(region.TryStart) || !owned.Contains(region.HandlerStart)
                || region.TryEnd is not null && !owned.Contains(region.TryEnd)
                || region.HandlerEnd is not null && !owned.Contains(region.HandlerEnd)) Fail();
            pending.Enqueue((region.HandlerStart, region.HandlerType is ExceptionHandlerType.Catch or ExceptionHandlerType.Filter ? 1 : 0));
            if (region.FilterStart is not null) pending.Enqueue((region.FilterStart, 1));
        }
        foreach (var instruction in body.Instructions)
        {
            if (instruction.Operand is Instruction target && !owned.Contains(target)) Fail();
            if (instruction.Operand is Instruction[] targets && targets.Any(t => !owned.Contains(t))) Fail();
        }
        while (pending.TryDequeue(out var item))
        {
            var (instruction, height) = item;
            if (heights.TryGetValue(instruction, out var previous)) { if (previous != height) Fail(); continue; }
            heights.Add(instruction, height);
            var pop = PopCount(method, instruction, height);
            if (height < pop) Fail();
            var next = checked(height - pop + PushCount(instruction));
            if (next > ushort.MaxValue) Fail();
            if (instruction.OpCode.Code is Code.Leave or Code.Leave_S) next = 0;
            if (instruction.Operand is Instruction branch) pending.Enqueue((branch, next));
            if (instruction.Operand is Instruction[] branches) foreach (var branchTarget in branches) pending.Enqueue((branchTarget, next));
            if (instruction.OpCode.FlowControl == FlowControl.Throw) continue;
            if (instruction.OpCode.FlowControl == FlowControl.Return)
            { if (next != 0) Fail(); continue; }
            if (instruction.OpCode.FlowControl == FlowControl.Branch) continue;
            if (instruction.Next is not null) pending.Enqueue((instruction.Next, next));
            else Fail();
        }
        ValidateTypes(method);
    }

    private enum StackKind { Unknown, Int32, Int64, NativeInt, Float, Object, Pointer, Value }
    private static TypeReference StackType(TypeReference type)
    {
        while (type is RequiredModifierType or OptionalModifierType or PinnedType or SentinelType) type = ((TypeSpecification)type).ElementType;
        return type;
    }
    private static bool IsVoid(TypeReference type) => StackType(type).MetadataType == MetadataType.Void;
    private static StackKind Kind(TypeReference type) => KindCore(StackType(type));
    private static StackKind KindCore(TypeReference type) => type.MetadataType switch
    {
        MetadataType.Boolean or MetadataType.Char or MetadataType.SByte or MetadataType.Byte or MetadataType.Int16 or MetadataType.UInt16 or MetadataType.Int32 or MetadataType.UInt32 => StackKind.Int32,
        MetadataType.Int64 or MetadataType.UInt64 => StackKind.Int64,
        MetadataType.IntPtr or MetadataType.UIntPtr => StackKind.NativeInt,
        MetadataType.Single or MetadataType.Double => StackKind.Float,
        MetadataType.ByReference or MetadataType.Pointer or MetadataType.FunctionPointer => StackKind.Pointer,
        MetadataType.String or MetadataType.Object or MetadataType.Class or MetadataType.Array => StackKind.Object,
        MetadataType.ValueType => type is TypeDefinition definition ? (definition.IsEnum ? Kind(definition.Fields.Single(f => f.Name == "value__").FieldType) : StackKind.Value) : StackKind.Unknown,
        MetadataType.GenericInstance => type.IsValueType ? StackKind.Unknown : StackKind.Object,
        _ => StackKind.Unknown
    };
    internal static string VerificationStatus(MethodDefinition method)
    {
        if (!method.HasBody) return "no-il-body";
        bool Nominal(TypeReference type) => !IsVoid(type) && Kind(type) is StackKind.Unknown or StackKind.Object or StackKind.Value or StackKind.Pointer;
        bool unresolved = method.HasGenericParameters || method.DeclaringType.HasGenericParameters || Nominal(method.ReturnType)
            || method.Parameters.Any(parameter => Nominal(parameter.ParameterType)) || method.Body.Variables.Any(variable => Nominal(variable.VariableType))
            || method.Body.HasExceptionHandlers || method.Body.Instructions.Any(instruction => instruction.Operand is MemberReference or CallSite
                || instruction.OpCode.Code is Code.Arglist or Code.Refanytype);
        return unresolved ? "stack-categories-verified;nominal-verification-required" : "stack-categories-verified";
    }
    private static void ValidateTypes(MethodDefinition method)
    {
        var states = new Dictionary<Instruction, StackKind[]>();
        var queue = new Queue<(Instruction Instruction, StackKind[] Stack)>();
        queue.Enqueue((method.Body.Instructions[0], []));
        foreach (var region in method.Body.ExceptionHandlers)
        {
            queue.Enqueue((region.HandlerStart, region.HandlerType is ExceptionHandlerType.Catch or ExceptionHandlerType.Filter ? [StackKind.Object] : []));
            if (region.FilterStart is not null) queue.Enqueue((region.FilterStart, [StackKind.Object]));
        }
        while (queue.TryDequeue(out var item))
        {
            var (instruction, stack) = item;
            if (states.TryGetValue(instruction, out var known))
            {
                if (known.Length != stack.Length) Fail();
                var changed = false;
                for (var i = 0; i < stack.Length; i++)
                {
                    Compatible(known[i], stack[i]);
                    if (known[i] != StackKind.Unknown && stack[i] == StackKind.Unknown) { known[i] = StackKind.Unknown; changed = true; }
                }
                if (!changed) continue;
                stack = known;
            }
            else states.Add(instruction, stack.ToArray());
            var pop = PopCount(method, instruction, stack.Length); var pushes = PushCount(instruction);
            var top = stack.Length == 0 ? StackKind.Unknown : stack[^1];
            ValidateOperands(instruction, stack);
            var result = StackKind.Unknown;
            if (ManagedTransforms.Integer(instruction, out _)) result = StackKind.Int32;
            else if (instruction.OpCode.Code is Code.Ldarg or Code.Ldarg_S or Code.Ldarg_0 or Code.Ldarg_1 or Code.Ldarg_2 or Code.Ldarg_3)
            {
                var index = instruction.OpCode.Code switch { Code.Ldarg_0 => 0, Code.Ldarg_1 => 1, Code.Ldarg_2 => 2, Code.Ldarg_3 => 3, _ => ((ParameterDefinition)instruction.Operand).Index + (method.HasThis ? 1 : 0) };
                result = method.HasThis && index == 0 ? (method.DeclaringType.IsValueType ? StackKind.Pointer : StackKind.Object)
                    : Kind(method.Parameters[index - (method.HasThis ? 1 : 0)].ParameterType);
            }
            else if (instruction.OpCode.Code is Code.Ldloc or Code.Ldloc_S or Code.Ldloc_0 or Code.Ldloc_1 or Code.Ldloc_2 or Code.Ldloc_3)
                result = Kind(Local(method, instruction).VariableType);
            else if (instruction.OpCode.Code is Code.Stloc or Code.Stloc_S or Code.Stloc_0 or Code.Stloc_1 or Code.Stloc_2 or Code.Stloc_3)
                Compatible(Kind(Local(method, instruction).VariableType), top);
            else if (instruction.OpCode.Code is Code.Starg or Code.Starg_S) Compatible(Kind(((ParameterDefinition)instruction.Operand).ParameterType), top);
            else if (instruction.OpCode.Code == Code.Ret && pop != 0) Compatible(Kind(method.ReturnType), top);
            else if (instruction.Operand is MethodReference callee && instruction.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj)
            {
                for (var p = 0; p < callee.Parameters.Count; p++) Compatible(Kind(callee.Parameters[callee.Parameters.Count - p - 1].ParameterType), stack[stack.Length - p - 1]);
                result = instruction.OpCode.Code == Code.Newobj ? Kind(callee.DeclaringType) : Kind(callee.ReturnType);
            }
            else if (instruction.Operand is FieldReference field)
            {
                if (instruction.OpCode.Code is Code.Stfld or Code.Stsfld) Compatible(Kind(field.FieldType), top);
                result = instruction.OpCode.Code is Code.Ldflda or Code.Ldsflda ? StackKind.Pointer : Kind(field.FieldType);
            }
            else result = instruction.OpCode.Code switch
            {
                Code.Ldc_I8 or Code.Conv_I8 or Code.Conv_U8 or Code.Conv_Ovf_I8 or Code.Conv_Ovf_I8_Un or Code.Conv_Ovf_U8 or Code.Conv_Ovf_U8_Un or Code.Ldind_I8 or Code.Ldelem_I8 => StackKind.Int64,
                Code.Ldc_R4 or Code.Ldc_R8 or Code.Conv_R4 or Code.Conv_R8 or Code.Conv_R_Un or Code.Ldind_R4 or Code.Ldind_R8 or Code.Ldelem_R4 or Code.Ldelem_R8 or Code.Ckfinite => StackKind.Float,
                Code.Ldstr or Code.Ldnull or Code.Box or Code.Castclass or Code.Isinst or Code.Newarr or Code.Ldind_Ref or Code.Ldelem_Ref => StackKind.Object,
                Code.Ldloca or Code.Ldloca_S or Code.Ldarga or Code.Ldarga_S or Code.Ldelema or Code.Unbox or Code.Refanyval => StackKind.Pointer,
                Code.Ldlen or Code.Ldftn or Code.Ldvirtftn or Code.Conv_I or Code.Conv_U or Code.Conv_Ovf_I or Code.Conv_Ovf_I_Un or Code.Conv_Ovf_U or Code.Conv_Ovf_U_Un or Code.Localloc or Code.Ldind_I or Code.Ldelem_I => StackKind.NativeInt,
                Code.Conv_I1 or Code.Conv_I2 or Code.Conv_I4 or Code.Conv_U1 or Code.Conv_U2 or Code.Conv_U4 or Code.Conv_Ovf_I1 or Code.Conv_Ovf_I1_Un or Code.Conv_Ovf_I2 or Code.Conv_Ovf_I2_Un or Code.Conv_Ovf_I4 or Code.Conv_Ovf_I4_Un
                    or Code.Conv_Ovf_U1 or Code.Conv_Ovf_U1_Un or Code.Conv_Ovf_U2 or Code.Conv_Ovf_U2_Un or Code.Conv_Ovf_U4 or Code.Conv_Ovf_U4_Un or Code.Ceq or Code.Cgt or Code.Cgt_Un or Code.Clt or Code.Clt_Un or Code.Sizeof
                    or Code.Ldind_I1 or Code.Ldind_U1 or Code.Ldind_I2 or Code.Ldind_U2 or Code.Ldind_I4 or Code.Ldind_U4 or Code.Ldelem_I1 or Code.Ldelem_U1 or Code.Ldelem_I2 or Code.Ldelem_U2 or Code.Ldelem_I4 or Code.Ldelem_U4 => StackKind.Int32,
                Code.Dup or Code.Neg or Code.Not => top,
                Code.Ldobj or Code.Unbox_Any or Code.Ldelem_Any => Kind((TypeReference)instruction.Operand),
                Code.Add or Code.Add_Ovf or Code.Add_Ovf_Un or Code.Sub or Code.Sub_Ovf or Code.Sub_Ovf_Un => AddResult(instruction.OpCode.Code, stack),
                Code.Mul or Code.Mul_Ovf or Code.Mul_Ovf_Un or Code.Div or Code.Div_Un or Code.Rem or Code.Rem_Un or Code.And or Code.Or or Code.Xor or Code.Shl or Code.Shr or Code.Shr_Un => stack.Length > 1 ? stack[^2] : StackKind.Unknown,
                _ => StackKind.Unknown
            };
            var next = new StackKind[stack.Length - pop + pushes]; Array.Copy(stack, next, stack.Length - pop);
            for (var i = next.Length - pushes; i < next.Length; i++) next[i] = result;
            if (instruction.OpCode.Code is Code.Leave or Code.Leave_S) next = [];
            if (instruction.Operand is Instruction branch) queue.Enqueue((branch, next));
            if (instruction.Operand is Instruction[] branches) foreach (var target in branches) queue.Enqueue((target, next));
            if (instruction.OpCode.FlowControl is not (FlowControl.Return or FlowControl.Throw or FlowControl.Branch) && instruction.Next is { } following) queue.Enqueue((following, next));
        }
    }
    private static StackKind AddResult(Code operation, StackKind[] stack)
    {
        var left = stack[^2]; var right = stack[^1];
        if (left == StackKind.Unknown || right == StackKind.Unknown) return StackKind.Unknown;
        if (left == StackKind.Pointer && right == StackKind.Pointer && operation is Code.Sub or Code.Sub_Ovf or Code.Sub_Ovf_Un) return StackKind.NativeInt;
        if (left == StackKind.Pointer || right == StackKind.Pointer) return StackKind.Pointer;
        return left == StackKind.NativeInt || right == StackKind.NativeInt ? StackKind.NativeInt : left;
    }
    private static void ValidateOperands(Instruction instruction, StackKind[] stack)
    {
        void Require(StackKind value, params StackKind[] permitted)
        {
            if (value != StackKind.Unknown && !permitted.Contains(value))
                ManagedPreflight.Fail("MANAGED_STACK_TYPE", "An IL operand has an incompatible evaluation-stack category.");
        }
        var code = instruction.OpCode.Code;
        if (code is Code.Add or Code.Add_Ovf or Code.Add_Ovf_Un or Code.Sub or Code.Sub_Ovf or Code.Sub_Ovf_Un
            or Code.Mul or Code.Mul_Ovf or Code.Mul_Ovf_Un or Code.Div or Code.Div_Un or Code.Rem or Code.Rem_Un
            or Code.And or Code.Or or Code.Xor)
        {
            var left = stack[^2]; var right = stack[^1];
            bool add = code is Code.Add or Code.Add_Ovf or Code.Add_Ovf_Un or Code.Sub or Code.Sub_Ovf or Code.Sub_Ovf_Un;
            if (add) { Require(left, StackKind.Int32, StackKind.Int64, StackKind.NativeInt, StackKind.Float, StackKind.Pointer); Require(right, StackKind.Int32, StackKind.Int64, StackKind.NativeInt, StackKind.Float, StackKind.Pointer); }
            else { Require(left, StackKind.Int32, StackKind.Int64, StackKind.NativeInt, StackKind.Float); Require(right, StackKind.Int32, StackKind.Int64, StackKind.NativeInt, StackKind.Float); }
            if (code is Code.And or Code.Or or Code.Xor) { Require(left, StackKind.Int32, StackKind.Int64, StackKind.NativeInt); Require(right, StackKind.Int32, StackKind.Int64, StackKind.NativeInt); }
            if (code is Code.Add_Ovf or Code.Add_Ovf_Un or Code.Sub_Ovf or Code.Sub_Ovf_Un or Code.Mul_Ovf or Code.Mul_Ovf_Un or Code.Div_Un or Code.Rem_Un)
            { Require(left, StackKind.Int32, StackKind.Int64, StackKind.NativeInt); Require(right, StackKind.Int32, StackKind.Int64, StackKind.NativeInt); }
            if (left == StackKind.Pointer && right == StackKind.Pointer && code == Code.Add
                || right == StackKind.Pointer && left != StackKind.Pointer && left != StackKind.Unknown && code == Code.Sub)
                ManagedPreflight.Fail("MANAGED_STACK_TYPE", "The IL pointer arithmetic operands are invalid.");
            if (left != StackKind.Unknown && right != StackKind.Unknown && left != right
                && (left is StackKind.Int64 or StackKind.Float || right is StackKind.Int64 or StackKind.Float))
                ManagedPreflight.Fail("MANAGED_STACK_TYPE", "Binary IL operands have incompatible numeric widths.");
        }
        else if (code is Code.Shl or Code.Shr or Code.Shr_Un)
        { Require(stack[^2], StackKind.Int32, StackKind.Int64, StackKind.NativeInt); Require(stack[^1], StackKind.Int32, StackKind.NativeInt); }
        else if (code == Code.Not) Require(stack[^1], StackKind.Int32, StackKind.Int64, StackKind.NativeInt);
        else if (code == Code.Neg) Require(stack[^1], StackKind.Int32, StackKind.Int64, StackKind.NativeInt, StackKind.Float);
        else if (code == Code.Throw) Require(stack[^1], StackKind.Object);
        else if (code is Code.Endfilter or Code.Switch) Require(stack[^1], StackKind.Int32);
        else if (instruction.Operand is MethodReference method && method.HasThis && code is Code.Call or Code.Callvirt)
            Require(stack[stack.Length - method.Parameters.Count - 1], StackKind.Object, StackKind.Pointer);
    }
    private static VariableDefinition Local(MethodDefinition method, Instruction instruction) => method.Body.Variables[instruction.OpCode.Code switch
    {
        Code.Ldloc_0 or Code.Stloc_0 => 0,
        Code.Ldloc_1 or Code.Stloc_1 => 1,
        Code.Ldloc_2 or Code.Stloc_2 => 2,
        Code.Ldloc_3 or Code.Stloc_3 => 3,
        _ => ((VariableDefinition)instruction.Operand).Index
    }];
    private static void Compatible(StackKind expected, StackKind actual)
    {
        // Generic parameters and unresolved external value-type identities remain
        // unknown here; the independent ILVerify lane resolves full nominal types.
        if (expected != StackKind.Unknown && actual != StackKind.Unknown && expected != actual)
            ManagedPreflight.Fail("MANAGED_STACK_TYPE", "A method has incompatible evaluation-stack categories.");
    }

    private static int PopCount(MethodDefinition method, Instruction instruction, int height) => instruction.OpCode.StackBehaviourPop switch
    {
        StackBehaviour.Pop0 => 0,
        StackBehaviour.Pop1 or StackBehaviour.Popi or StackBehaviour.Popref => 1,
        StackBehaviour.Pop1_pop1 or StackBehaviour.Popi_pop1 or StackBehaviour.Popi_popi or StackBehaviour.Popi_popi8
            or StackBehaviour.Popi_popr4 or StackBehaviour.Popi_popr8 or StackBehaviour.Popref_pop1 or StackBehaviour.Popref_popi => 2,
        StackBehaviour.Popi_popi_popi or StackBehaviour.Popref_popi_popi
            or StackBehaviour.Popref_popi_popi8 or StackBehaviour.Popref_popi_popr4 or StackBehaviour.Popref_popi_popr8
            or StackBehaviour.Popref_popi_popref => 3,
        StackBehaviour.PopAll => height,
        StackBehaviour.Varpop when instruction.OpCode.Code == Code.Ret => IsVoid(method.ReturnType) ? 0 : 1,
        StackBehaviour.Varpop when instruction.Operand is MethodReference callee => callee.Parameters.Count + (callee.HasThis && instruction.OpCode.Code != Code.Newobj ? 1 : 0),
        StackBehaviour.Varpop when instruction.Operand is CallSite site => site.Parameters.Count + (site.HasThis ? 1 : 0) + 1,
        _ => throw new ManagedProtectionException("MANAGED_STACK_OPCODE", "The method uses an unsupported stack instruction.")
    };

    private static int PushCount(Instruction instruction) => instruction.OpCode.StackBehaviourPush switch
    {
        StackBehaviour.Push0 => 0,
        StackBehaviour.Push1 or StackBehaviour.Pushi or StackBehaviour.Pushi8 or StackBehaviour.Pushr4 or StackBehaviour.Pushr8 or StackBehaviour.Pushref => 1,
        StackBehaviour.Push1_push1 => 2,
        StackBehaviour.Varpush when instruction.Operand is MethodReference callee => IsVoid(callee.ReturnType) ? 0 : 1,
        StackBehaviour.Varpush when instruction.Operand is CallSite site => IsVoid(site.ReturnType) ? 0 : 1,
        _ => throw new ManagedProtectionException("MANAGED_STACK_OPCODE", "The method uses an unsupported stack instruction.")
    };

    private static void Fail() => ManagedPreflight.Fail("MANAGED_STACK_INVALID", "A method failed IL stack or branch validation.");
}
