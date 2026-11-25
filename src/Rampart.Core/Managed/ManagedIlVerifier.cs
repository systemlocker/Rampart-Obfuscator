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
        { throw new ManagedProtectionException(error.ReasonCode, $"Method 0x{method.MetadataToken.ToInt32():X8} failed evaluation-stack validation.", error); }
    }

    internal static void UpdateMaxStackSize(MethodDefinition method)
    {
        if (!method.HasBody || method.Body.Instructions.Count == 0) return;
        var body = method.Body;
        var owned = body.Instructions.ToHashSet();
        var heights = new Dictionary<Instruction, int>();
        var pending = new Queue<(Instruction Instruction, int Height)>();
        pending.Enqueue((body.Instructions[0], 0));
        foreach (var region in body.ExceptionHandlers)
        {
            if (region.HandlerStart is not null && owned.Contains(region.HandlerStart))
                pending.Enqueue((region.HandlerStart, region.HandlerType is ExceptionHandlerType.Catch or ExceptionHandlerType.Filter ? 1 : 0));
            if (region.FilterStart is not null && owned.Contains(region.FilterStart))
                pending.Enqueue((region.FilterStart, 1));
        }
        var peak = 0;
        while (pending.TryDequeue(out var item))
        {
            var (instruction, height) = item;
            if (!owned.Contains(instruction) || heights.ContainsKey(instruction)) continue;
            heights.Add(instruction, height);
            peak = Math.Max(peak, height);
            if (instruction.OpCode.Code == Code.Jmp) continue;
            var pop = PopCount(method, instruction, height);
            if (height < pop) continue;
            var next = checked(height - pop + PushCount(instruction));
            peak = Math.Max(peak, next);
            if (instruction.OpCode.Code is Code.Leave or Code.Leave_S) next = 0;
            if (instruction.Operand is Instruction branch) pending.Enqueue((branch, next));
            if (instruction.Operand is Instruction[] branches) foreach (var branchTarget in branches) pending.Enqueue((branchTarget, next));
            if (instruction.OpCode.FlowControl is FlowControl.Throw or FlowControl.Return or FlowControl.Branch) continue;
            if (instruction.Next is not null) pending.Enqueue((instruction.Next, next));
        }
        if (peak <= ushort.MaxValue)
            body.MaxStackSize = Math.Max(body.MaxStackSize, Math.Max(1, peak));
    }

    private static void ValidateCore(MethodDefinition method)
    {
        if (!method.HasBody) return;
        var body = method.Body;
        if (body.Instructions.Count == 0) Fail();
        var indices = new Dictionary<Instruction, int>(body.Instructions.Count);
        for (var i = 0; i < body.Instructions.Count; i++) indices[body.Instructions[i]] = i;
        var heights = new Dictionary<Instruction, int>();
        var pending = new Queue<(Instruction Instruction, int Height)>();
        pending.Enqueue((body.Instructions[0], 0));
        var regions = new List<(int TryStart, int TryEnd, int HandlerStart, int HandlerEnd)>(body.ExceptionHandlers.Count);
        foreach (var region in body.ExceptionHandlers)
        {
            if (region.TryStart is null || !indices.TryGetValue(region.TryStart, out var tryStart)
                || region.HandlerStart is null || !indices.TryGetValue(region.HandlerStart, out var handlerStart))
            { Fail(); return; }
            var tryEnd = region.TryEnd is null ? body.Instructions.Count : (indices.TryGetValue(region.TryEnd, out var te) ? te : -1);
            var handlerEnd = region.HandlerEnd is null ? body.Instructions.Count : (indices.TryGetValue(region.HandlerEnd, out var he) ? he : -1);
            if (tryEnd <= tryStart || handlerEnd <= handlerStart) { Fail(); return; }
            // A try region and its own handler must be disjoint.
            if (!(tryEnd <= handlerStart || handlerEnd <= tryStart)) { Fail(); return; }
            if (region.HandlerType == ExceptionHandlerType.Filter)
            {
                if (region.FilterStart is null || !indices.TryGetValue(region.FilterStart, out var filterStart)) { Fail(); return; }
                if (filterStart >= handlerStart || !(tryEnd <= filterStart || handlerStart <= tryStart)) { Fail(); return; }
                pending.Enqueue((region.FilterStart, 1));
            }
            else if (region.FilterStart is not null) { Fail(); return; }
            regions.Add((tryStart, tryEnd, handlerStart, handlerEnd));
            pending.Enqueue((region.HandlerStart, region.HandlerType is ExceptionHandlerType.Catch or ExceptionHandlerType.Filter ? 1 : 0));
        }
        for (var i = 0; i < regions.Count; i++)
        {
            for (var j = i + 1; j < regions.Count; j++)
            {
                if (PartiallyOverlaps(regions[i].TryStart, regions[i].TryEnd, regions[j].TryStart, regions[j].TryEnd)
                    || PartiallyOverlaps(regions[i].HandlerStart, regions[i].HandlerEnd, regions[j].HandlerStart, regions[j].HandlerEnd))
                    Fail();
            }
        }
        foreach (var instruction in body.Instructions)
        {
            if (instruction.Operand is Instruction target && !indices.ContainsKey(target)) Fail();
            if (instruction.Operand is Instruction[] targets && targets.Any(t => !indices.ContainsKey(t))) Fail();
        }
        while (pending.TryDequeue(out var item))
        {
            var (instruction, height) = item;
            if (height > body.MaxStackSize) Fail();
            if (heights.TryGetValue(instruction, out var previous)) { if (previous != height) Fail(); continue; }
            heights.Add(instruction, height);
            if (instruction.OpCode.Code == Code.Jmp)
            {
                if (height != 0) Fail();
                continue;
            }
            var pop = PopCount(method, instruction, height);
            if (height < pop) Fail();
            var next = checked(height - pop + PushCount(instruction));
            if (next > ushort.MaxValue || next > body.MaxStackSize) Fail();
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

    private static bool PartiallyOverlaps(int aStart, int aEnd, int bStart, int bEnd) =>
        (aStart < bStart && bStart < aEnd && aEnd < bEnd)
        || (bStart < aStart && aStart < bEnd && bEnd < aEnd);

    private enum StackKind { Unknown, Int32, Int64, NativeInt, Float, Object, Pointer, Value }
    internal static TypeReference StackType(TypeReference type)
    {
        while (type is RequiredModifierType or OptionalModifierType or PinnedType or SentinelType) type = ((TypeSpecification)type).ElementType;
        return type;
    }
    internal static bool IsVoid(TypeReference type) => StackType(type).MetadataType == MetadataType.Void;
    private static StackKind Kind(TypeReference type) => KindCore(StackType(type));
    private static StackKind KindCore(TypeReference type) => type.MetadataType switch
    {
        MetadataType.Boolean or MetadataType.Char or MetadataType.SByte or MetadataType.Byte or MetadataType.Int16 or MetadataType.UInt16 or MetadataType.Int32 or MetadataType.UInt32 => StackKind.Int32,
        MetadataType.Int64 or MetadataType.UInt64 => StackKind.Int64,
        // Per ECMA-335 III.1.1, unmanaged pointers and function pointers have
        // evaluation-stack category native int, distinct from managed byrefs (&).
        MetadataType.IntPtr or MetadataType.UIntPtr or MetadataType.Pointer or MetadataType.FunctionPointer => StackKind.NativeInt,
        MetadataType.Single or MetadataType.Double => StackKind.Float,
        MetadataType.ByReference => StackKind.Pointer,
        MetadataType.String or MetadataType.Object or MetadataType.Class or MetadataType.Array => StackKind.Object,
        MetadataType.ValueType => type is TypeDefinition definition
            ? (definition.IsEnum
                ? (definition.Fields.FirstOrDefault(f => !f.IsStatic) is { } valueField ? Kind(valueField.FieldType) : StackKind.Unknown)
                : StackKind.Value)
            : StackKind.Unknown,
        MetadataType.GenericInstance => type.IsValueType ? StackKind.Unknown : StackKind.Object,
        _ => StackKind.Unknown
    };
    internal static string VerificationStatus(MethodDefinition method)
    {
        if (!method.HasBody) return "no-il-body";
        bool Nominal(TypeReference type) => !IsVoid(type)
            && (StackType(type).MetadataType is MetadataType.Pointer or MetadataType.FunctionPointer
                || Kind(type) is StackKind.Unknown or StackKind.Object or StackKind.Value or StackKind.Pointer);
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
        bool hasImplicitThis = method.HasThis && !method.ExplicitThis;
        while (queue.TryDequeue(out var item))
        {
            var (instruction, stack) = item;
            if (states.TryGetValue(instruction, out var known))
            {
                if (known.Length != stack.Length) Fail();
                var changed = false;
                for (var i = 0; i < stack.Length; i++)
                {
                    var merged = MergeKinds(known[i], stack[i]);
                    if (merged != known[i]) { known[i] = merged; changed = true; }
                }
                if (!changed) continue;
                stack = known;
            }
            else states.Add(instruction, stack.ToArray());
            if (instruction.OpCode.Code == Code.Jmp) continue;
            var pop = PopCount(method, instruction, stack.Length); var pushes = PushCount(instruction);
            var top = stack.Length == 0 ? StackKind.Unknown : stack[^1];
            ValidateOperands(instruction, stack);
            var result = StackKind.Unknown;
            if (ManagedTransforms.Integer(instruction, out _)) result = StackKind.Int32;
            else if (instruction.OpCode.Code is Code.Ldarg or Code.Ldarg_S or Code.Ldarg_0 or Code.Ldarg_1 or Code.Ldarg_2 or Code.Ldarg_3)
            {
                var index = ArgIndex(method, instruction, hasImplicitThis);
                result = hasImplicitThis && index == 0 ? (method.DeclaringType.IsValueType ? StackKind.Pointer : StackKind.Object)
                    : Kind(method.Parameters[index - (hasImplicitThis ? 1 : 0)].ParameterType);
            }
            else if (instruction.OpCode.Code is Code.Ldarga or Code.Ldarga_S)
            {
                _ = ArgIndex(method, instruction, hasImplicitThis);
                result = StackKind.Pointer;
            }
            else if (instruction.OpCode.Code is Code.Ldloc or Code.Ldloc_S or Code.Ldloc_0 or Code.Ldloc_1 or Code.Ldloc_2 or Code.Ldloc_3)
                result = Kind(Local(method, instruction).VariableType);
            else if (instruction.OpCode.Code is Code.Ldloca or Code.Ldloca_S)
            {
                _ = Local(method, instruction);
                result = StackKind.Pointer;
            }
            else if (instruction.OpCode.Code is Code.Stloc or Code.Stloc_S or Code.Stloc_0 or Code.Stloc_1 or Code.Stloc_2 or Code.Stloc_3)
                Compatible(Kind(Local(method, instruction).VariableType), top);
            else if (instruction.OpCode.Code is Code.Starg or Code.Starg_S)
            {
                var index = ArgIndex(method, instruction, hasImplicitThis);
                var targetKind = hasImplicitThis && index == 0 ? (method.DeclaringType.IsValueType ? StackKind.Pointer : StackKind.Object)
                    : Kind(method.Parameters[index - (hasImplicitThis ? 1 : 0)].ParameterType);
                Compatible(targetKind, top);
            }
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
                Code.Ldelema or Code.Unbox or Code.Refanyval => StackKind.Pointer,
                Code.Ldlen or Code.Ldftn or Code.Ldvirtftn or Code.Conv_I or Code.Conv_U or Code.Conv_Ovf_I or Code.Conv_Ovf_I_Un or Code.Conv_Ovf_U or Code.Conv_Ovf_U_Un or Code.Localloc or Code.Ldind_I or Code.Ldelem_I => StackKind.NativeInt,
                Code.Conv_I1 or Code.Conv_I2 or Code.Conv_I4 or Code.Conv_U1 or Code.Conv_U2 or Code.Conv_U4 or Code.Conv_Ovf_I1 or Code.Conv_Ovf_I1_Un or Code.Conv_Ovf_I2 or Code.Conv_Ovf_I2_Un or Code.Conv_Ovf_I4 or Code.Conv_Ovf_I4_Un
                    or Code.Conv_Ovf_U1 or Code.Conv_Ovf_U1_Un or Code.Conv_Ovf_U2 or Code.Conv_Ovf_U2_Un or Code.Conv_Ovf_U4 or Code.Conv_Ovf_U4_Un or Code.Ceq or Code.Cgt or Code.Cgt_Un or Code.Clt or Code.Clt_Un or Code.Sizeof
                    or Code.Ldind_I1 or Code.Ldind_U1 or Code.Ldind_I2 or Code.Ldind_U2 or Code.Ldind_I4 or Code.Ldind_U4 or Code.Ldelem_I1 or Code.Ldelem_U1 or Code.Ldelem_I2 or Code.Ldelem_U2 or Code.Ldelem_I4 or Code.Ldelem_U4 => StackKind.Int32,
                Code.Dup or Code.Neg or Code.Not => top,
                Code.Ldobj or Code.Unbox_Any or Code.Ldelem_Any => Kind((TypeReference)instruction.Operand),
                Code.Add or Code.Add_Ovf or Code.Add_Ovf_Un or Code.Sub or Code.Sub_Ovf or Code.Sub_Ovf_Un => AddResult(instruction.OpCode.Code, stack),
                Code.Mul or Code.Mul_Ovf or Code.Mul_Ovf_Un or Code.Div or Code.Div_Un or Code.Rem or Code.Rem_Un or Code.And or Code.Or or Code.Xor => BinaryResult(stack),
                Code.Shl or Code.Shr or Code.Shr_Un => stack.Length > 1 ? stack[^2] : StackKind.Unknown,
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
    private static StackKind MergeKinds(StackKind existing, StackKind incoming)
    {
        if (existing == incoming) return existing;
        if (existing == StackKind.Unknown || incoming == StackKind.Unknown) return StackKind.Unknown;
        if ((existing == StackKind.Int32 && incoming == StackKind.NativeInt)
            || (existing == StackKind.NativeInt && incoming == StackKind.Int32))
            return StackKind.NativeInt;
        ManagedPreflight.Fail("MANAGED_STACK_TYPE", "A method has incompatible evaluation-stack categories.");
        return StackKind.Unknown;
    }
    private static StackKind BinaryResult(StackKind[] stack)
    {
        var left = stack[^2]; var right = stack[^1];
        if (left == StackKind.Unknown || right == StackKind.Unknown) return StackKind.Unknown;
        return left == StackKind.NativeInt || right == StackKind.NativeInt ? StackKind.NativeInt : left;
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
            // Per ECMA-335 Table III.2, Add_Ovf_Un and Sub_Ovf_Un permit managed pointers
            // with int32/native int offsets (and pointer - pointer for Sub_Ovf_Un).
            if (code is Code.Add_Ovf or Code.Sub_Ovf or Code.Mul_Ovf or Code.Mul_Ovf_Un or Code.Div_Un or Code.Rem_Un)
            { Require(left, StackKind.Int32, StackKind.Int64, StackKind.NativeInt); Require(right, StackKind.Int32, StackKind.Int64, StackKind.NativeInt); }
            else if (code is Code.Add_Ovf_Un or Code.Sub_Ovf_Un)
            { Require(left, StackKind.Int32, StackKind.Int64, StackKind.NativeInt, StackKind.Pointer); Require(right, StackKind.Int32, StackKind.Int64, StackKind.NativeInt, StackKind.Pointer); }
            if (left == StackKind.Pointer && right == StackKind.Pointer && code is Code.Add or Code.Add_Ovf_Un
                || right == StackKind.Pointer && left != StackKind.Pointer && left != StackKind.Unknown && code is Code.Sub or Code.Sub_Ovf_Un)
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
        else if (instruction.Operand is MethodReference method && method.HasThis && !method.ExplicitThis && code is Code.Call or Code.Callvirt)
            Require(stack[stack.Length - method.Parameters.Count - 1], StackKind.Object, StackKind.Pointer, StackKind.NativeInt);
    }
    private static int ArgIndex(MethodDefinition method, Instruction instruction, bool hasImplicitThis)
    {
        int index;
        switch (instruction.OpCode.Code)
        {
            case Code.Ldarg_0: index = 0; break;
            case Code.Ldarg_1: index = 1; break;
            case Code.Ldarg_2: index = 2; break;
            case Code.Ldarg_3: index = 3; break;
            default:
                if (instruction.Operand is not ParameterDefinition parameter) { Fail(); return 0; }
                index = parameter.Index + (hasImplicitThis ? 1 : 0);
                break;
        }
        int total = method.Parameters.Count + (hasImplicitThis ? 1 : 0);
        if (index < 0 || index >= total) Fail();
        return index;
    }
    private static VariableDefinition Local(MethodDefinition method, Instruction instruction)
    {
        int index = instruction.OpCode.Code switch
        {
            Code.Ldloc_0 or Code.Stloc_0 => 0,
            Code.Ldloc_1 or Code.Stloc_1 => 1,
            Code.Ldloc_2 or Code.Stloc_2 => 2,
            Code.Ldloc_3 or Code.Stloc_3 => 3,
            _ => instruction.Operand is VariableDefinition variable ? variable.Index : -1
        };
        if (index < 0 || index >= method.Body.Variables.Count) Fail();
        return method.Body.Variables[index];
    }
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
        StackBehaviour.Varpop when instruction.Operand is MethodReference callee => callee.Parameters.Count + (callee.HasThis && !callee.ExplicitThis && instruction.OpCode.Code != Code.Newobj ? 1 : 0),
        StackBehaviour.Varpop when instruction.Operand is CallSite site => site.Parameters.Count + (site.HasThis && !site.ExplicitThis ? 1 : 0) + 1,
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
