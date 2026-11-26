using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Rampart.Managed;

/// <summary>
/// Replaces common Boolean/int32 decision branches with per-site, seeded dispatch.
/// This deliberately has a narrower admission contract than full CFG permutation,
/// so it can still harden compiler-generated async methods and exception regions.
/// </summary>
internal sealed class ManagedDecisionGuards
{
    private const int DispatchSlots = 16;
    private const int MaximumSitesPerMethod = 64;

    private readonly ModuleDefinition _module;
    private readonly long _seed;
    private TypeDefinition? _helperType;
    private int _helperCount;

    internal ManagedDecisionGuards(ModuleDefinition module, long seed)
    {
        _module = module;
        _seed = seed;
    }

    internal int Apply(MethodDefinition method, string identity)
    {
        if (!method.HasBody || method.Body.Instructions.Count < 2)
            return 0;

        Instruction[] original = method.Body.Instructions.ToArray();
        var protectedBoundaries = ExceptionBoundaries(method);
        var inbound = BranchTargets(original);
        var il = method.Body.GetILProcessor();
        int count = 0;

        foreach (Instruction branch in original)
        {
            if (count == MaximumSitesPerMethod || branch.Next is null
                || branch.Operand is not Instruction target || target == branch.Next
                || protectedBoundaries.Contains(branch) || inbound.Contains(branch))
            {
                continue;
            }

            bool takenWhenOne;
            bool normalizeOneOperand;
            if (branch.OpCode.Code is Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S)
            {
                Instruction? producer = PreviousMeaningful(branch);
                if (producer is null || !ProducesBooleanLikeValue(method, producer))
                    continue;
                takenWhenOne = branch.OpCode.Code is Code.Brtrue or Code.Brtrue_S;
                normalizeOneOperand = true;
            }
            else if (branch.OpCode.Code is Code.Beq or Code.Beq_S or Code.Bne_Un or Code.Bne_Un_S)
            {
                Instruction? right = PreviousMeaningful(branch);
                Instruction? left = right is null ? null : PreviousMeaningful(right);
                if (left is null || right is null || !IsZeroOrOne(left) && !IsZeroOrOne(right))
                    continue;
                Instruction value = IsZeroOrOne(left) ? right : left;
                if (!ProducesBooleanLikeValue(method, value))
                    continue;
                // ceq below normalizes either literal comparison to equality=1.
                // The original branch only determines which normalized value jumps.
                takenWhenOne = branch.OpCode.Code is Code.Beq or Code.Beq_S;
                normalizeOneOperand = false;
            }
            else
            {
                continue;
            }

            MethodDefinition helper = CreateHelper(identity, branch.Offset, count, out int zeroSlot, out int oneSlot);
            if (normalizeOneOperand)
            {
                // brtrue/brfalse accept any non-zero int32. Two equality steps
                // normalize that exact rule to 0/1 before the seeded dispatcher.
                il.InsertBefore(branch, Instruction.Create(OpCodes.Ldc_I4_0));
                il.InsertBefore(branch, Instruction.Create(OpCodes.Ceq));
                il.InsertBefore(branch, Instruction.Create(OpCodes.Ldc_I4_0));
                il.InsertBefore(branch, Instruction.Create(OpCodes.Ceq));
            }
            else
            {
                // Equality branches already have both operands on the stack.
                il.InsertBefore(branch, Instruction.Create(OpCodes.Ceq));
            }
            il.InsertBefore(branch, Instruction.Create(OpCodes.Call, helper));

            Instruction fallthrough = branch.Next;
            var destinations = Enumerable.Repeat(fallthrough, DispatchSlots).ToArray();
            destinations[zeroSlot] = takenWhenOne ? fallthrough : target;
            destinations[oneSlot] = takenWhenOne ? target : fallthrough;
            branch.OpCode = OpCodes.Switch;
            branch.Operand = destinations;
            count++;
        }

        if (count > 0)
        {
            method.Body.InitLocals = true;
            method.DebugInformation.Scope = null;
            ManagedIlVerifier.UpdateMaxStackSize(method);
        }
        return count;
    }

    private MethodDefinition CreateHelper(string identity, int offset, int site, out int zeroSlot, out int oneSlot)
    {
        TypeDefinition owner = EnsureHelperType(identity);
        int key = ManagedTransforms.Key(_seed, identity + "|decision", offset ^ site);
        int multiplier = ((key >> 8) & 7) * 2 + 1;
        int bias = key & (DispatchSlots - 1);
        zeroSlot = bias;
        oneSlot = (bias + multiplier) & (DispatchSlots - 1);

        var helper = new MethodDefinition(
            $"d_{_helperCount++:X4}",
            MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig,
            _module.TypeSystem.Int32)
        {
            // Keeping the arithmetic in a per-site helper prevents an ahead-of-time
            // optimizer from folding the dispatcher back into the original cmp/jcc.
            ImplAttributes = MethodImplAttributes.NoInlining | MethodImplAttributes.NoOptimization,
        };
        helper.Parameters.Add(new ParameterDefinition("decision", ParameterAttributes.None, _module.TypeSystem.Int32));
        ILProcessor il = helper.Body.GetILProcessor();
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Ldc_I4, multiplier);
        il.Emit(OpCodes.Mul);
        il.Emit(OpCodes.Ldc_I4, bias);
        il.Emit(OpCodes.Add);
        il.Emit(OpCodes.Ldc_I4, DispatchSlots - 1);
        il.Emit(OpCodes.And);
        il.Emit(OpCodes.Ret);
        ManagedIlVerifier.UpdateMaxStackSize(helper);
        ManagedIlVerifier.Validate(helper);
        owner.Methods.Add(helper);
        return helper;
    }

    private TypeDefinition EnsureHelperType(string identity)
    {
        if (_helperType is not null)
            return _helperType;
        string suffix = unchecked((uint)ManagedTransforms.Key(_seed, identity, 0)).ToString("X8");
        _helperType = new TypeDefinition(
            "",
            "<Rampart_Decisions_" + suffix + ">",
            TypeAttributes.NotPublic | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.BeforeFieldInit,
            _module.TypeSystem.Object);
        _module.Types.Add(_helperType);
        return _helperType;
    }

    private static HashSet<Instruction> BranchTargets(IEnumerable<Instruction> instructions)
    {
        var targets = new HashSet<Instruction>();
        foreach (Instruction instruction in instructions)
        {
            if (instruction.Operand is Instruction target)
                targets.Add(target);
            else if (instruction.Operand is Instruction[] multiple)
                foreach (Instruction candidate in multiple)
                    targets.Add(candidate);
        }
        return targets;
    }

    private static HashSet<Instruction> ExceptionBoundaries(MethodDefinition method)
    {
        var boundaries = new HashSet<Instruction>();
        foreach (ExceptionHandler region in method.Body.ExceptionHandlers)
        {
            boundaries.Add(region.TryStart);
            boundaries.Add(region.HandlerStart);
            if (region.TryEnd is not null) boundaries.Add(region.TryEnd);
            if (region.HandlerEnd is not null) boundaries.Add(region.HandlerEnd);
            if (region.FilterStart is not null) boundaries.Add(region.FilterStart);
        }
        return boundaries;
    }

    private static Instruction? PreviousMeaningful(Instruction instruction)
    {
        for (Instruction? current = instruction.Previous; current is not null; current = current.Previous)
            if (current.OpCode.Code != Code.Nop)
                return current;
        return null;
    }

    private static bool ProducesBooleanLikeValue(MethodDefinition owner, Instruction instruction)
    {
        if (instruction.OpCode.Code is Code.Ceq or Code.Cgt or Code.Cgt_Un or Code.Clt or Code.Clt_Un)
            return true;
        if (instruction.Operand is MethodReference method)
            return IsBooleanLike(method.ReturnType);
        if (instruction.Operand is FieldReference field)
            return IsBooleanLike(field.FieldType);
        if (instruction.Operand is VariableDefinition variable)
            return IsBooleanLike(variable.VariableType);
        if (instruction.Operand is ParameterDefinition parameter)
            return IsBooleanLike(parameter.ParameterType);
        if (instruction.OpCode.Code is >= Code.Ldloc_0 and <= Code.Ldloc_3)
        {
            int index = (int)instruction.OpCode.Code - (int)Code.Ldloc_0;
            return index < owner.Body.Variables.Count && IsBooleanLike(owner.Body.Variables[index].VariableType);
        }
        return IsZeroOrOne(instruction);
    }

    private static bool IsBooleanLike(TypeReference type) =>
        type.MetadataType is MetadataType.Boolean or MetadataType.Int32 or MetadataType.UInt32;

    private static bool IsZeroOrOne(Instruction instruction) =>
        ManagedTransforms.Integer(instruction, out int value) && value is 0 or 1;
}
