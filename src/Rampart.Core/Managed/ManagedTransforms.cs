using System.Security.Cryptography;
using System.Text;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Rampart.Managed;

internal static class ManagedTransforms
{
    internal static int Key(long seed, string identity, int site)
        => BitConverter.ToInt32(SHA256.HashData(Encoding.UTF8.GetBytes($"{seed}|{identity}|{site}")), 0);

    internal static bool Integer(Instruction instruction, out int value)
    {
        value = instruction.OpCode.Code switch
        {
            Code.Ldc_I4_M1 => -1,
            Code.Ldc_I4_0 => 0,
            Code.Ldc_I4_1 => 1,
            Code.Ldc_I4_2 => 2,
            Code.Ldc_I4_3 => 3,
            Code.Ldc_I4_4 => 4,
            Code.Ldc_I4_5 => 5,
            Code.Ldc_I4_6 => 6,
            Code.Ldc_I4_7 => 7,
            Code.Ldc_I4_8 => 8,
            Code.Ldc_I4_S => (sbyte)instruction.Operand,
            Code.Ldc_I4 => (int)instruction.Operand,
            _ => 0
        };
        return instruction.OpCode.Code is >= Code.Ldc_I4_M1 and <= Code.Ldc_I4;
    }

    internal static void ExpandBranches(MethodDefinition method)
    {
        foreach (var instruction in method.Body.Instructions)
            instruction.OpCode = instruction.OpCode.Code switch
            {
                Code.Br_S => OpCodes.Br,
                Code.Brfalse_S => OpCodes.Brfalse,
                Code.Brtrue_S => OpCodes.Brtrue,
                Code.Beq_S => OpCodes.Beq,
                Code.Bge_S => OpCodes.Bge,
                Code.Bgt_S => OpCodes.Bgt,
                Code.Ble_S => OpCodes.Ble,
                Code.Blt_S => OpCodes.Blt,
                Code.Bne_Un_S => OpCodes.Bne_Un,
                Code.Bge_Un_S => OpCodes.Bge_Un,
                Code.Bgt_Un_S => OpCodes.Bgt_Un,
                Code.Ble_Un_S => OpCodes.Ble_Un,
                Code.Blt_Un_S => OpCodes.Blt_Un,
                Code.Leave_S => OpCodes.Leave,
                _ => instruction.OpCode
            };
    }

    internal static int Constants(MethodDefinition method, long seed, string id, Func<Instruction, bool>? eligible = null)
    {
        var il = method.Body.GetILProcessor(); var count = 0;
        foreach (var instruction in method.Body.Instructions.ToArray())
        {
            if (!Integer(instruction, out var value) || eligible is not null && !eligible(instruction)) continue;
            var key = Key(seed, id, count++);
            instruction.OpCode = OpCodes.Ldc_I4;
            instruction.Operand = value ^ key;
            var mask = Instruction.Create(OpCodes.Ldc_I4, key);
            il.InsertAfter(instruction, mask);
            il.InsertAfter(mask, Instruction.Create(OpCodes.Xor));
        }
        return count;
    }

    internal static int Strings(MethodDefinition method, MethodDefinition helper, MemoryStream resource, string resourceName, long seed, string id, Func<Instruction, bool>? eligible = null)
    {
        var il = method.Body.GetILProcessor(); var count = 0;
        foreach (var instruction in method.Body.Instructions.ToArray())
        {
            if (instruction.OpCode.Code != Code.Ldstr || eligible is not null && !eligible(instruction)) continue;
            var value = (string)instruction.Operand;
            // ldstr may legally contain unpaired UTF-16 surrogates. Encoding replacement
            // fallbacks would change their values, so preserve the code units directly.
            var bytes = new byte[value.Length * 2];
            for (var i = 0; i < value.Length; i++) { bytes[i * 2] = (byte)value[i]; bytes[i * 2 + 1] = (byte)(value[i] >> 8); }
            var offset = checked((int)resource.Length);
            var key = Key(seed, id, count++);
            for (var i = 0; i < bytes.Length; i++) bytes[i] ^= (byte)(key + i * 31);
            resource.Write(bytes);
            var cache = new FieldDefinition("s_" + offset + "_" + helper.DeclaringType.Fields.Count,
                FieldAttributes.Assembly | FieldAttributes.Static, method.Module.TypeSystem.String);
            helper.DeclaringType.Fields.Add(cache);
            instruction.Operand = resourceName;
            var previous = instruction;
            foreach (var next in new[] { Instruction.Create(OpCodes.Ldc_I4, offset), Instruction.Create(OpCodes.Ldc_I4, bytes.Length),
                Instruction.Create(OpCodes.Ldc_I4, key), Instruction.Create(OpCodes.Ldsflda, cache), Instruction.Create(OpCodes.Call, helper) })
            { il.InsertAfter(previous, next); previous = next; }
        }
        return count;
    }

    internal static bool ControlFlow(MethodDefinition method, long seed, string id)
    {
        var body = method.Body;
        if (method.IsConstructor || body.HasExceptionHandlers || body.Instructions.Count < 3
            || body.Variables.Any(variable => variable.VariableType.IsByReference || variable.VariableType.IsPointer)
            || body.Instructions.Any(instruction => instruction.OpCode.OpCodeType == OpCodeType.Prefix
                || instruction.OpCode.Code is Code.Calli or Code.Jmp or Code.Localloc or Code.Leave or Code.Leave_S)
            || !ManagedFlowAnalysis.TryHeights(method, out var heights, out _)) return false;

        var original = body.Instructions.ToArray();
        var blocks = new List<List<Instruction>>();
        var entries = new Dictionary<Instruction, Instruction>();
        var spills = new List<VariableDefinition>();
        if (ManagedIntegerProgram.TryLift(method, out var integer))
        {
            // Integer instructions can be split even when their original edges
            // carried values. Typed spills make every permuted edge stack-empty,
            // including loop back edges and ternary-expression merge points.
            for (var slot = 0; slot < integer!.MaximumStack; slot++) spills.Add(new(method.Module.TypeSystem.Int32));
            foreach (var instruction in original)
            {
                ManagedFlowAnalysis.Effect(method, instruction, out var pop, out var push);
                var height = heights[instruction];
                var block = new List<Instruction>();
                for (var slot = height - pop; slot < height; slot++) block.Add(Instruction.Create(OpCodes.Ldloc, spills[slot]));
                block.Add(instruction);
                for (var slot = height - pop + push - 1; slot >= height - pop; slot--) block.Add(Instruction.Create(OpCodes.Stloc, spills[slot]));
                entries.Add(instruction, block[0]); blocks.Add(block);
            }
        }
        else
        {
            // Calls, instance members, generics and wider numeric operations keep
            // their exact instruction sequences inside blocks. Only empty-stack
            // boundaries may move; no object/byref/value-type spills are inferred.
            var leaders = new HashSet<Instruction> { original[0] };
            foreach (var instruction in original)
            {
                if (instruction.Operand is Instruction target) leaders.Add(target);
                if (instruction.Operand is Instruction[] targets) foreach (var destination in targets) leaders.Add(destination);
                if (instruction.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch or FlowControl.Return or FlowControl.Throw
                    && instruction.Next is not null) leaders.Add(instruction.Next);
                if (heights[instruction] == 0) leaders.Add(instruction);
            }
            if (leaders.Any(instruction => heights[instruction] != 0)) return false;
            List<Instruction>? current = null;
            foreach (var instruction in original)
            {
                if (leaders.Contains(instruction)) { current = []; blocks.Add(current); entries.Add(instruction, instruction); }
                current!.Add(instruction);
            }
            if (blocks.Count < 2) return false;
        }

        // Everything above is an admission/planning pass. Rejected bodies have
        // not acquired locals, new edges, changed operands or debug scopes.
        ExpandBranches(method);
        foreach (var variable in spills) body.Variables.Add(variable);
        if (spills.Count > 0) body.InitLocals = true;
        foreach (var instruction in original)
        {
            if (instruction.Operand is Instruction target) instruction.Operand = entries[target];
            else if (instruction.Operand is Instruction[] targets) instruction.Operand = targets.Select(target => entries[target]).ToArray();
        }
        for (var index = 0; index < blocks.Count - 1; index++)
            if (blocks[index][^1].OpCode.FlowControl is not (FlowControl.Branch or FlowControl.Return or FlowControl.Throw))
                blocks[index].Add(Instruction.Create(OpCodes.Br, blocks[index + 1][0]));
        body.Instructions.Clear();
        body.Instructions.Add(Instruction.Create(OpCodes.Br, blocks[0][0]));
        foreach (var block in blocks.Select((block, index) => (block, key: Key(seed, id, index))).OrderBy(pair => pair.key))
            foreach (var instruction in block.block) body.Instructions.Add(instruction);
        var offset = 0;
        foreach (var instruction in body.Instructions) { instruction.Offset = offset; offset += instruction.GetSize(); }
        var points = method.DebugInformation.SequencePoints.OrderBy(point => point.Offset).ToArray();
        method.DebugInformation.SequencePoints.Clear();
        foreach (var point in points) method.DebugInformation.SequencePoints.Add(point);
        method.DebugInformation.Scope = null;
        return true;
    }

    internal static bool Virtualize(MethodDefinition method, MethodDefinition helper, long seed, string id)
    {
        if (!ManagedIntegerProgram.TryLift(method, out var program)) return false;
        if (ManagedExpressionVm.TryVirtualize(method, helper, program!, seed, id)) return true;
        var opcodeKey = (Key(seed, id, 0) & 65535) | 1;
        var encoded = program!.Encode(method.Body.Variables.Count, opcodeKey);
        method.Body.Instructions.Clear(); method.Body.Variables.Clear();
        method.DebugInformation.SequencePoints.Clear(); method.DebugInformation.Scope = null;
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldstr, encoded); il.Emit(OpCodes.Ldc_I4, opcodeKey);
        // Ordinary signatures pass scalar arguments directly. The array fallback
        // preserves support for the original 255-argument admission boundary.
        for (var index = 0; index < 8; index++)
        {
            if (index < method.Parameters.Count) il.Emit(OpCodes.Ldarg, method.Parameters[index]);
            else il.Emit(OpCodes.Ldc_I4_0);
        }
        if (method.Parameters.Count <= 8) il.Emit(OpCodes.Ldnull);
        else
        {
            il.Emit(OpCodes.Ldc_I4, method.Parameters.Count); il.Emit(OpCodes.Newarr, method.Module.TypeSystem.Int32);
            foreach (var parameter in method.Parameters)
            { il.Emit(OpCodes.Dup); il.Emit(OpCodes.Ldc_I4, parameter.Index); il.Emit(OpCodes.Ldarg, parameter); il.Emit(OpCodes.Stelem_I4); }
        }
        il.Emit(OpCodes.Call, helper); il.Emit(OpCodes.Ret);
        return true;
    }
}
