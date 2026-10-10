using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Rampart.Managed;

// This analysis is deliberately independent of layout. In particular, a loop's
// back edge must agree with its first entry before either transform can mutate IL.
internal static class ManagedFlowAnalysis
{
    internal static bool TryHeights(MethodDefinition method, out Dictionary<Instruction, int> heights, out int maximum)
    {
        heights = new(); maximum = 0;
        var instructions = method.Body.Instructions;
        if (instructions.Count == 0 || method.Body.HasExceptionHandlers) return false;
        var owned = instructions.ToHashSet();
        var pending = new Queue<(Instruction Instruction, int Height)>();
        pending.Enqueue((instructions[0], 0));
        while (pending.TryDequeue(out var item))
        {
            if (!owned.Contains(item.Instruction)) return false;
            if (heights.TryGetValue(item.Instruction, out var known))
            { if (known != item.Height) return false; continue; }
            heights.Add(item.Instruction, item.Height);
            if (!Effect(method, item.Instruction, out var pop, out var push) || item.Height < pop) return false;
            var next = item.Height - pop + push;
            maximum = Math.Max(maximum, next);
            if (next > ushort.MaxValue) return false;
            if (item.Instruction.Operand is Instruction target) pending.Enqueue((target, next));
            if (item.Instruction.Operand is Instruction[] targets)
                foreach (var destination in targets) pending.Enqueue((destination, next));
            if (item.Instruction.OpCode.FlowControl is FlowControl.Return or FlowControl.Throw)
            { if (next != 0) return false; continue; }
            if (item.Instruction.OpCode.FlowControl == FlowControl.Branch) continue;
            if (item.Instruction.Next is null) return false;
            pending.Enqueue((item.Instruction.Next, next));
        }
        // Keeping unreachable instructions in a reordered body requires separate
        // lexical-region reasoning. Leave that uncommon shape intact for now.
        return heights.Count == instructions.Count;
    }

    internal static bool Effect(MethodDefinition method, Instruction instruction, out int pop, out int push)
    {
        pop = instruction.OpCode.StackBehaviourPop switch
        {
            StackBehaviour.Pop0 => 0,
            StackBehaviour.Pop1 or StackBehaviour.Popi or StackBehaviour.Popref => 1,
            StackBehaviour.Pop1_pop1 or StackBehaviour.Popi_pop1 or StackBehaviour.Popi_popi or StackBehaviour.Popi_popi8
                or StackBehaviour.Popi_popr4 or StackBehaviour.Popi_popr8 or StackBehaviour.Popref_pop1 or StackBehaviour.Popref_popi => 2,
            StackBehaviour.Popi_popi_popi or StackBehaviour.Popref_popi_popi or StackBehaviour.Popref_popi_popi8
                or StackBehaviour.Popref_popi_popr4 or StackBehaviour.Popref_popi_popr8 or StackBehaviour.Popref_popi_popref => 3,
            StackBehaviour.Varpop when instruction.OpCode.Code == Code.Ret => method.ReturnType.MetadataType == MetadataType.Void ? 0 : 1,
            StackBehaviour.Varpop when instruction.Operand is MethodReference called => called.Parameters.Count + (called.HasThis && instruction.OpCode.Code != Code.Newobj ? 1 : 0),
            _ => -1
        };
        push = instruction.OpCode.StackBehaviourPush switch
        {
            StackBehaviour.Push0 => 0,
            StackBehaviour.Push1 or StackBehaviour.Pushi or StackBehaviour.Pushi8 or StackBehaviour.Pushr4 or StackBehaviour.Pushr8 or StackBehaviour.Pushref => 1,
            StackBehaviour.Push1_push1 => 2,
            StackBehaviour.Varpush when instruction.Operand is MethodReference called => called.ReturnType.MetadataType == MetadataType.Void ? 0 : 1,
            _ => -1
        };
        return pop >= 0 && push >= 0;
    }
}
