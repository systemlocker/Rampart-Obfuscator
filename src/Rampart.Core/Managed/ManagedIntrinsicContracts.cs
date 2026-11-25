using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Rampart.Managed;

internal static class ManagedIntrinsicContracts
{
    internal static Dictionary<Instruction, string> Constants(IEnumerable<MethodDefinition> methods)
    {
        var preserved = new Dictionary<Instruction, string>();
        foreach (var method in methods.Where(method => method.HasBody))
        {
            var boundaries = method.Body.Instructions.SelectMany(instruction => instruction.Operand switch
            { Instruction target => new[] { target }, Instruction[] targets => targets, _ => [] }).ToHashSet();
            foreach (var region in method.Body.ExceptionHandlers)
            { boundaries.Add(region.HandlerStart); if (region.FilterStart is { } filter) boundaries.Add(filter); boundaries.Add(region.TryStart); }
            var stack = new List<Instruction?>();
            Instruction? Pop() { if (stack.Count == 0) return null; var top = stack[^1]; stack.RemoveAt(stack.Count - 1); return top; }

            foreach (var instruction in method.Body.Instructions)
            {
                if (boundaries.Contains(instruction)) stack.Clear();

                // NativeAOT 8 recognizes the compiler's literal-array initialization
                // sequence before constant folding. Hiding the newarr length can
                // leave a call to InitializeArray's unsupported runtime fallback.
                // Keep only this length operand, not every constant in the method.
                if (ManagedTransforms.Integer(instruction, out _)
                    && instruction.Next?.OpCode.Code == Code.Newarr
                    && instruction.Next.Next?.OpCode.Code == Code.Dup
                    && instruction.Next.Next.Next?.OpCode.Code == Code.Ldtoken
                    && instruction.Next.Next.Next.Operand is FieldReference
                    && instruction.Next.Next.Next.Next is { OpCode.Code: Code.Call, Operand: MethodReference initCall }
                    && initCall.DeclaringType.FullName == "System.Runtime.CompilerServices.RuntimeHelpers"
                    && initCall.Name == "InitializeArray" && initCall.Parameters.Count == 2)
                {
                    preserved.TryAdd(instruction, "constants:runtime-array-initializer");
                }

                // Hardware intrinsics (System.Runtime.Intrinsics.*) require compile-time
                // constant immediates for [ConstantExpected] parameters. Preserve integer
                // literals flowing directly into any intrinsic call in this basic block.
                var code = instruction.OpCode.Code;
                if (ManagedTransforms.Integer(instruction, out _))
                {
                    stack.Add(instruction);
                }
                else if (code == Code.Dup)
                {
                    var top = Pop(); stack.Add(top); stack.Add(top);
                }
                else if (code is Code.Conv_I1 or Code.Conv_U1 or Code.Conv_I2 or Code.Conv_U2 or Code.Conv_I4 or Code.Conv_U4
                    or Code.Conv_Ovf_I1 or Code.Conv_Ovf_U1 or Code.Conv_Ovf_I2 or Code.Conv_Ovf_U2 or Code.Conv_Ovf_I4 or Code.Conv_Ovf_U4
                    or Code.Conv_Ovf_I1_Un or Code.Conv_Ovf_U1_Un or Code.Conv_Ovf_I2_Un or Code.Conv_Ovf_U2_Un or Code.Conv_Ovf_I4_Un or Code.Conv_Ovf_U4_Un)
                {
                    var top = Pop(); stack.Add(top);
                }
                else if (instruction.Operand is MethodReference callee && code is Code.Call or Code.Callvirt or Code.Newobj)
                {
                    var isIntrinsic = ManagedPolicy.EffectiveNamespace(callee.DeclaringType)
                        .StartsWith("System.Runtime.Intrinsics", StringComparison.Ordinal);
                    for (var i = 0; i < callee.Parameters.Count; i++)
                    {
                        var arg = Pop();
                        if (isIntrinsic && arg is not null)
                            preserved.TryAdd(arg, "constants:hardware-intrinsic-immediate");
                    }
                    if (callee.HasThis && !callee.ExplicitThis && code != Code.Newobj) _ = Pop();
                    if (code == Code.Newobj || !ManagedIlVerifier.IsVoid(callee.ReturnType)) stack.Add(null);
                }
                else
                {
                    var pop = instruction.OpCode.StackBehaviourPop switch
                    {
                        StackBehaviour.Pop0 => 0,
                        StackBehaviour.Pop1 or StackBehaviour.Popi or StackBehaviour.Popref => 1,
                        StackBehaviour.Pop1_pop1 or StackBehaviour.Popi_pop1 or StackBehaviour.Popi_popi or StackBehaviour.Popi_popi8
                            or StackBehaviour.Popi_popr4 or StackBehaviour.Popi_popr8 or StackBehaviour.Popref_pop1 or StackBehaviour.Popref_popi => 2,
                        StackBehaviour.Popi_popi_popi or StackBehaviour.Popref_popi_popi or StackBehaviour.Popref_popi_popi8
                            or StackBehaviour.Popref_popi_popr4 or StackBehaviour.Popref_popi_popr8 or StackBehaviour.Popref_popi_popref => 3,
                        StackBehaviour.PopAll => stack.Count,
                        StackBehaviour.Varpop when code == Code.Ret => ManagedIlVerifier.IsVoid(method.ReturnType) ? 0 : 1,
                        StackBehaviour.Varpop when instruction.Operand is CallSite site => site.Parameters.Count + (site.HasThis && !site.ExplicitThis ? 1 : 0) + 1,
                        _ => stack.Count
                    };
                    for (var i = 0; i < pop; i++) _ = Pop();
                    var push = instruction.OpCode.StackBehaviourPush switch
                    {
                        StackBehaviour.Push0 => 0,
                        StackBehaviour.Push1_push1 => 2,
                        StackBehaviour.Varpush => instruction.Operand is CallSite site && !ManagedIlVerifier.IsVoid(site.ReturnType) ? 1 : 0,
                        _ => 1
                    };
                    for (var i = 0; i < push; i++) stack.Add(null);
                }
                if (instruction.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch or FlowControl.Return or FlowControl.Throw || code == Code.Jmp)
                    stack.Clear();
            }
        }
        return preserved;
    }
}
