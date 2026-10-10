using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Rampart.Managed;

internal static class ManagedIntrinsicContracts
{
    internal static Dictionary<Instruction, string> Constants(IEnumerable<MethodDefinition> methods)
    {
        var preserved = new Dictionary<Instruction, string>();
        foreach (var method in methods.Where(method => method.HasBody))
            foreach (var instruction in method.Body.Instructions)
            {
                // NativeAOT 8 recognizes the compiler's literal-array initialization
                // sequence before constant folding. Hiding the newarr length can
                // leave a call to InitializeArray's unsupported runtime fallback.
                // Keep only this length operand, not every constant in the method.
                if (!ManagedTransforms.Integer(instruction, out _)
                    || instruction.Next?.OpCode.Code != Code.Newarr
                    || instruction.Next.Next?.OpCode.Code != Code.Dup
                    || instruction.Next.Next.Next?.OpCode.Code != Code.Ldtoken
                    || instruction.Next.Next.Next.Operand is not FieldReference
                    || instruction.Next.Next.Next.Next is not { OpCode.Code: Code.Call, Operand: MethodReference call }
                    || call.DeclaringType.FullName != "System.Runtime.CompilerServices.RuntimeHelpers"
                    || call.Name != "InitializeArray" || call.Parameters.Count != 2) continue;
                preserved.Add(instruction, "constants:runtime-array-initializer");
            }
        return preserved;
    }
}
