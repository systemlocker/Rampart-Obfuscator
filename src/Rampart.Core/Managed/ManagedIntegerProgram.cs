using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Rampart.Managed;

internal sealed class ManagedIntegerProgram
{
    internal sealed record Operation(Instruction Source, int Code, int Operand);
    internal required Operation[] Operations { get; init; }
    internal required Dictionary<Instruction, int> Heights { get; init; }
    internal required int MaximumStack { get; init; }

    internal static bool TryLift(MethodDefinition method, out ManagedIntegerProgram? result)
    {
        result = null;
        // The implicit receiver may remain unused; interpreting object references,
        // callbacks and exception regions requires a different VM value model.
        if (method.IsConstructor || method.HasGenericParameters || method.DeclaringType.HasGenericParameters
            || !IntegerType(method.ReturnType) || method.Parameters.Count > 255
            || method.Parameters.Any(parameter => !IntegerType(parameter.ParameterType))
            || method.Body.Variables.Any(variable => !IntegerType(variable.VariableType))
            || method.Body.HasVariables && !method.Body.InitLocals
            || method.Body.Variables.Count > 4096
            || !ManagedFlowAnalysis.TryHeights(method, out var heights, out var maximum) || maximum > 4096) return false;
        var operations = new List<Operation>();
        foreach (var instruction in method.Body.Instructions)
        {
            var operand = 0;
            int code;
            if (ManagedTransforms.Integer(instruction, out operand)) code = 1;
            else
            {
                var argument = instruction.OpCode.Code switch
                {
                    Code.Ldarg_0 => 0,
                    Code.Ldarg_1 => 1,
                    Code.Ldarg_2 => 2,
                    Code.Ldarg_3 => 3,
                    Code.Ldarg or Code.Ldarg_S => ((ParameterDefinition)instruction.Operand).Index + (method.HasThis ? 1 : 0),
                    _ => -1
                };
                if (argument >= 0)
                {
                    operand = argument - (method.HasThis ? 1 : 0);
                    if (operand < 0 || operand >= method.Parameters.Count) return false;
                    code = 2;
                }
                else
                {
                    code = instruction.OpCode.Code switch
                    {
                        Code.Nop => 0,
                        Code.Add => 3,
                        Code.Sub => 4,
                        Code.Mul => 5,
                        Code.Xor => 6,
                        Code.And => 7,
                        Code.Or => 8,
                        Code.Neg => 9,
                        Code.Not => 10,
                        Code.Ret => 11,
                        Code.Ldloc or Code.Ldloc_S or Code.Ldloc_0 or Code.Ldloc_1 or Code.Ldloc_2 or Code.Ldloc_3 => 12,
                        Code.Stloc or Code.Stloc_S or Code.Stloc_0 or Code.Stloc_1 or Code.Stloc_2 or Code.Stloc_3 => 13,
                        Code.Br or Code.Br_S => 14,
                        Code.Brfalse or Code.Brfalse_S => 15,
                        Code.Brtrue or Code.Brtrue_S => 16,
                        Code.Beq or Code.Beq_S => 17,
                        Code.Bne_Un or Code.Bne_Un_S => 18,
                        Code.Bge or Code.Bge_S => 19,
                        Code.Bgt or Code.Bgt_S => 20,
                        Code.Ble or Code.Ble_S => 21,
                        Code.Blt or Code.Blt_S => 22,
                        Code.Bge_Un or Code.Bge_Un_S => 23,
                        Code.Bgt_Un or Code.Bgt_Un_S => 24,
                        Code.Ble_Un or Code.Ble_Un_S => 25,
                        Code.Blt_Un or Code.Blt_Un_S => 26,
                        Code.Ceq => 27,
                        Code.Cgt => 28,
                        Code.Clt => 29,
                        Code.Cgt_Un => 30,
                        Code.Clt_Un => 31,
                        Code.Div => 32,
                        Code.Div_Un => 33,
                        Code.Rem => 34,
                        Code.Rem_Un => 35,
                        Code.Shl => 36,
                        Code.Shr => 37,
                        Code.Shr_Un => 38,
                        Code.Add_Ovf => 39,
                        Code.Sub_Ovf => 40,
                        Code.Mul_Ovf => 41,
                        Code.Add_Ovf_Un => 42,
                        Code.Sub_Ovf_Un => 43,
                        Code.Mul_Ovf_Un => 44,
                        Code.Dup => 45,
                        Code.Pop => 46,
                        Code.Switch => 47,
                        Code.Conv_I1 => 48,
                        Code.Conv_U1 => 49,
                        Code.Conv_I2 => 50,
                        Code.Conv_U2 => 51,
                        Code.Conv_I4 or Code.Conv_U4 => 0,
                        Code.Conv_Ovf_I1 => 56,
                        Code.Conv_Ovf_U1 => 57,
                        Code.Conv_Ovf_I2 => 58,
                        Code.Conv_Ovf_U2 => 59,
                        Code.Conv_Ovf_I4 => 0,
                        Code.Conv_Ovf_U4 => 61,
                        Code.Conv_Ovf_I1_Un => 62,
                        Code.Conv_Ovf_U1_Un => 63,
                        Code.Conv_Ovf_I2_Un => 64,
                        Code.Conv_Ovf_U2_Un => 65,
                        Code.Conv_Ovf_I4_Un => 66,
                        Code.Conv_Ovf_U4_Un => 0,
                        _ => -1
                    };
                    if (code < 0) return false;
                    if (code is 12 or 13)
                    {
                        operand = instruction.OpCode.Code switch
                        {
                            Code.Ldloc_0 or Code.Stloc_0 => 0,
                            Code.Ldloc_1 or Code.Stloc_1 => 1,
                            Code.Ldloc_2 or Code.Stloc_2 => 2,
                            Code.Ldloc_3 or Code.Stloc_3 => 3,
                            _ => ((VariableDefinition)instruction.Operand).Index
                        };
                        if (operand >= method.Body.Variables.Count) return false;
                        if (code == 13)
                            code = method.Body.Variables[operand].VariableType.MetadataType switch
                            {
                                MetadataType.SByte => 52,
                                MetadataType.Byte or MetadataType.Boolean => 53,
                                MetadataType.Int16 => 54,
                                MetadataType.UInt16 or MetadataType.Char => 55,
                                _ => code
                            };
                    }
                }
            }
            operations.Add(new(instruction, code, operand));
        }
        result = new() { Operations = operations.ToArray(), Heights = heights, MaximumStack = maximum };
        return true;
    }

    internal string Encode(int locals, int opcodeKey)
    {
        // Fixed-width UTF-16 operands let the interpreter consume its interned
        // program directly. No Base64 decoding or per-invocation program exists.
        var positions = Operations.Select((operation, index) => (operation.Source, Offset: 4 + index * 3)).ToDictionary(pair => pair.Source, pair => pair.Offset);
        var data = new List<char>(4 + Operations.Length * 3);
        AddInt(data, locals); AddInt(data, MaximumStack);
        var tables = new List<char>();
        foreach (var operation in Operations)
        {
            var operand = operation.Operand;
            if (operation.Source.Operand is Instruction target) operand = positions[target];
            else if (operation.Source.Operand is Instruction[] targets)
            {
                operand = 4 + Operations.Length * 3 + tables.Count;
                AddInt(tables, targets.Length);
                foreach (var destination in targets) AddInt(tables, positions[destination]);
            }
            data.Add((char)(operation.Code ^ opcodeKey)); AddInt(data, operand);
        }
        data.AddRange(tables);
        return new string(data.ToArray());
    }

    private static void AddInt(List<char> target, int value) { target.Add((char)value); target.Add((char)(value >> 16)); }
    private static bool IntegerType(TypeReference type) => type.MetadataType is MetadataType.Int32 or MetadataType.UInt32 or MetadataType.Boolean
        or MetadataType.Char or MetadataType.Int16 or MetadataType.UInt16 or MetadataType.SByte or MetadataType.Byte;
}
