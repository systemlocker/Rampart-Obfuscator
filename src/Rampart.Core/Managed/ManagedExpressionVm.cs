using System.Security.Cryptography;
using System.Text;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Rampart.Managed;

// Straight-line integer programs need no runtime stack pointer or shared frame.
// Their verified stack heights become fixed virtual registers; the encoded
// program still selects an interpreter handler for each operation at runtime.
internal static class ManagedExpressionVm
{
    private enum Form { Constant, Argument, Unary, Binary, ConstantBinary, ArgumentBinary, ArgumentConstantBinary, ArgumentUnaryConstantBinary, Duplicate }
    private readonly record struct Handler(Form Form, Code Code, int Destination, int Argument = 0, Code Prefix = Code.Nop);
    private readonly record struct Step(Handler Handler, int Operand = 0);

    internal static bool TryVirtualize(MethodDefinition method, MethodDefinition generalHelper,
        ManagedIntegerProgram program, long seed, string identity)
    {
        var operations = program.Operations;
        if (method.Body.HasVariables || method.Parameters.Count > 8 || program.MaximumStack > 8
            || operations.Length is < 2 or > 256 || operations[^1].Code != 11
            || operations.Take(operations.Length - 1).Any(operation => operation.Code is not (0 or 1 or 2 or 45 or 46)
                && !Unary(operation.Code) && !Binary(operation.Code))) return false;

        var steps = new List<Step>();
        for (int index = 0; index < operations.Length - 1; index++)
        {
            var operation = operations[index];
            int height = program.Heights[operation.Source];
            if (operation.Code is 0 or 46) continue;
            // Fusions consume contiguous instructions with no incoming edges:
            // this lane admits neither branches nor exception regions. Preserve
            // source order, especially for checked conversion/division exceptions.
            if (operation.Code == 2 && index + 3 < operations.Length - 1
                && Unary(operations[index + 1].Code) && operations[index + 2].Code == 1 && Binary(operations[index + 3].Code))
            {
                steps.Add(new(new(Form.ArgumentUnaryConstantBinary, operations[index + 3].Source.OpCode.Code, height,
                    operation.Operand, operations[index + 1].Source.OpCode.Code), operations[index + 2].Operand));
                index += 3;
            }
            else if (operation.Code == 2 && index + 2 < operations.Length - 1
                && operations[index + 1].Code == 1 && Binary(operations[index + 2].Code))
            {
                steps.Add(new(new(Form.ArgumentConstantBinary, operations[index + 2].Source.OpCode.Code, height, operation.Operand), operations[index + 1].Operand));
                index += 2;
            }
            else if (operation.Code is 1 or 2 && index + 1 < operations.Length - 1 && Binary(operations[index + 1].Code))
            {
                steps.Add(new(new(operation.Code == 1 ? Form.ConstantBinary : Form.ArgumentBinary,
                    operations[index + 1].Source.OpCode.Code, height - 1, operation.Code == 2 ? operation.Operand : 0), operation.Operand));
                index++;
            }
            else
            {
                var handler = operation.Code switch
                {
                    1 => new Handler(Form.Constant, Code.Nop, height),
                    2 => new Handler(Form.Argument, Code.Nop, height, operation.Operand),
                    45 => new Handler(Form.Duplicate, Code.Nop, height),
                    _ when Unary(operation.Code) => new Handler(Form.Unary, operation.Source.OpCode.Code, height - 1),
                    _ => new Handler(Form.Binary, operation.Source.OpCode.Code, height - 2)
                };
                steps.Add(new(handler, operation.Operand));
            }
        }
        var handlers = steps.Select(step => step.Handler).Distinct().OrderBy(handler => handler.Form)
            .ThenBy(handler => handler.Code).ThenBy(handler => handler.Destination).ThenBy(handler => handler.Argument)
            .ThenBy(handler => handler.Prefix).ToArray();
        // Bound generated dispatch size independently of the source instruction
        // limit. Larger expressions retain the established general VM contract.
        if (handlers.Length is 0 or > 32) return false;
        string shape = "expression-v1|" + method.Parameters.Count + "|" + program.MaximumStack + "|"
            + string.Join(";", handlers.Select(handler => $"{(int)handler.Form},{(int)handler.Code},{handler.Destination},{handler.Argument},{(int)handler.Prefix}"));
        string name = "InterpretExpression_" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(shape)));
        var helper = generalHelper.DeclaringType.Methods.FirstOrDefault(candidate => candidate.Name == name)
            ?? CreateHelper(method, generalHelper, name, handlers, program.MaximumStack);
        int key = (ManagedTransforms.Key(seed, identity, 0) & 65535) | 1;
        var encoded = new char[steps.Count * 3];
        for (int index = 0; index < steps.Count; index++)
        {
            encoded[index * 3] = (char)(Array.IndexOf(handlers, steps[index].Handler) ^ key);
            encoded[index * 3 + 1] = (char)steps[index].Operand;
            encoded[index * 3 + 2] = (char)(steps[index].Operand >> 16);
        }
        method.Body.Instructions.Clear(); method.Body.Variables.Clear();
        method.DebugInformation.SequencePoints.Clear(); method.DebugInformation.Scope = null;
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldstr, new string(encoded)); il.Emit(OpCodes.Ldc_I4, key);
        foreach (var parameter in method.Parameters) il.Emit(OpCodes.Ldarg, parameter);
        il.Emit(OpCodes.Call, helper); il.Emit(OpCodes.Ret);
        return true;
    }

    private static MethodDefinition CreateHelper(MethodDefinition source, MethodDefinition general,
        string name, Handler[] handlers, int registerCount)
    {
        var types = source.Module.TypeSystem;
        var result = new MethodDefinition(name, MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig, types.Int32);
        result.Parameters.Add(new("program", ParameterAttributes.None, types.String));
        result.Parameters.Add(new("key", ParameterAttributes.None, types.Int32));
        for (int index = 0; index < source.Parameters.Count; index++) result.Parameters.Add(new("arg" + index, ParameterAttributes.None, types.Int32));
        result.Body.InitLocals = true;
        var pc = new VariableDefinition(types.Int32); result.Body.Variables.Add(pc);
        var operand = new VariableDefinition(types.Int32); result.Body.Variables.Add(operand);
        var registers = Enumerable.Range(0, registerCount).Select(_ => new VariableDefinition(types.Int32)).ToArray();
        foreach (var register in registers) result.Body.Variables.Add(register);
        // Reuse already rebound platform references. This emits the same verified
        // CLR4-compatible IL without importing the protector's runtime facades.
        var references = general.Body.Instructions.Select(instruction => instruction.Operand).OfType<MethodReference>().ToArray();
        var chars = references.First(reference => reference.DeclaringType.FullName == "System.String" && reference.Name == "get_Chars");
        var length = references.First(reference => reference.DeclaringType.FullName == "System.String" && reference.Name == "get_Length");
        var invalid = references.First(reference => reference.DeclaringType.FullName == "System.IO.InvalidDataException" && reference.Name == ".ctor");
        var il = result.Body.GetILProcessor();
        var check = Instruction.Create(OpCodes.Ldloc, pc);
        var next = Instruction.Create(OpCodes.Ldloc, pc);
        var entry = Instruction.Create(OpCodes.Ldarg_0);
        var cases = handlers.Select(_ => Instruction.Create(OpCodes.Nop)).ToArray();
        il.Emit(OpCodes.Br, check);
        il.Append(entry); il.Emit(OpCodes.Ldloc, pc); il.Emit(OpCodes.Callvirt, chars);
        // Share operand decoding across the small dispatch table. Duplicating
        // it in each immediate handler inflated first-call JIT work and code size.
        il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Ldloc, pc); il.Emit(OpCodes.Ldc_I4_1); il.Emit(OpCodes.Add); il.Emit(OpCodes.Callvirt, chars);
        il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Ldloc, pc); il.Emit(OpCodes.Ldc_I4_2); il.Emit(OpCodes.Add); il.Emit(OpCodes.Callvirt, chars);
        il.Emit(OpCodes.Ldc_I4, 16); il.Emit(OpCodes.Shl); il.Emit(OpCodes.Or); il.Emit(OpCodes.Stloc, operand);
        il.Emit(OpCodes.Ldarg_1); il.Emit(OpCodes.Xor); il.Emit(OpCodes.Switch, cases);
        il.Emit(OpCodes.Ldstr, "The protected method program is invalid."); il.Emit(OpCodes.Newobj, invalid); il.Emit(OpCodes.Throw);
        void Register(int index) => il.Emit(OpCodes.Ldloc, registers[index]);
        void Argument(int index) => il.Emit(OpCodes.Ldarg, result.Parameters[index + 2]);
        void Immediate() => il.Emit(OpCodes.Ldloc, operand);
        for (int index = 0; index < handlers.Length; index++)
        {
            var handler = handlers[index]; il.Append(cases[index]);
            switch (handler.Form)
            {
                case Form.Constant: Immediate(); break;
                case Form.Argument: Argument(handler.Argument); break;
                case Form.Duplicate: Register(handler.Destination - 1); break;
                case Form.Unary: Register(handler.Destination); il.Emit(Opcode(handler.Code)); break;
                case Form.Binary: Register(handler.Destination); Register(handler.Destination + 1); il.Emit(Opcode(handler.Code)); break;
                case Form.ConstantBinary: Register(handler.Destination); Immediate(); il.Emit(Opcode(handler.Code)); break;
                case Form.ArgumentBinary: Register(handler.Destination); Argument(handler.Argument); il.Emit(Opcode(handler.Code)); break;
                case Form.ArgumentConstantBinary:
                case Form.ArgumentUnaryConstantBinary:
                    Argument(handler.Argument);
                    if (handler.Form == Form.ArgumentUnaryConstantBinary) il.Emit(Opcode(handler.Prefix));
                    Immediate(); il.Emit(Opcode(handler.Code)); break;
            }
            il.Emit(OpCodes.Stloc, registers[handler.Destination]); il.Emit(OpCodes.Br, next);
        }
        il.Append(next); il.Emit(OpCodes.Ldc_I4_3); il.Emit(OpCodes.Add); il.Emit(OpCodes.Stloc, pc);
        il.Append(check); il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Callvirt, length); il.Emit(OpCodes.Blt, entry);
        Register(0); il.Emit(OpCodes.Ret);
        general.DeclaringType.Methods.Add(result);
        return result;
    }

    private static bool Unary(int code) => code is 9 or 10 or >= 48 and <= 51 or >= 56 and <= 59 or >= 61 and <= 66;
    private static bool Binary(int code) => code is >= 3 and <= 8 or >= 27 and <= 44;
    private static OpCode Opcode(Code code) => code switch
    {
        Code.Add => OpCodes.Add,
        Code.Sub => OpCodes.Sub,
        Code.Mul => OpCodes.Mul,
        Code.Xor => OpCodes.Xor,
        Code.And => OpCodes.And,
        Code.Or => OpCodes.Or,
        Code.Neg => OpCodes.Neg,
        Code.Not => OpCodes.Not,
        Code.Ceq => OpCodes.Ceq,
        Code.Cgt => OpCodes.Cgt,
        Code.Clt => OpCodes.Clt,
        Code.Cgt_Un => OpCodes.Cgt_Un,
        Code.Clt_Un => OpCodes.Clt_Un,
        Code.Div => OpCodes.Div,
        Code.Div_Un => OpCodes.Div_Un,
        Code.Rem => OpCodes.Rem,
        Code.Rem_Un => OpCodes.Rem_Un,
        Code.Shl => OpCodes.Shl,
        Code.Shr => OpCodes.Shr,
        Code.Shr_Un => OpCodes.Shr_Un,
        Code.Add_Ovf => OpCodes.Add_Ovf,
        Code.Sub_Ovf => OpCodes.Sub_Ovf,
        Code.Mul_Ovf => OpCodes.Mul_Ovf,
        Code.Add_Ovf_Un => OpCodes.Add_Ovf_Un,
        Code.Sub_Ovf_Un => OpCodes.Sub_Ovf_Un,
        Code.Mul_Ovf_Un => OpCodes.Mul_Ovf_Un,
        Code.Conv_I1 => OpCodes.Conv_I1,
        Code.Conv_U1 => OpCodes.Conv_U1,
        Code.Conv_I2 => OpCodes.Conv_I2,
        Code.Conv_U2 => OpCodes.Conv_U2,
        Code.Conv_Ovf_I1 => OpCodes.Conv_Ovf_I1,
        Code.Conv_Ovf_U1 => OpCodes.Conv_Ovf_U1,
        Code.Conv_Ovf_I2 => OpCodes.Conv_Ovf_I2,
        Code.Conv_Ovf_U2 => OpCodes.Conv_Ovf_U2,
        Code.Conv_Ovf_U4 => OpCodes.Conv_Ovf_U4,
        Code.Conv_Ovf_I1_Un => OpCodes.Conv_Ovf_I1_Un,
        Code.Conv_Ovf_U1_Un => OpCodes.Conv_Ovf_U1_Un,
        Code.Conv_Ovf_I2_Un => OpCodes.Conv_Ovf_I2_Un,
        Code.Conv_Ovf_U2_Un => OpCodes.Conv_Ovf_U2_Un,
        Code.Conv_Ovf_I4_Un => OpCodes.Conv_Ovf_I4_Un,
        Code.Conv_Ovf_U4_Un => OpCodes.Conv_Ovf_U4_Un,
        _ => throw new InvalidOperationException("An unsupported operation entered the expression VM.")
    };
}
