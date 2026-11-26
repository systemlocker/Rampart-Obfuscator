using System.Security.Cryptography;
using System.Text;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Rampart.Managed;

internal static class ManagedHardenedTransforms
{
    internal static int Strings(MethodDefinition method, MethodDefinition decoder, MemoryStream payload,
        string resource, long seed, string identity, Func<Instruction, bool> eligible)
    {
        int count = 0;
        foreach (var instruction in method.Body.Instructions.ToArray())
        {
            if (instruction.OpCode.Code != Code.Ldstr || !eligible(instruction)) continue;
            ReplaceLiteral(method, instruction, decoder, payload, resource, seed, identity, count++, intern: true);
        }
        if (count > 0) ManagedIlVerifier.UpdateMaxStackSize(method);
        return count;
    }

    private static void ReplaceLiteral(MethodDefinition method, Instruction literal, MethodDefinition decoder,
        MemoryStream payload, string resource, long seed, string identity, int site, bool intern, bool ephemeral = false)
    {
        string value = (string)literal.Operand;
        var plaintext = new byte[checked(value.Length * 2)];
        for (int index = 0; index < value.Length; index++)
        { plaintext[index * 2] = (byte)value[index]; plaintext[index * 2 + 1] = (byte)(value[index] >> 8); }
        // Domain and content separation retain reproducibility without reusing
        // an IV/key pair for different payloads at the same source site.
        var keySeed = SHA256.HashData(Encoding.UTF8.GetBytes($"payload-v1|{resource}|{seed}|{identity}|{site}|{Convert.ToHexString(SHA256.HashData(plaintext))}"));
        var material = SHA512.HashData(keySeed);
        var iv = SHA256.HashData(material)[..16];
        byte[] ciphertext;
        using (var algorithm = Aes.Create())
        {
            algorithm.Mode = CipherMode.CBC; algorithm.Padding = PaddingMode.PKCS7;
            using var encryptor = algorithm.CreateEncryptor(material[..32], iv);
            ciphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
        }
        CryptographicOperations.ZeroMemory(plaintext);
        var record = new byte[checked(16 + ciphertext.Length + 32)];
        iv.CopyTo(record, 0); ciphertext.CopyTo(record, 16);
        using (var mac = new HMACSHA256(material[32..]))
            mac.ComputeHash(record, 0, record.Length - 32).CopyTo(record, record.Length - 32);
        int offset = checked((int)payload.Length); payload.Write(record);
        var keyMethod = CreateKeyMethod(decoder, keySeed, seed, identity, site, offset, out int salt);
        var returnType = ephemeral ? new ArrayType(method.Module.TypeSystem.Char) : method.Module.TypeSystem.String;
        var reader = new MethodDefinition("p_" + offset, MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig, returnType)
        { ImplAttributes = MethodImplAttributes.NoInlining };
        var il = reader.Body.GetILProcessor();
        FieldDefinition? cache = null;
        Instruction? done = null;
        if (!ephemeral)
        {
            cache = new FieldDefinition("p_" + offset, FieldAttributes.Assembly | FieldAttributes.Static, method.Module.TypeSystem.String);
            decoder.DeclaringType.Fields.Add(cache);
            done = Instruction.Create(OpCodes.Ret);
            // User-string semantics require a stable interned object. Ephemeral VM
            // programs take the separate uncached path below.
            il.Emit(OpCodes.Ldsfld, cache); il.Emit(OpCodes.Dup); il.Emit(OpCodes.Brtrue, done); il.Emit(OpCodes.Pop);
        }
        il.Emit(OpCodes.Ldstr, resource); il.Emit(OpCodes.Ldc_I4, offset); il.Emit(OpCodes.Ldc_I4, record.Length);
        il.Emit(OpCodes.Ldc_I4, salt); il.Emit(OpCodes.Call, keyMethod);
        if (!ephemeral)
        {
            il.Emit(intern ? OpCodes.Ldc_I4_1 : OpCodes.Ldc_I4_0);
            il.Emit(OpCodes.Ldsflda, cache!);
        }
        il.Emit(OpCodes.Call, decoder);
        if (done is not null) il.Append(done);
        else il.Emit(OpCodes.Ret);
        ManagedIlVerifier.UpdateMaxStackSize(reader);
        decoder.DeclaringType.Methods.Add(reader);
        literal.OpCode = OpCodes.Call; literal.Operand = reader;
        CryptographicOperations.ZeroMemory(keySeed);
        CryptographicOperations.ZeroMemory(material);
    }

    private static MethodDefinition CreateKeyMethod(MethodDefinition decoder, byte[] seedBytes, long seed,
        string identity, int site, int offset, out int salt)
    {
        var module = decoder.Module; var types = module.TypeSystem;
        var byteArray = new ArrayType(types.Byte);
        var result = new MethodDefinition("k_" + offset, MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig, byteArray)
        { ImplAttributes = MethodImplAttributes.NoInlining };
        result.Parameters.Add(new ParameterDefinition(types.Int32));
        var calls = decoder.Body.Instructions.Select(instruction => instruction.Operand).OfType<MethodReference>().ToArray();
        var cryptoScope = calls.First(call => call.DeclaringType.FullName == "System.Security.Cryptography.Aes").DeclaringType.Scope;
        var hash = new MethodReference("HashData", byteArray, new TypeReference("System.Security.Cryptography", "SHA512", module, cryptoScope));
        hash.Parameters.Add(new ParameterDefinition(byteArray));
        salt = ManagedTransforms.Key(seed, identity + "|key", site);
        result.Body.InitLocals = true;
        var seedBuffer = new VariableDefinition(byteArray); var derivedKey = new VariableDefinition(byteArray);
        result.Body.Variables.Add(seedBuffer); result.Body.Variables.Add(derivedKey);
        var il = result.Body.GetILProcessor(); il.Emit(OpCodes.Ldc_I4, seedBytes.Length); il.Emit(OpCodes.Newarr, types.Byte); il.Emit(OpCodes.Stloc, seedBuffer);
        // The seed is materialized from scattered immediates and a caller-supplied
        // salt in a non-inlined method. Returning byte[] directly avoids pinning
        // key material in an immutable Base64 string on the managed heap.
        foreach (int index in Enumerable.Range(0, seedBytes.Length).OrderBy(index => ManagedTransforms.Key(seed, identity, site + index + 100)))
        {
            int mask = unchecked(salt + index * 83) & 255;
            il.Emit(OpCodes.Ldloc, seedBuffer); il.Emit(OpCodes.Ldc_I4, index); il.Emit(OpCodes.Ldc_I4, seedBytes[index] ^ mask);
            il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Ldc_I4, index * 83); il.Emit(OpCodes.Add); il.Emit(OpCodes.Conv_U1);
            il.Emit(OpCodes.Xor); il.Emit(OpCodes.Conv_U1); il.Emit(OpCodes.Stelem_I1);
        }
        il.Emit(OpCodes.Ldloc, seedBuffer); il.Emit(OpCodes.Call, hash); il.Emit(OpCodes.Stloc, derivedKey);
        var clearArray = decoder.Body.Instructions.Select(instruction => instruction.Operand).OfType<MethodReference>()
            .First(reference => reference.DeclaringType.FullName == "System.Array" && reference.Name == "Clear");
        il.Emit(OpCodes.Ldloc, seedBuffer); il.Emit(OpCodes.Ldc_I4_0); il.Emit(OpCodes.Ldloc, seedBuffer);
        il.Emit(OpCodes.Ldlen); il.Emit(OpCodes.Conv_I4); il.Emit(OpCodes.Call, clearArray);
        il.Emit(OpCodes.Ldloc, derivedKey); il.Emit(OpCodes.Ret);
        ManagedIlVerifier.UpdateMaxStackSize(result);
        decoder.DeclaringType.Methods.Add(result);
        return result;
    }

    internal static bool Virtualize(MethodDefinition method, MethodDefinition interpreter, MethodDefinition decoder,
        MethodDefinition clearScratch, MemoryStream payload, string resource, long seed, string identity, bool ephemeral)
    {
        if (!ManagedIntegerProgram.TryLift(method, out var program)) return false;
        int key = (ManagedTransforms.Key(seed, identity, 0) & 65535) | 1;
        char[] encoded = program!.Encode(method.Body.Variables.Count, key).ToCharArray();
        var baseName = "v_" + identity[..16];
        var counter = interpreter.DeclaringType.Methods.Count(m => m.Name.StartsWith(baseName + "_", StringComparison.Ordinal));
        var helper = Clone(interpreter, baseName + "_" + counter, ephemeral);
        // Each selected method has its own opcode assignment. The original
        // logical switch is permuted together with the program; branch and
        // switch destinations remain exact UTF-16 program offsets.
        var dispatch = helper.Body.Instructions.Single(instruction => instruction.OpCode.Code == Code.Switch
            && instruction.Operand is Instruction[] targets && targets.Length == 67);
        var originalTargets = (Instruction[])dispatch.Operand;
        int[] order = Enumerable.Range(0, originalTargets.Length).OrderBy(index => ManagedTransforms.Key(seed, identity, index + 1)).ThenBy(index => index).ToArray();
        int[] opcodes = new int[order.Length];
        for (int index = 0; index < order.Length; index++) opcodes[order[index]] = index;
        dispatch.Operand = order.Select(index => originalTargets[index]).ToArray();
        for (int index = 0; index < program.Operations.Length; index++)
            encoded[4 + index * 3] = (char)(opcodes[program.Operations[index].Code] ^ key);
        helper.ImplAttributes |= MethodImplAttributes.NoInlining;
        interpreter.DeclaringType.Methods.Add(helper);
        method.Body.Instructions.Clear(); method.Body.Variables.Clear();
        method.DebugInformation.SequencePoints.Clear(); method.DebugInformation.Scope = null;
        var il = method.Body.GetILProcessor();
        var literal = Instruction.Create(OpCodes.Ldstr, new string(encoded)); il.Append(literal);
        ReplaceLiteral(method, literal, decoder, payload, resource, seed, identity + "|vm", 0, intern: false, ephemeral);

        void EmitArguments()
        {
            il.Emit(OpCodes.Ldc_I4, key);
            for (int index = 0; index < 8; index++)
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
        }

        if (!ephemeral)
        {
            EmitArguments();
            il.Emit(OpCodes.Call, helper); il.Emit(OpCodes.Ret);
        }
        else
        {
            // Keep no static reference to the plaintext program. The finally block
            // clears both it and the thread-local operand frame on success or error.
            method.Body.InitLocals = true;
            var programLocal = new VariableDefinition(new ArrayType(method.Module.TypeSystem.Char));
            var result = new VariableDefinition(method.Module.TypeSystem.Int32);
            method.Body.Variables.Add(programLocal); method.Body.Variables.Add(result);
            il.Emit(OpCodes.Stloc, programLocal);
            var tryStart = Instruction.Create(OpCodes.Ldloc, programLocal); il.Append(tryStart);
            EmitArguments();
            il.Emit(OpCodes.Call, helper); il.Emit(OpCodes.Stloc, result);
            var afterFinally = Instruction.Create(OpCodes.Nop);
            il.Emit(OpCodes.Leave, afterFinally);
            var finallyStart = Instruction.Create(OpCodes.Call, clearScratch); il.Append(finallyStart);
            il.Emit(OpCodes.Ldloc, programLocal); il.Emit(OpCodes.Ldc_I4_0); il.Emit(OpCodes.Ldloc, programLocal);
            il.Emit(OpCodes.Ldlen); il.Emit(OpCodes.Conv_I4);
            var clearArray = decoder.Body.Instructions.Select(instruction => instruction.Operand).OfType<MethodReference>()
                .First(reference => reference.DeclaringType.FullName == "System.Array" && reference.Name == "Clear");
            il.Emit(OpCodes.Call, clearArray); il.Emit(OpCodes.Endfinally);
            il.Append(afterFinally); il.Emit(OpCodes.Ldloc, result); il.Emit(OpCodes.Ret);
            method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally)
            {
                TryStart = tryStart,
                TryEnd = finallyStart,
                HandlerStart = finallyStart,
                HandlerEnd = afterFinally
            });
        }
        ManagedIlVerifier.UpdateMaxStackSize(method);
        return true;
    }

    private static MethodDefinition Clone(MethodDefinition source, string name, bool ephemeralProgram)
    {
        var copy = new MethodDefinition(name, source.Attributes, source.ReturnType);
        foreach (var parameter in source.Parameters) copy.Parameters.Add(new ParameterDefinition(parameter.Name, parameter.Attributes, parameter.ParameterType));
        if (ephemeralProgram) copy.Parameters[0].ParameterType = new ArrayType(source.Module.TypeSystem.Char);
        copy.Body.InitLocals = source.Body.InitLocals; copy.Body.MaxStackSize = source.Body.MaxStackSize;
        foreach (var variable in source.Body.Variables) copy.Body.Variables.Add(new VariableDefinition(variable.VariableType));
        var instructions = source.Body.Instructions.ToDictionary(instruction => instruction, _ => Instruction.Create(OpCodes.Nop));
        foreach (var instruction in source.Body.Instructions)
        {
            var cloned = instructions[instruction]; cloned.OpCode = instruction.OpCode;
            cloned.Operand = instruction.Operand switch
            {
                Instruction branch => instructions[branch],
                Instruction[] branches => branches.Select(branch => instructions[branch]).ToArray(),
                VariableDefinition variable => copy.Body.Variables[variable.Index],
                ParameterDefinition parameter => copy.Parameters[parameter.Index],
                _ => instruction.Operand
            };
            if (ephemeralProgram && instruction.Operand is MethodReference call
                && call.DeclaringType.FullName == "System.String" && call.Name == "get_Chars")
            {
                cloned.OpCode = OpCodes.Ldelem_U2; cloned.Operand = null;
            }
            else if (ephemeralProgram && instruction.Operand is MethodReference length
                && length.DeclaringType.FullName == "System.String" && length.Name == "get_Length")
            {
                cloned.OpCode = OpCodes.Ldlen; cloned.Operand = null;
            }
            copy.Body.Instructions.Add(cloned);
            if (ephemeralProgram && instruction.Operand is MethodReference lengthCall
                && lengthCall.DeclaringType.FullName == "System.String" && lengthCall.Name == "get_Length")
                copy.Body.Instructions.Add(Instruction.Create(OpCodes.Conv_I4));
        }
        foreach (var region in source.Body.ExceptionHandlers)
            copy.Body.ExceptionHandlers.Add(new ExceptionHandler(region.HandlerType)
            {
                TryStart = instructions[region.TryStart],
                TryEnd = region.TryEnd is null ? null : instructions[region.TryEnd],
                HandlerStart = instructions[region.HandlerStart],
                HandlerEnd = region.HandlerEnd is null ? null : instructions[region.HandlerEnd],
                FilterStart = region.FilterStart is null ? null : instructions[region.FilterStart],
                CatchType = region.CatchType
            });
        return copy;
    }
}
