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
            ReplaceLiteral(method, instruction, decoder, payload, resource, seed, identity, count++);
        }
        return count;
    }

    private static void ReplaceLiteral(MethodDefinition method, Instruction literal, MethodDefinition decoder,
        MemoryStream payload, string resource, long seed, string identity, int site)
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
        var cache = new FieldDefinition("p_" + offset, FieldAttributes.Assembly | FieldAttributes.Static, method.Module.TypeSystem.String);
        decoder.DeclaringType.Fields.Add(cache);
        var keyMethod = CreateKeyMethod(decoder, keySeed, seed, identity, site, offset, out int salt);
        var reader = new MethodDefinition("p_" + offset, MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig, method.Module.TypeSystem.String)
        { ImplAttributes = MethodImplAttributes.NoInlining };
        var il = reader.Body.GetILProcessor(); var done = Instruction.Create(OpCodes.Ret);
        // Check the site cache before deriving a key. After initialization the
        // wrapper only returns the cached immutable string/program; it allocates
        // nothing and performs no cryptographic work on the hot path.
        il.Emit(OpCodes.Ldsfld, cache); il.Emit(OpCodes.Dup); il.Emit(OpCodes.Brtrue, done); il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ldstr, resource); il.Emit(OpCodes.Ldc_I4, offset); il.Emit(OpCodes.Ldc_I4, record.Length);
        il.Emit(OpCodes.Ldc_I4, salt); il.Emit(OpCodes.Call, keyMethod); il.Emit(OpCodes.Ldsflda, cache); il.Emit(OpCodes.Call, decoder);
        il.Append(done); decoder.DeclaringType.Methods.Add(reader);
        literal.OpCode = OpCodes.Call; literal.Operand = reader;
        CryptographicOperations.ZeroMemory(keySeed);
        CryptographicOperations.ZeroMemory(material);
    }

    private static MethodDefinition CreateKeyMethod(MethodDefinition decoder, byte[] seedBytes, long seed,
        string identity, int site, int offset, out int salt)
    {
        var module = decoder.Module; var types = module.TypeSystem;
        var result = new MethodDefinition("k_" + offset, MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig, types.String)
        { ImplAttributes = MethodImplAttributes.NoInlining };
        result.Parameters.Add(new ParameterDefinition(types.Int32));
        var calls = decoder.Body.Instructions.Select(instruction => instruction.Operand).OfType<MethodReference>().ToArray();
        var cryptoScope = calls.First(call => call.DeclaringType.FullName == "System.Security.Cryptography.Aes").DeclaringType.Scope;
        var hash = new MethodReference("HashData", new ArrayType(types.Byte), new TypeReference("System.Security.Cryptography", "SHA512", module, cryptoScope));
        hash.Parameters.Add(new ParameterDefinition(new ArrayType(types.Byte)));
        var convert = new MethodReference("ToBase64String", types.String, calls.First(call => call.DeclaringType.FullName == "System.Convert").DeclaringType);
        convert.Parameters.Add(new ParameterDefinition(new ArrayType(types.Byte)));
        salt = ManagedTransforms.Key(seed, identity + "|key", site);
        var il = result.Body.GetILProcessor(); il.Emit(OpCodes.Ldc_I4, seedBytes.Length); il.Emit(OpCodes.Newarr, types.Byte);
        // The seed is materialized from scattered immediates and a caller-supplied
        // salt in a non-inlined method. The full AES/MAC key is never an ldstr or
        // static array initializer. This raises extraction work, not secrecy:
        // an analyst can still evaluate this routine in the native application.
        foreach (int index in Enumerable.Range(0, seedBytes.Length).OrderBy(index => ManagedTransforms.Key(seed, identity, site + index + 100)))
        {
            int mask = unchecked(salt + index * 83) & 255;
            il.Emit(OpCodes.Dup); il.Emit(OpCodes.Ldc_I4, index); il.Emit(OpCodes.Ldc_I4, seedBytes[index] ^ mask);
            il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Ldc_I4, index * 83); il.Emit(OpCodes.Add); il.Emit(OpCodes.Conv_U1);
            il.Emit(OpCodes.Xor); il.Emit(OpCodes.Conv_U1); il.Emit(OpCodes.Stelem_I1);
        }
        il.Emit(OpCodes.Call, hash); il.Emit(OpCodes.Call, convert); il.Emit(OpCodes.Ret);
        decoder.DeclaringType.Methods.Add(result);
        return result;
    }

    internal static bool Virtualize(MethodDefinition method, MethodDefinition interpreter, MethodDefinition decoder,
        MemoryStream payload, string resource, long seed, string identity)
    {
        if (!ManagedIntegerProgram.TryLift(method, out var program)) return false;
        int key = (ManagedTransforms.Key(seed, identity, 0) & 65535) | 1;
        char[] encoded = program!.Encode(method.Body.Variables.Count, key).ToCharArray();
        var helper = Clone(interpreter, "v_" + identity[..16]);
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
        ReplaceLiteral(method, literal, decoder, payload, resource, seed, identity + "|vm", 0);
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
        il.Emit(OpCodes.Call, helper); il.Emit(OpCodes.Ret);
        return true;
    }

    private static MethodDefinition Clone(MethodDefinition source, string name)
    {
        var copy = new MethodDefinition(name, source.Attributes, source.ReturnType);
        foreach (var parameter in source.Parameters) copy.Parameters.Add(new ParameterDefinition(parameter.Name, parameter.Attributes, parameter.ParameterType));
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
            copy.Body.Instructions.Add(cloned);
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
