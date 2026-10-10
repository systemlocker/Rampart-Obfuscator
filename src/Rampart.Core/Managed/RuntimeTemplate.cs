using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace Rampart.Managed;

// Copied into each protected module. Cached data belongs to that module, so it
// cannot root a collectible load context through a process-wide registry.
internal static class RuntimeTemplate
{
    [ThreadStatic] private static int[]? scratch;

    internal static string Decode(string resource, int offset, int length, int key, ref string? cached)
    {
        // Concurrent first calls may decode twice, but all callers publish the
        // same immutable interned value. Later calls need no lock or allocation.
        var existing = cached;
        if (existing is not null) return existing;
        var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resource)!;
        stream.Position = offset;
        var bytes = new byte[length];
        for (var i = 0; i < bytes.Length; i++) bytes[i] = (byte)(stream.ReadByte() ^ (key + i * 31));
        stream.Dispose();
        // ldstr returns interned strings. Retaining that behavior also retains plaintext
        // for the lifetime of its intern pool; this is obfuscation, not secret storage.
        var characters = new char[bytes.Length / 2];
        for (var i = 0; i < characters.Length; i++) characters[i] = (char)(bytes[i * 2] | bytes[i * 2 + 1] << 8);
        existing = string.Intern(new string(characters));
        cached = existing;
        return existing;
    }

    internal static void Verify(string resource, string expected)
    {
        var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resource)!;
        var digest = SHA256.HashData(stream);
        stream.Dispose();
        if (Convert.ToHexString(digest) != expected)
            throw new InvalidDataException("The protected resource failed its integrity check.");
    }

    internal static int Interpret(string program, int opcodeKey, int arg0, int arg1, int arg2, int arg3,
        int arg4, int arg5, int arg6, int arg7, int[]? arguments)
    {
        var locals = program[0] | program[1] << 16;
        var maximum = program[2] | program[3] << 16;
        var stack = scratch;
        if (stack is null || stack.Length < locals + maximum) scratch = stack = new int[locals + maximum];
        // The admitted VM has no calls, callbacks or exception handlers. Its frame
        // therefore cannot re-enter this interpreter on the same thread. Clear
        // only locals: every live stack slot is assigned before its first read.
        if (locals != 0) Array.Clear(stack, 0, locals);
        var top = locals;
        var pc = 4;
        while (pc < program.Length)
        {
            var operation = program[pc] ^ opcodeKey;
            var operand = program[pc + 1] | program[pc + 2] << 16;
            pc += 3;
            switch (operation)
            {
                case 0: break;
                case 1: stack[top++] = operand; break;
                case 2:
                    stack[top++] = operand switch
                    {
                        0 => arg0,
                        1 => arg1,
                        2 => arg2,
                        3 => arg3,
                        4 => arg4,
                        5 => arg5,
                        6 => arg6,
                        7 => arg7,
                        _ => arguments![operand]
                    };
                    break;
                case 3: top--; stack[top - 1] = unchecked(stack[top - 1] + stack[top]); break;
                case 4: top--; stack[top - 1] = unchecked(stack[top - 1] - stack[top]); break;
                case 5: top--; stack[top - 1] = unchecked(stack[top - 1] * stack[top]); break;
                case 6: top--; stack[top - 1] ^= stack[top]; break;
                case 7: top--; stack[top - 1] &= stack[top]; break;
                case 8: top--; stack[top - 1] |= stack[top]; break;
                case 9: stack[top - 1] = unchecked(-stack[top - 1]); break;
                case 10: stack[top - 1] = ~stack[top - 1]; break;
                case 11: return stack[top - 1];
                case 12: stack[top++] = stack[operand]; break;
                case 13: stack[operand] = stack[--top]; break;
                case 14: pc = operand; break;
                case 15: if (stack[--top] == 0) pc = operand; break;
                case 16: if (stack[--top] != 0) pc = operand; break;
                case 17: top -= 2; if (stack[top] == stack[top + 1]) pc = operand; break;
                case 18: top -= 2; if (stack[top] != stack[top + 1]) pc = operand; break;
                case 19: top -= 2; if (stack[top] >= stack[top + 1]) pc = operand; break;
                case 20: top -= 2; if (stack[top] > stack[top + 1]) pc = operand; break;
                case 21: top -= 2; if (stack[top] <= stack[top + 1]) pc = operand; break;
                case 22: top -= 2; if (stack[top] < stack[top + 1]) pc = operand; break;
                case 23: top -= 2; if ((uint)stack[top] >= (uint)stack[top + 1]) pc = operand; break;
                case 24: top -= 2; if ((uint)stack[top] > (uint)stack[top + 1]) pc = operand; break;
                case 25: top -= 2; if ((uint)stack[top] <= (uint)stack[top + 1]) pc = operand; break;
                case 26: top -= 2; if ((uint)stack[top] < (uint)stack[top + 1]) pc = operand; break;
                case 27: top--; stack[top - 1] = stack[top - 1] == stack[top] ? 1 : 0; break;
                case 28: top--; stack[top - 1] = stack[top - 1] > stack[top] ? 1 : 0; break;
                case 29: top--; stack[top - 1] = stack[top - 1] < stack[top] ? 1 : 0; break;
                case 30: top--; stack[top - 1] = (uint)stack[top - 1] > (uint)stack[top] ? 1 : 0; break;
                case 31: top--; stack[top - 1] = (uint)stack[top - 1] < (uint)stack[top] ? 1 : 0; break;
                case 32: top--; stack[top - 1] /= stack[top]; break;
                case 33: top--; stack[top - 1] = (int)((uint)stack[top - 1] / (uint)stack[top]); break;
                case 34: top--; stack[top - 1] %= stack[top]; break;
                case 35: top--; stack[top - 1] = (int)((uint)stack[top - 1] % (uint)stack[top]); break;
                case 36: top--; stack[top - 1] <<= stack[top]; break;
                case 37: top--; stack[top - 1] >>= stack[top]; break;
                case 38: top--; stack[top - 1] = (int)((uint)stack[top - 1] >> stack[top]); break;
                case 39: top--; stack[top - 1] = checked(stack[top - 1] + stack[top]); break;
                case 40: top--; stack[top - 1] = checked(stack[top - 1] - stack[top]); break;
                case 41: top--; stack[top - 1] = checked(stack[top - 1] * stack[top]); break;
                case 42: top--; stack[top - 1] = unchecked((int)checked((uint)stack[top - 1] + (uint)stack[top])); break;
                case 43: top--; stack[top - 1] = unchecked((int)checked((uint)stack[top - 1] - (uint)stack[top])); break;
                case 44: top--; stack[top - 1] = unchecked((int)checked((uint)stack[top - 1] * (uint)stack[top])); break;
                case 45: stack[top] = stack[top - 1]; top++; break;
                case 46: top--; break;
                case 47:
                    var index = stack[--top];
                    var count = program[operand] | program[operand + 1] << 16;
                    if ((uint)index < (uint)count)
                    {
                        operand += 2 + index * 2;
                        pc = program[operand] | program[operand + 1] << 16;
                    }
                    break;
                case 48: stack[top - 1] = (sbyte)stack[top - 1]; break;
                case 49: stack[top - 1] = (byte)stack[top - 1]; break;
                case 50: stack[top - 1] = (short)stack[top - 1]; break;
                case 51: stack[top - 1] = (ushort)stack[top - 1]; break;
                case 52: stack[operand] = (sbyte)stack[--top]; break;
                case 53: stack[operand] = (byte)stack[--top]; break;
                case 54: stack[operand] = (short)stack[--top]; break;
                case 55: stack[operand] = (ushort)stack[--top]; break;
                case 56: stack[top - 1] = checked((sbyte)stack[top - 1]); break;
                case 57: stack[top - 1] = checked((byte)stack[top - 1]); break;
                case 58: stack[top - 1] = checked((short)stack[top - 1]); break;
                case 59: stack[top - 1] = checked((ushort)stack[top - 1]); break;
                case 61: stack[top - 1] = unchecked((int)checked((uint)stack[top - 1])); break;
                case 62: stack[top - 1] = checked((sbyte)unchecked((uint)stack[top - 1])); break;
                case 63: stack[top - 1] = checked((byte)unchecked((uint)stack[top - 1])); break;
                case 64: stack[top - 1] = checked((short)unchecked((uint)stack[top - 1])); break;
                case 65: stack[top - 1] = checked((ushort)unchecked((uint)stack[top - 1])); break;
                case 66: stack[top - 1] = checked((int)unchecked((uint)stack[top - 1])); break;
                default: throw new InvalidDataException("The protected method program is invalid.");
            }
        }
        throw new InvalidDataException("The protected method program is incomplete.");
    }
}

// Only this method replaces the modern integrity helper on the .NET Framework
// lane. It uses APIs present in the CLR 4 reference assemblies; its references
// are explicitly rebound by the injector rather than importing .NET 8 facades.
internal static class FrameworkIntegrityTemplate
{
    internal static void Verify(string resource, string expected)
    {
        var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resource)!;
        var algorithm = SHA256.Create();
        var digest = algorithm.ComputeHash(stream);
        algorithm.Dispose(); stream.Dispose();
        var characters = new char[digest.Length * 2];
        const string alphabet = "0123456789ABCDEF";
        for (var i = 0; i < digest.Length; i++)
        {
            characters[i * 2] = alphabet[digest[i] >> 4];
            characters[i * 2 + 1] = alphabet[digest[i] & 15];
        }
        if (new string(characters) != expected)
            throw new InvalidDataException("The protected resource failed its integrity check.");
    }
}
