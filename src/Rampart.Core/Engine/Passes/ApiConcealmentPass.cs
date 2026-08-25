using System.Buffers.Binary;
using Rampart.Pe;
using Rampart.X64;

namespace Rampart.Engine.Passes;

/// <summary>
/// Routes selected imported calls through Rampart-owned tail thunks. Unlike
/// import-slot concealment, this changes the call graph itself: protected code
/// calls a local, per-build wrapper and the wrapper performs the final indirect
/// transfer through the loader-populated IAT slot.
/// </summary>
public sealed class ApiConcealmentPass
{
    // Process, memory, loader, timing, and termination APIs expose the most
    // useful behavioral outline of a protected application. Keep this list
    // deliberately small at Light so ordinary library calls remain untouched.
    private static readonly HashSet<string> SensitiveNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CheckRemoteDebuggerPresent",
        "CreateFileA", "CreateFileW",
        "CreateProcessA", "CreateProcessW",
        "CreateRemoteThread",
        "ExitProcess", "GetProcAddress",
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "OpenProcess", "ReadProcessMemory",
        "SetProcessMitigationPolicy",
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory",
    };

    public void Run(BuildContext ctx)
    {
        var level = ctx.Level("memory.api-concealment");
        if (level == Config.ProtectionLevel.Off)
            return;

        List<ImportedFunction> imports = ImportTable.Parse(ctx.Pe)
            .Where(imported => SensitiveNames.Contains(imported.Name))
            .ToList();
        if (imports.Count == 0)
        {
            ctx.Log.Add(new("api-concealment", "no sensitive imported APIs were present"));
            return;
        }

        var wrappers = new Dictionary<uint, uint>();
        int rewritten = 0;
        foreach (FunctionDescriptor function in ctx.Functions)
        {
            if (!ctx.Pe.TryRvaToOffset(function.BeginRva, out int fileOffset))
                continue;

            PeImage.Section section = ctx.Pe.SectionFromRva(function.BeginRva)!;
            int available = checked((int)Math.Min(
                function.Size,
                section.PointerToRawData + section.SizeOfRawData - (uint)fileOffset));
            int sectionOffset = fileOffset - checked((int)section.PointerToRawData);
            Span<byte> code = section.Data.AsSpan(sectionOffset, available);

            int position = 0;
            while (position < code.Length)
            {
                uint instructionRva = function.BeginRva + (uint)position;
                if (!X64Decoder.TryDecode(code, position, instructionRva, out X64Instruction instruction))
                    break;

                bool supportedTransfer = instruction.Mnemonic is
                    X64Mnemonic.CallIndirect or X64Mnemonic.JmpIndirect;
                bool exactRipEncoding = instruction.Length == 6
                    && code[position] == 0xFF
                    && code[position + 1] is 0x15 or 0x25;
                ImportedFunction? imported = supportedTransfer && exactRipEncoding
                    ? imports.FirstOrDefault(candidate => candidate.ThunkRva == instruction.RipTargetRva)
                    : null;

                if (imported is not null)
                {
                    if (!wrappers.TryGetValue(imported.ThunkRva, out uint wrapperRva))
                    {
                        wrapperRva = EmitWrapper(ctx, imported);
                        wrappers.Add(imported.ThunkRva, wrapperRva);
                    }

                    long displacement = (long)wrapperRva - (instructionRva + 5L);
                    if (displacement is >= int.MinValue and <= int.MaxValue)
                    {
                        code[position] = instruction.Mnemonic == X64Mnemonic.CallIndirect
                            ? (byte)0xE8
                            : (byte)0xE9;
                        BinaryPrimitives.WriteInt32LittleEndian(
                            code.Slice(position + 1, 4), checked((int)displacement));
                        code[position + 5] = 0x90;
                        rewritten++;
                    }
                }

                position += instruction.Length;
            }
        }

        ctx.Log.Add(new("api-concealment",
            $"routed {rewritten} sensitive call site(s) through {wrappers.Count} local wrapper thunk(s)"));
    }

    private static uint EmitWrapper(BuildContext ctx, ImportedFunction imported)
    {
        // jmp qword ptr [rip+disp32]. A direct CALL from target code enters this
        // six-byte tail thunk; the imported function returns straight to the
        // original caller, so no stack or unwind contract changes.
        uint rva = ctx.Alloc(6, 16);
        long displacement = (long)imported.ThunkRva - (rva + 6L);
        if (displacement is < int.MinValue or > int.MaxValue)
            throw new NotSupportedException("Imported API slot is outside the x64 RIP-relative wrapper range.");

        Span<byte> wrapper = stackalloc byte[6];
        wrapper[0] = 0xFF;
        wrapper[1] = 0x25;
        BinaryPrimitives.WriteInt32LittleEndian(wrapper[2..], checked((int)displacement));
        ctx.WriteStub(rva, wrapper);
        return rva;
    }
}
