using System.Buffers.Binary;

namespace Rampart.Pe;

public sealed record ImportedFunction(string Dll, string Name, uint Hint, uint ThunkRva);

/// <summary>Parses the classic import table (INT/IAT pairs, ASCII names). Used to
/// rebuild hash-resolved imports and to find thunks worth re-routing.</summary>
public static class ImportTable
{
    public static List<ImportedFunction> Parse(PeImage pe)
    {
        var result = new List<ImportedFunction>();
        var dir = pe.Directory(DataDir.Import);
        if (dir.IsEmpty)
            return result;

        uint descRva = dir.RelativeVirtualAddress;
        while (true)
        {
            var desc = pe.ReadRva(descRva, 20);
            uint originalFirstThunk = BinaryPrimitives.ReadUInt32LittleEndian(desc);
            uint nameRva = BinaryPrimitives.ReadUInt32LittleEndian(desc.AsSpan(12));
            uint firstThunk = BinaryPrimitives.ReadUInt32LittleEndian(desc.AsSpan(16));
            if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0)
                break;

            string dll = pe.ReadCString(nameRva);
            uint thunk = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
            int index = 0;
            while (true)
            {
                ulong entry = pe.IsPe32Plus
                    ? pe.ReadU64(thunk + (uint)(index * 8))
                    : pe.ReadU32(thunk + (uint)(index * 4));

                if (entry == 0)
                    break;

                uint thunkRva = firstThunk + (uint)(index * (pe.IsPe32Plus ? 8 : 4));
                if ((entry & (pe.IsPe32Plus ? 0x8000000000000000UL : 0x80000000UL)) != 0)
                {
                    uint ordinal = (uint)(entry & 0xFFFF);
                    result.Add(new ImportedFunction(dll, $"#{ordinal}", ordinal, thunkRva));
                }
                else
                {
                    uint hintNameRva = checked((uint)entry);
                    uint hint = BinaryPrimitives.ReadUInt16LittleEndian(pe.ReadRva(hintNameRva, 2));
                    // Import names may legally end at the last raw byte of a
                    // section. Reading a speculative 256-byte block crosses
                    // into virtual padding in real binaries such as 7-Zip.
                    string fname = pe.ReadCString(checked(hintNameRva + 2));
                    result.Add(new ImportedFunction(dll, fname, hint, thunkRva));
                }
                index++;
            }
            descRva += 20;
        }
        return result;
    }

    /// <summary>Case-insensitive DLL group with canonical kernel32 entries the
    /// runtime stubs like to resolve first.</summary>
    public static string NormalizeDll(string dll) =>
        dll.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? dll[..^4] : dll;
}
