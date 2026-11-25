using System.Buffers.Binary;

namespace Rampart.Pe;

public readonly record struct RelocEntry(uint Rva, ushort Type);

/// <summary>Base relocation table (.reloc) access. Two uses: applying relocations
/// when a stub assumes the preferred base, and enumerating every absolute pointer
/// in the image (the honest way to find data referenced by address).</summary>
public static class Relocations
{
    public const ushort TypeAbsolute = 10;   // PE32+ DIR64
    public const ushort TypeHighLow = 3;     // PE32 DIR32

    public static IEnumerable<RelocEntry> Enumerate(PeImage pe)
    {
        var dir = pe.Directory(DataDir.Basereloc);
        if (dir.IsEmpty)
            yield break;

        ulong cursorRva = dir.RelativeVirtualAddress;
        ulong end = (ulong)dir.RelativeVirtualAddress + dir.Size;
        while (cursorRva + 8 <= end && cursorRva <= uint.MaxValue)
        {
            var block = pe.ReadRva((uint)cursorRva, 8);
            uint blockPage = BinaryPrimitives.ReadUInt32LittleEndian(block);
            uint blockSize = BinaryPrimitives.ReadUInt32LittleEndian(block.AsSpan(4));
            if (blockSize < 8 || (blockSize & 1) != 0 || cursorRva + blockSize > end || blockSize - 8 > int.MaxValue)
                yield break; // malformed tail — stop rather than throw mid-enumeration

            var entries = pe.ReadRva(checked((uint)(cursorRva + 8)), (int)(blockSize - 8));
            for (int i = 0; i + 2 <= entries.Length; i += 2)
            {
                ushort e = BinaryPrimitives.ReadUInt16LittleEndian(entries.AsSpan(i));
                ushort type = (ushort)(e >> 12);
                ushort offset = (ushort)(e & 0xFFF);
                if (type == 0)
                    continue;
                if ((ulong)blockPage + offset <= uint.MaxValue)
                    yield return new RelocEntry(blockPage + offset, type);
                // IMAGE_REL_BASED_HIGHADJ (4) consumes an extra 16-bit parameter slot.
                if (type == 4)
                    i += 2;
            }
            cursorRva += blockSize;
        }
    }

    /// <summary>True when the image asks for ASLR (and therefore has relocations).</summary>
    public static bool IsDynamicBase(PeImage pe) =>
        pe.DllChars.HasFlag(DllCharacteristics.DynamicBase);
}
