using System.Buffers.Binary;

namespace Rampart.Pe;

public readonly record struct RuntimeFunction(uint BeginRva, uint EndRva, uint UnwindRva);

/// <summary>x64 exception directory (.pdata): one RUNTIME_FUNCTION per function,
/// giving exact begin/end RVAs. This is the map that makes safe code surgery
/// possible — every transform that rewrites branches works inside these bounds.</summary>
public static class ExceptionTable
{
    public static List<RuntimeFunction> Parse(PeImage pe)
    {
        var result = new List<RuntimeFunction>();
        var dir = pe.Directory(DataDir.Exception);
        if (dir.IsEmpty)
            return result;
        if (dir.RelativeVirtualAddress == 0)
            throw new BadImageFormatException("Exception directory has a non-zero size with RVA 0.");

        int count = checked((int)(dir.Size / 12));
        if (count == 0)
            return result;
        var blob = pe.ReadRva(dir.RelativeVirtualAddress, checked(count * 12));
        for (int i = 0; i < count; i++)
        {
            uint begin = BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(i * 12));
            uint end = BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(i * 12 + 4));
            uint unwind = BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(i * 12 + 8));
            if (begin == 0)
                continue;
            if (end <= begin)
                throw new BadImageFormatException($"Exception table entry at index {i} has EndRva ({end:X8}) <= BeginRva ({begin:X8}).");
            result.Add(new RuntimeFunction(begin, end, unwind));
        }
        result.Sort((a, b) => a.BeginRva.CompareTo(b.BeginRva));
        return result;
    }
}
