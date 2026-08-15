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

        int count = (int)(dir.Size / 12);
        var blob = pe.ReadRva(dir.RelativeVirtualAddress, count * 12);
        for (int i = 0; i < count; i++)
        {
            uint begin = BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(i * 12));
            uint end = BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(i * 12 + 4));
            uint unwind = BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(i * 12 + 8));
            if (begin == 0)
                continue;
            result.Add(new RuntimeFunction(begin, end, unwind));
        }
        result.Sort((a, b) => a.BeginRva.CompareTo(b.BeginRva));
        return result;
    }
}
