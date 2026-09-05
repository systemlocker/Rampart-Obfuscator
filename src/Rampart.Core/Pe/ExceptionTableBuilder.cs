using System.Buffers.Binary;
using Rampart.Engine;

namespace Rampart.Pe;

/// <summary>Registers generated x64 frames without replacing original unwind records.</summary>
public static class ExceptionTableBuilder
{
    public static void Register(BuildContext ctx, uint begin, uint end, ReadOnlySpan<byte> unwind)
    {
        if (end <= begin || unwind.Length < 4 || (unwind.Length & 3) != 0)
            throw new ArgumentException("Invalid generated runtime-function range or unwind record.");
        var directory = ctx.Pe.Directory(DataDir.Exception);
        if (!directory.IsEmpty && directory.Size % 12 != 0)
            throw new BadImageFormatException("Exception directory has an incomplete runtime-function entry.");
        var records = ExceptionTable.Parse(ctx.Pe);
        if (records.Any(record => record.BeginRva < end && record.EndRva > begin))
            throw new ArgumentException("Generated runtime-function range overlaps an existing entry.");
        uint unwindRva = ctx.AllocData(unwind.Length, 4);
        ctx.WriteData(unwindRva, unwind);
        records.Add(new(begin, end, unwindRva));
        records.Sort((a, b) => a.BeginRva.CompareTo(b.BeginRva));
        byte[] table = new byte[records.Count * 12];
        for (int index = 0; index < records.Count; index++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(table.AsSpan(index * 12), records[index].BeginRva);
            BinaryPrimitives.WriteUInt32LittleEndian(table.AsSpan(index * 12 + 4), records[index].EndRva);
            BinaryPrimitives.WriteUInt32LittleEndian(table.AsSpan(index * 12 + 8), records[index].UnwindRva);
        }
        uint tableRva = ctx.AllocData(table.Length, 4);
        ctx.WriteData(tableRva, table);
        ctx.Pe.SetDirectory(DataDir.Exception, tableRva, (uint)table.Length);
    }
}
