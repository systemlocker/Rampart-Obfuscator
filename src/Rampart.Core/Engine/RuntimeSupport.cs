using System.Buffers.Binary;
using Rampart.Pe;

namespace Rampart.Engine;

/// <summary>Rebuilds the base-relocation table to cover pointer slots the
/// protector added. The original entries are preserved verbatim; ours are
/// appended as new blocks in a fresh region of the stub section, and the data
/// directory is repointed.</summary>
public static class RelocBuilder
{
    public static void Rebuild(BuildContext ctx)
    {
        if (ctx.RelocSlots.Count == 0)
            return;

        var pe = ctx.Pe;
        var existing = Relocations.Enumerate(pe).ToList();
        var combined = existing
            .Concat(ctx.RelocSlots.Select(r => new RelocEntry(r, Relocations.TypeAbsolute)))
            .Distinct()
            .OrderBy(r => r.Rva)
            .ThenBy(r => r.Type)
            .ToList();

        // PE/COFF relocation blocks group entries by 4K image page and are
        // DWORD-aligned. Rebuild from the union so the target's fixups survive.
        var byPage = combined.GroupBy(r => r.Rva & ~0xFFFu).OrderBy(g => g.Key).ToList();
        int newSize = byPage.Sum(g => 8 + Align2(g.Count() * 2, 4));

        uint newRva = ctx.Alloc(newSize, 8);
        var blob = new byte[newSize];
        int pos = 0;

        foreach (var page in byPage)
        {
            uint pageRva = page.Key;
            var entries = page.OrderBy(r => r.Rva).ThenBy(r => r.Type).ToList();
            int entriesPos = pos + 8;
            int count = 0;
            foreach (var entry in entries)
            {
                ushort e = (ushort)(((uint)entry.Type << 12) | (entry.Rva & 0xFFF));
                BinaryPrimitives.WriteUInt16LittleEndian(blob.AsSpan(entriesPos + count * 2), e);
                count++;
            }
            int blockSize = 8 + Align2(count * 2, 4);
            BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan(pos), pageRva);
            BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan(pos + 4), (uint)blockSize);
            pos += blockSize;
        }

        ctx.WriteStub(newRva, blob);
        pe.SetDirectory(DataDir.Basereloc, newRva, (uint)pos);
        ctx.Log.Add(new("reloc", $"relocation table rebuilt: {existing.Count} original + {ctx.RelocSlots.Count} new slots ({combined.Count} unique)"));
    }

    private static int Align2(int v, int a) => (v + a - 1) / a * a;
}

/// <summary>Adds Rampart-created guarded targets to an image's Guard CF function
/// table while retaining every compiler-generated entry and metadata byte.</summary>
public static class GuardCfBuilder
{
    private const uint FunctionTableSizeMask = 0xF0000000;
    private const int FunctionTableSizeShift = 28;

    public static void RegisterTarget(BuildContext ctx, uint targetRva)
    {
        var pe = ctx.Pe;
        PeCompatibilityFeatures compatibility = PeCompatibility.Inspect(pe);
        if (!compatibility.GuardCf)
            return;

        DataDirectory directory = pe.Directory(DataDir.LoadConfig);
        if (directory.IsEmpty || compatibility.LoadConfigSize < 0x94)
        {
            throw new NotSupportedException(
                "CFG-enabled images require a PE32+ load-config directory large enough to register Rampart callbacks.");
        }

        uint loadConfigRva = directory.RelativeVirtualAddress;
        ulong oldTableVa = BinaryPrimitives.ReadUInt64LittleEndian(pe.ReadRva(loadConfigRva + 0x80, 8));
        ulong oldCount = BinaryPrimitives.ReadUInt64LittleEndian(pe.ReadRva(loadConfigRva + 0x88, 8));
        int extraBytes = (int)(((uint)compatibility.GuardFlags & FunctionTableSizeMask) >> FunctionTableSizeShift);
        int stride = checked(4 + extraBytes);
        if (oldCount > 16_000_000 || oldCount > (ulong)(int.MaxValue / stride))
            throw new BadImageFormatException("Guard CF function table is unreasonably large.");
        if ((oldTableVa == 0) != (oldCount == 0))
            throw new BadImageFormatException("Guard CF function table pointer/count are inconsistent.");

        var entries = new List<byte[]>((int)oldCount + 1);
        if (oldCount > 0)
        {
            uint oldTableRva = pe.VaToRva(oldTableVa);
            byte[] oldTable = pe.ReadRva(oldTableRva, checked((int)oldCount * stride));
            for (int i = 0; i < (int)oldCount; i++)
                entries.Add(oldTable.AsSpan(i * stride, stride).ToArray());
        }

        if (entries.Any(entry => BinaryPrimitives.ReadUInt32LittleEndian(entry) == targetRva))
            return;

        var added = new byte[stride];
        BinaryPrimitives.WriteUInt32LittleEndian(added, targetRva);
        entries.Add(added);
        entries.Sort((left, right) =>
            BinaryPrimitives.ReadUInt32LittleEndian(left)
                .CompareTo(BinaryPrimitives.ReadUInt32LittleEndian(right)));

        byte[] rebuilt = new byte[entries.Count * stride];
        for (int i = 0; i < entries.Count; i++)
            entries[i].CopyTo(rebuilt, i * stride);
        uint newTableRva = ctx.Alloc(rebuilt.Length, 8);
        ctx.WriteStub(newTableRva, rebuilt);

        pe.WriteRva(loadConfigRva + 0x80, BitConverter.GetBytes(pe.ImageBase + newTableRva));
        pe.WriteRva(loadConfigRva + 0x88, BitConverter.GetBytes((ulong)entries.Count));
        ImageGuardFlags flags = compatibility.GuardFlags | ImageGuardFlags.CfFunctionTablePresent;
        pe.WriteRva(loadConfigRva + 0x90, BitConverter.GetBytes((uint)flags));
        ctx.RelocSlots.Add(loadConfigRva + 0x80);
        ctx.Log.Add(new("guard-cf",
            $"registered target RVA {targetRva:X8} in {entries.Count}-entry Guard CF table"));
    }
}

/// <summary>Builds (or chains into) the TLS directory so the protector's init
/// routines run before the original entry point, on every thread start.</summary>
public static class TlsBuilder
{
    /// <summary>Installs a single callback that walks the registered init chain.
    /// If the image already has TLS callbacks, ours run first and the original
    /// callbacks follow in the new array.</summary>
    public static void Install(BuildContext ctx, uint dispatcherRva)
    {
        var pe = ctx.Pe;
        var existing = new List<ulong>();
        ulong startAddress = 0;
        ulong endAddress = 0;
        ulong indexAddress = 0;
        uint sizeOfZeroFill = 0;
        uint characteristics = 0;
        var dir = pe.Directory(DataDir.Tls);
        if (!dir.IsEmpty)
        {
            if (!pe.IsPe32Plus)
                throw new NotSupportedException("TLS chaining currently supports PE32+ images only.");

            var tls = pe.ReadRva(dir.RelativeVirtualAddress, 40);
            startAddress = BinaryPrimitives.ReadUInt64LittleEndian(tls);
            endAddress = BinaryPrimitives.ReadUInt64LittleEndian(tls.AsSpan(8));
            indexAddress = BinaryPrimitives.ReadUInt64LittleEndian(tls.AsSpan(16));
            ulong callbacksVa = BinaryPrimitives.ReadUInt64LittleEndian(tls.AsSpan(24));
            sizeOfZeroFill = BinaryPrimitives.ReadUInt32LittleEndian(tls.AsSpan(32));
            characteristics = BinaryPrimitives.ReadUInt32LittleEndian(tls.AsSpan(36));
            if (callbacksVa != 0)
            {
                uint callbacksRva = pe.VaToRva(callbacksVa);
                for (int i = 0; i < 4096; i++)
                {
                    ulong cb = pe.ReadU64(callbacksRva + (uint)(i * 8));
                    if (cb == 0)
                        break;
                    existing.Add(cb);
                    if (i == 4095)
                        throw new BadImageFormatException("TLS callback array is not terminated within 4096 entries.");
                }
            }
        }

        // Callback array: [dispatcher, ...original, 0]. Each entry is an absolute
        // VA the loader relocates — every slot is registered for DIR64 fixups.
        uint arrayRva = ctx.Alloc(8 * (existing.Count + 2), 8);
        ulong imageBase = pe.ImageBase;
        if (indexAddress == 0)
            indexAddress = imageBase + ctx.Alloc(8, 8);
        uint dirRva = ctx.Alloc(40, 8);

        ctx.WriteStub(arrayRva, BitConverter.GetBytes(imageBase + dispatcherRva));
        for (int i = 0; i < existing.Count; i++)
            ctx.WriteStub(arrayRva + 8 + (uint)(i * 8), BitConverter.GetBytes(existing[i]));
        // terminating zero already zero.

        for (int i = 0; i < existing.Count + 1; i++)
            ctx.RelocSlots.Add(arrayRva + (uint)(i * 8));

        var dirBlob = new byte[40];
        BinaryPrimitives.WriteUInt64LittleEndian(dirBlob.AsSpan(0), startAddress);
        BinaryPrimitives.WriteUInt64LittleEndian(dirBlob.AsSpan(8), endAddress);
        BinaryPrimitives.WriteUInt64LittleEndian(dirBlob.AsSpan(16), indexAddress);
        BinaryPrimitives.WriteUInt64LittleEndian(dirBlob.AsSpan(24), imageBase + arrayRva);     // AddressOfCallBacks
        BinaryPrimitives.WriteUInt32LittleEndian(dirBlob.AsSpan(32), sizeOfZeroFill);
        BinaryPrimitives.WriteUInt32LittleEndian(dirBlob.AsSpan(36), characteristics);
        ctx.WriteStub(dirRva, dirBlob);

        // IMAGE_TLS_DIRECTORY64 stores absolute VAs, not RVAs. The loader may
        // rebase the image before it writes AddressOfIndex or walks callbacks,
        // so both populated fields need DIR64 fixups just like callback slots.
        if (startAddress != 0) ctx.RelocSlots.Add(dirRva);
        if (endAddress != 0) ctx.RelocSlots.Add(dirRva + 8);
        ctx.RelocSlots.Add(dirRva + 16); // AddressOfIndex
        ctx.RelocSlots.Add(dirRva + 24); // AddressOfCallBacks

        pe.SetDirectory(DataDir.Tls, dirRva, 40);
        ctx.Log.Add(new("tls", $"TLS callback array at RVA {arrayRva:X8}: dispatcher + {existing.Count} original callbacks"));
    }
}
