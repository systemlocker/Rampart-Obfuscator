using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using Rampart.Engine;
using Rampart.Pe;

namespace Rampart.ControlFlow;

/// <summary>Conservative preconditions for tail-transferring explicitly selected,
/// single-entry Windows x64 leaf functions. Computed interior entry points are
/// outside the supported native ABI; this checks the discoverable representations.</summary>
public static class LeafFunctionEligibility
{
    private sealed class ScanBudget { public long Used; public int Attempts; }
    private static readonly ConditionalWeakTable<BuildContext, ScanBudget> Budgets = new();
    public static bool TryValidate(BuildContext ctx, FunctionDescriptor function, out string reason)
    {
        var pe = ctx.Pe;
        reason = "";
        var budget = Budgets.GetOrCreateValue(ctx);
        lock (budget)
        {
            if (++budget.Attempts > 256)
                return Fail("build exhausted its 256 leaf-validation attempts", out reason);
        }
        if (pe.Machine != MachineType.Amd64 || function.EndRva <= function.BeginRva
            || function.Size is < 5 or > 512)
            return Fail("requires an AMD64 function between 5 and 512 bytes", out reason);
        var section = pe.SectionFromRva(function.BeginRva);
        if (section is null || !section.IsExecutable
            || section.Characteristics.HasFlag(SectionCharacteristics.MemWrite)
            || (ulong)function.EndRva > (ulong)section.VirtualAddress + Math.Min(section.VirtualSize, (uint)section.Data.Length))
            return Fail("function must fit in one non-writable executable section", out reason);
        if (!pe.Directory(DataDir.LoadConfig).IsEmpty || pe.DllChars.HasFlag(DllCharacteristics.GuardCf))
            return Fail("load-configuration entry inventories are not supported", out reason);
        if (ctx.Functions.Any(other => other != function
            && other.BeginRva < function.EndRva && other.EndRva > function.BeginRva))
            return Fail("overlapping runtime function ranges", out reason);
        if (ctx.Symbols.Any(symbol => Inside(symbol.StartRva, function)) || Inside(pe.EntryPointRva, function))
            return Fail("known interior entry point", out reason);

        try
        {
            // Only version 1 with no flags, prologue, unwind slots, or frame register
            // describes the unchanged-stack leaf contract used by both emitters.
            byte[] unwind = pe.ReadRva(function.UnwindRva, 4);
            if (!unwind.AsSpan().SequenceEqual(new byte[] { 1, 0, 0, 0 }))
                return Fail("requires empty version-1 leaf unwind information", out reason);
            // Scanning at every byte is intentional: relying on a partial decoder
            // to find incoming branches could silently miss an overlapping stream.
            // False positives skip protection rather than risking an entry patch.
            long scanSize = pe.Sections.Sum(s => (long)s.Data.Length);
            if (scanSize > 32 * 1024 * 1024)
                return Fail("image exceeds the bounded entry-reference scan", out reason);
            lock (budget)
            {
                // VM and flattening share this cumulative bound. A large symbol
                // selection must not multiply whole-image scans without limit.
                if (budget.Used + scanSize > 64 * 1024 * 1024)
                    return Fail("build exhausted its leaf entry-reference scan budget", out reason);
                budget.Used += scanSize;
            }
            if (!ValidateRelocations(pe, function, out reason)) return false;
            foreach (var source in pe.Sections)
            {
                var bytes = source.Data;
                for (int i = 0; i < bytes.Length; i++)
                {
                    long site = (long)source.VirtualAddress + i;
                    if (site >= function.BeginRva && site < function.EndRva)
                        continue;
                    if (i + 4 <= bytes.Length && Inside(BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i)), function))
                        return Fail("possible stored interior RVA", out reason);
                    if (i + 8 <= bytes.Length)
                    {
                        ulong pointer = BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(i));
                        if (pointer >= pe.ImageBase && pointer - pe.ImageBase <= uint.MaxValue
                            && Inside((uint)(pointer - pe.ImageBase), function))
                            return Fail("possible stored interior address", out reason);
                    }
                    if (!source.IsExecutable)
                        continue;
                    if (bytes[i] is 0x8D or 0x8B && i + 6 <= bytes.Length && (bytes[i + 1] & 0xC7) == 0x05)
                    {
                        // The opcode position also catches REX-prefixed forms:
                        // the instruction endpoint is still opcode + 6 bytes.
                        long pointerTarget = site + 6 + BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(i + 2));
                        if (pointerTarget > function.BeginRva && pointerTarget < function.EndRva)
                            return Fail("possible RIP-relative interior reference", out reason);
                    }
                    int size = 0, relative = 0;
                    if (bytes[i] is 0xE8 or 0xE9 && i + 5 <= bytes.Length)
                    { size = 5; relative = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(i + 1)); }
                    else if ((bytes[i] is 0xEB or >= 0x70 and <= 0x7F) && i + 2 <= bytes.Length)
                    { size = 2; relative = (sbyte)bytes[i + 1]; }
                    else if (bytes[i] == 0x0F && i + 6 <= bytes.Length && bytes[i + 1] is >= 0x80 and <= 0x8F)
                    { size = 6; relative = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(i + 2)); }
                    long target = site + size + relative;
                    if (size != 0 && target > function.BeginRva && target < function.EndRva)
                        return Fail("possible external branch to an interior instruction", out reason);
                }
            }
        }
        catch (Exception error) when (error is ArgumentException or InvalidOperationException or OverflowException)
        {
            return Fail("malformed leaf metadata or address range", out reason);
        }
        return true;
    }

    private static bool Inside(uint rva, FunctionDescriptor function) => rva > function.BeginRva && rva < function.EndRva;
    private static bool Fail(string message, out string reason) { reason = message; return false; }

    private static bool ValidateRelocations(PeImage pe, FunctionDescriptor function, out string reason)
    {
        reason = "";
        var directory = pe.Directory(DataDir.Basereloc);
        if (directory.IsEmpty) return true;
        // Do not use the inspection enumerator's truncated-tail behavior here:
        // rewriting must prove the complete table, not accept a valid prefix.
        if (directory.RelativeVirtualAddress == 0 || directory.Size is < 8 or > 4 * 1024 * 1024
            || (ulong)directory.RelativeVirtualAddress + directory.Size > uint.MaxValue)
            return Fail("malformed or oversized relocation directory", out reason);
        byte[] bytes = pe.ReadRva(directory.RelativeVirtualAddress, (int)directory.Size);
        for (int cursor = 0; cursor < bytes.Length;)
        {
            if (bytes.Length - cursor < 8) return Fail("truncated relocation block", out reason);
            uint page = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(cursor));
            uint blockSize = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(cursor + 4));
            if ((page & 4095) != 0 || blockSize < 8 || (blockSize & 1) != 0 || blockSize > bytes.Length - cursor)
                return Fail("malformed relocation block", out reason);
            for (int offset = cursor + 8; offset < cursor + (int)blockSize; offset += 2)
            {
                ushort entry = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset));
                int type = entry >> 12;
                if (type == 0) continue;
                if (type != Relocations.TypeAbsolute) return Fail("unsupported AMD64 relocation type", out reason);
                ulong rva = (ulong)page + (uint)(entry & 4095);
                if (rva + 8 > pe.SizeOfImage) return Fail("relocation target is outside the image", out reason);
                if (rva < function.EndRva && rva + 8 > function.BeginRva)
                    return Fail("function contains a loader relocation", out reason);
            }
            cursor += (int)blockSize;
        }
        return true;
    }
}
