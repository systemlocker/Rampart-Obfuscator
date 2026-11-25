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
    private sealed class ScanBudget
    {
        public long Used;
        public int Attempts;
        public ulong CachedFingerprint;
        public bool HasCache;
        public (uint Target, uint Site)[] StoredRvas = [];
        public (uint Target, uint Site)[] StoredVas = [];
        public (uint Target, uint Site)[] RipRefs = [];
        public (uint Target, uint Site)[] BranchTargets = [];
    }
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
        if (HasUnsupportedLoadConfig(pe))
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
            if (!ValidateRelocations(pe, function, out reason)) return false;

            // Build the whole-image interior-reference index once per image state,
            // invalidating automatically if any section bytes change between calls.
            ulong fingerprint = ComputeImageFingerprint(pe);
            lock (budget)
            {
                if (!budget.HasCache || budget.CachedFingerprint != fingerprint)
                {
                    long scanSize = pe.Sections.Sum(s => (long)s.Data.Length);
                    if (scanSize > 32 * 1024 * 1024)
                        return Fail("image exceeds the bounded entry-reference scan", out reason);
                    if (budget.Used + scanSize > 64 * 1024 * 1024)
                        return Fail("build exhausted its leaf entry-reference scan budget", out reason);
                    budget.Used += scanSize;
                    BuildReferenceIndex(pe, budget);
                    budget.CachedFingerprint = fingerprint;
                    budget.HasCache = true;
                }
            }

            if (HasExternalTargetInside(budget.StoredRvas, function))
                return Fail("possible stored interior RVA", out reason);
            if (HasExternalTargetInside(budget.StoredVas, function))
                return Fail("possible stored interior address", out reason);
            if (HasExternalTargetInside(budget.RipRefs, function))
                return Fail("possible RIP-relative interior reference", out reason);
            if (HasExternalTargetInside(budget.BranchTargets, function))
                return Fail("possible external branch to an interior instruction", out reason);
        }
        catch (Exception error) when (error is ArgumentException or InvalidOperationException or OverflowException)
        {
            return Fail("malformed leaf metadata or address range", out reason);
        }
        return true;
    }

    /// <summary>Allows benign LoadConfig tables (such as SecurityCookie-only MSVC
    /// builds) while failing closed on malformed/truncated LoadConfig or images
    /// carrying Guard CF, CET, longjmp, or EH-continuation target inventories.</summary>
    private static bool HasUnsupportedLoadConfig(PeImage pe)
    {
        if (pe.DllChars.HasFlag(DllCharacteristics.GuardCf))
            return true;
        DataDirectory loadConfig = pe.Directory(DataDir.LoadConfig);
        if (loadConfig.IsEmpty)
            return false;
        if (loadConfig.RelativeVirtualAddress == 0 || loadConfig.Size < 0x94
            || !pe.TryRvaToOffset(loadConfig.RelativeVirtualAddress, out _))
            return true;
        PeImage.Section? sec = pe.SectionFromRva(loadConfig.RelativeVirtualAddress);
        if (sec is null)
            return true;
        uint avail = checked(sec.SizeOfRawData - (loadConfig.RelativeVirtualAddress - sec.VirtualAddress));
        uint structSize = pe.ReadU32(loadConfig.RelativeVirtualAddress);
        uint effectiveSize = Math.Min(Math.Max(loadConfig.Size, structSize), avail);
        if (structSize < 0x94 || effectiveSize < 0x94)
            return true;

        uint guardFlags = pe.ReadU32(checked(loadConfig.RelativeVirtualAddress + 0x90));
        const uint UnsupportedGuardMask =
            (uint)ImageGuardFlags.CfInstrumented
            | (uint)ImageGuardFlags.CfFunctionTablePresent
            | 0x00010000u /* IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT */
            | (uint)ImageGuardFlags.EhContinuationTablePresent
            | 0x00020000u /* IMAGE_GUARD_RF_INSTRUMENTED */
            | 0x00040000u /* IMAGE_GUARD_RF_ENABLE */
            | 0x00080000u /* IMAGE_GUARD_RF_STRICT */;
        if ((guardFlags & UnsupportedGuardMask) != 0)
            return true;

        // Also reject non-empty Guard CF, IAT, longjmp, or EH-continuation tables.
        foreach (uint countOffset in new uint[] { 0x88, 0xA8, 0xB8, 0xF8 })
        {
            if (effectiveSize >= countOffset + 8 && pe.ReadU64(checked(loadConfig.RelativeVirtualAddress + countOffset)) != 0)
                return true;
        }
        return false;
    }

    private static ulong ComputeImageFingerprint(PeImage pe)
    {
        ulong hash = 14695981039346656037UL;
        foreach (PeImage.Section sec in pe.Sections)
        {
            hash = unchecked((hash ^ sec.VirtualAddress) * 1099511628211UL);
            hash = unchecked((hash ^ (uint)sec.Data.Length) * 1099511628211UL);
            hash = unchecked((hash ^ (uint)sec.Characteristics) * 1099511628211UL);
            ReadOnlySpan<byte> data = sec.Data;
            int i = 0;
            for (; i + 8 <= data.Length; i += 8)
                hash = unchecked((hash ^ BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(i, 8))) * 1099511628211UL);
            for (; i < data.Length; i++)
                hash = unchecked((hash ^ data[i]) * 1099511628211UL);
        }
        return hash;
    }

    private static void BuildReferenceIndex(PeImage pe, ScanBudget budget)
    {
        // Only record targets that fall inside some executable section, keeping
        // the cached arrays compact and fast to binary-search per candidate function.
        var execRanges = pe.Sections
            .Where(s => s.IsExecutable)
            .Select(s => (Start: s.VirtualAddress, End: checked(s.VirtualAddress + s.ResolvedVirtualSize)))
            .ToArray();

        bool InExecutable(ulong rva)
        {
            for (int r = 0; r < execRanges.Length; r++)
                if (rva >= execRanges[r].Start && rva < execRanges[r].End)
                    return true;
            return false;
        }

        var storedRvas = new List<(uint Target, uint Site)>();
        var storedVas = new List<(uint Target, uint Site)>();
        var ripRefs = new List<(uint Target, uint Site)>();
        var branchTargets = new List<(uint Target, uint Site)>();

        foreach (var source in pe.Sections)
        {
            byte[] bytes = source.Data;
            for (int i = 0; i < bytes.Length; i++)
            {
                uint site = checked(source.VirtualAddress + (uint)i);
                if (i + 4 <= bytes.Length)
                {
                    uint val = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i));
                    if (InExecutable(val))
                        storedRvas.Add((val, site));
                }
                if (i + 8 <= bytes.Length)
                {
                    ulong pointer = BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(i));
                    if (pointer >= pe.ImageBase && pointer - pe.ImageBase <= uint.MaxValue)
                    {
                        uint vaRva = (uint)(pointer - pe.ImageBase);
                        if (InExecutable(vaRva))
                            storedVas.Add((vaRva, site));
                    }
                }
                if (!source.IsExecutable)
                    continue;
                if (bytes[i] is 0x8D or 0x8B && i + 6 <= bytes.Length && (bytes[i + 1] & 0xC7) == 0x05)
                {
                    long pointerTarget = (long)site + 6 + BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(i + 2));
                    if (pointerTarget >= 0 && pointerTarget <= uint.MaxValue && InExecutable((uint)pointerTarget))
                        ripRefs.Add(((uint)pointerTarget, site));
                }
                int size = 0, relative = 0;
                if (bytes[i] is 0xE8 or 0xE9 && i + 5 <= bytes.Length)
                { size = 5; relative = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(i + 1)); }
                else if ((bytes[i] is 0xEB or >= 0x70 and <= 0x7F) && i + 2 <= bytes.Length)
                { size = 2; relative = (sbyte)bytes[i + 1]; }
                else if (bytes[i] == 0x0F && i + 6 <= bytes.Length && bytes[i + 1] is >= 0x80 and <= 0x8F)
                { size = 6; relative = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(i + 2)); }
                if (size != 0)
                {
                    long target = (long)site + size + relative;
                    if (target >= 0 && target <= uint.MaxValue && InExecutable((uint)target))
                        branchTargets.Add(((uint)target, site));
                }
            }
        }

        static (uint Target, uint Site)[] SortPairs(List<(uint Target, uint Site)> items)
        {
            items.Sort(static (a, b) => a.Target.CompareTo(b.Target));
            return items.ToArray();
        }

        budget.StoredRvas = SortPairs(storedRvas);
        budget.StoredVas = SortPairs(storedVas);
        budget.RipRefs = SortPairs(ripRefs);
        budget.BranchTargets = SortPairs(branchTargets);
    }

    private static bool HasExternalTargetInside((uint Target, uint Site)[] sorted, FunctionDescriptor function)
    {
        // Binary search for the first entry with Target > function.BeginRva.
        int low = 0, high = sorted.Length;
        while (low < high)
        {
            int mid = low + (high - low) / 2;
            if (sorted[mid].Target <= function.BeginRva)
                low = mid + 1;
            else
                high = mid;
        }
        for (int i = low; i < sorted.Length && sorted[i].Target < function.EndRva; i++)
        {
            uint site = sorted[i].Site;
            if (site < function.BeginRva || site >= function.EndRva)
                return true;
        }
        return false;
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
