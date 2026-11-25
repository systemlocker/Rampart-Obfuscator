using System.Buffers.Binary;
using System.Globalization;
using Rampart.Config;
using Rampart.Engine;
using Rampart.Pe;
using Rampart.X64;

namespace Rampart.Strings;

internal readonly record struct StringCandidate(uint Rva, int Length, int Characters, int UnitSize,
    ProtectionLevel Encryption, ProtectionLevel Coverage, ProtectionLevel Integrity,
    IReadOnlyList<FunctionDescriptor> Owners);

/// <summary>Conservative address-taking discovery, not a scan of arbitrary printable bytes.</summary>
internal static class StringCandidates
{
    internal static List<StringCandidate> Find(BuildContext context)
    {
        PeImage pe = context.Pe;
        var excluded = MergeRanges(MetadataRanges(pe));
        var found = new Dictionary<uint, StringCandidate>();
        // Track every observed pointer target (including short <3-char suffixes
        // and relocated DIR64 pointer targets) so interior aliases are rejected.
        var allObservedTargets = new HashSet<uint>();
        foreach (RelocEntry relocation in Relocations.Enumerate(pe))
        {
            if (relocation.Type != Relocations.TypeAbsolute)
                continue;
            if (!pe.TryRvaToOffset(relocation.Rva, out _) || !pe.TryRvaToOffset(checked(relocation.Rva + 7), out _))
                continue;
            ulong targetVa = pe.ReadU64(relocation.Rva);
            if (targetVa >= pe.ImageBase && targetVa - pe.ImageBase < pe.SizeOfImage)
                allObservedTargets.Add((uint)(targetVa - pe.ImageBase));
        }

        foreach (FunctionDescriptor function in context.Functions)
        {
            // Relocated bodies can contain inline tables/bytecode. Their original
            // entry trampoline is not evidence of their original data references.
            if (context.IsFunctionClaimed(function)) continue;
            PeImage.Section? codeSection = pe.SectionFromRva(function.BeginRva);
            if (codeSection is null || !codeSection.IsExecutable) continue;
            int offset = checked((int)(function.BeginRva - codeSection.VirtualAddress));
            int length = (int)Math.Min(function.Size, (uint)Math.Max(0, codeSection.Data.Length - offset));
            if (length <= 0) continue;
            ReadOnlySpan<byte> code = codeSection.Data.AsSpan(offset, length);
            for (int position = 0; position < code.Length;)
            {
                if (!X64Decoder.TryDecode(code, position, function.BeginRva + (uint)position, out var instruction)) break;
                position += instruction.Length;
                if (instruction.Mnemonic != X64Mnemonic.LeaRip) continue;
                uint target = instruction.RipTargetRva;
                allObservedTargets.Add(target);
                if (!Measure(pe, target, out int bytes, out int chars, out int unit)) continue;
                if (IsExcluded(excluded, target, bytes + unit)) continue;
                var candidate = new StringCandidate(target, bytes, chars, unit,
                    context.LevelFor("strings.encryption", function),
                    context.LevelFor("strings.coverage", function),
                    context.LevelFor("strings.anti-instrumentation", function),
                    [function]);
                // Balanced intentionally uses a higher floor than Light. Check
                // each owner's eligibility before merging numeric levels so a
                // shared Light reference cannot bypass a Balanced owner's floor.
                if (chars < MinimumCharacters(candidate.Coverage)
                    || (pe.SectionFromRva(target)!.Characteristics.HasFlag(SectionCharacteristics.MemWrite)
                        && candidate.Coverage != ProtectionLevel.Maximum))
                    candidate = candidate with { Encryption = ProtectionLevel.Off };
                if (found.TryGetValue(target, out var previous))
                {
                    // One storage location cannot follow conflicting policies.
                    // The least permissive reference wins, including explicit Off.
                    candidate = candidate with
                    {
                        Encryption = Min(previous.Encryption, candidate.Encryption),
                        Coverage = Min(previous.Coverage, candidate.Coverage),
                        Integrity = Min(previous.Integrity, candidate.Integrity),
                        Owners = previous.Owners.Concat(candidate.Owners)
                            .DistinctBy(owner => owner.BeginRva).ToArray(),
                    };
                }
                found[target] = candidate;
            }
        }
        var candidates = found.Values.OrderBy(value => value.Rva).ToArray();
        var overlapping = new HashSet<uint>();
        // Sweep complete overlap components, including nested suffix aliases.
        // Discovery remains O(n log n), rather than comparing every pair in
        // applications with tens of thousands of string-address references.
        for (int first = 0; first < candidates.Length;)
        {
            int next = first + 1;
            ulong end = (ulong)candidates[first].Rva + (uint)(candidates[first].Length + candidates[first].UnitSize);
            while (next < candidates.Length && candidates[next].Rva < end)
            {
                end = Math.Max(end, (ulong)candidates[next].Rva + (uint)(candidates[next].Length + candidates[next].UnitSize));
                next++;
            }
            if (next > first + 1)
                for (int index = first; index < next; index++) overlapping.Add(candidates[index].Rva);
            first = next;
        }
        // Also reject any candidate whose interior bytes are referenced by another
        // LEA or DIR64 relocation (for example a 1- or 2-character pooled suffix).
        uint[] sortedTargets = allObservedTargets.OrderBy(rva => rva).ToArray();
        foreach (StringCandidate candidate in candidates)
        {
            ulong end = (ulong)candidate.Rva + (uint)(candidate.Length + candidate.UnitSize);
            int idx = Array.BinarySearch(sortedTargets, candidate.Rva);
            int nextIdx = idx >= 0 ? idx + 1 : ~idx;
            if (nextIdx < sortedTargets.Length && sortedTargets[nextIdx] < end)
                overlapping.Add(candidate.Rva);
        }
        return candidates.Where(value =>
            value.Encryption != ProtectionLevel.Off &&
            value.Characters >= MinimumCharacters(value.Coverage) &&
            (!pe.SectionFromRva(value.Rva)!.Characteristics.HasFlag(SectionCharacteristics.MemWrite)
                || value.Coverage == ProtectionLevel.Maximum) &&
            // Suffix pooling and mixed-width aliases are skipped as an entire
            // overlap component, never encrypted twice with incompatible keys.
            !overlapping.Contains(value.Rva))
            .ToList();
    }

    private static ProtectionLevel Min(ProtectionLevel a, ProtectionLevel b) => (ProtectionLevel)Math.Min((int)a, (int)b);
    private static int MinimumCharacters(ProtectionLevel coverage) =>
        coverage >= ProtectionLevel.Heavy ? 3 : coverage == ProtectionLevel.Balanced ? 8 : 6;
    private static List<(uint Start, ulong End)> MergeRanges(List<(uint Start, int Length)> ranges)
    {
        var merged = new List<(uint Start, ulong End)>();
        foreach (var range in ranges.OrderBy(value => value.Start))
        {
            ulong end = (ulong)range.Start + (uint)range.Length;
            if (merged.Count == 0 || range.Start > merged[^1].End) merged.Add((range.Start, end));
            else merged[^1] = (merged[^1].Start, Math.Max(merged[^1].End, end));
        }
        return merged;
    }

    private static bool IsExcluded(List<(uint Start, ulong End)> ranges, uint rva, int length)
    {
        int low = 0, high = ranges.Count;
        while (low < high)
        {
            int middle = low + (high - low) / 2;
            if (ranges[middle].End <= rva) low = middle + 1;
            else high = middle;
        }
        return low < ranges.Count && ranges[low].Start < (ulong)rva + (uint)length;
    }

    private static bool Measure(PeImage pe, uint rva, out int length, out int characters, out int unit)
    {
        length = characters = 0;
        unit = 1;
        PeImage.Section? section = pe.SectionFromRva(rva);
        if (section is null || section.IsExecutable || section.Name is ".rmpt" or ".rmpd"
            || !section.Characteristics.HasFlag(SectionCharacteristics.CntInitializedData)
            || !section.Characteristics.HasFlag(SectionCharacteristics.MemRead)) return false;
        int start = checked((int)(rva - section.VirtualAddress));
        int end = (int)Math.Min((uint)section.Data.Length, section.ResolvedVirtualSize);
        if (start < 0 || start >= end) return false;
        ReadOnlySpan<byte> data = section.Data.AsSpan(0, end);
        // A preceding terminator is deliberately not required: linker suffix
        // pooling is valid. Overlap rejection is based on all observed targets.
        // Check UTF-16LE before ASCII when the second byte is NUL on an even RVA
        // so ASCII probes do not reject wide strings, and avoid treating plain
        // ASCII text as accidental UTF-16LE CJK code points.
        if ((rva & 1) == 0 && start + 1 < data.Length && data[start] >= 0x20 && data[start + 1] == 0)
        {
            unit = 2;
            return MeasureWidth(data, start, 2, out length, out characters);
        }
        if (MeasureWidth(data, start, 1, out length, out characters)) return true;
        unit = 2;
        return (rva & 1) == 0 && MeasureWidth(data, start, 2, out length, out characters);
    }

    private static bool MeasureWidth(ReadOnlySpan<byte> data, int start, int unit, out int length, out int characters)
    {
        length = characters = 0;
        for (int cursor = start; cursor + unit <= data.Length && characters <= 4096; cursor += unit)
        {
            ushort value = unit == 1 ? data[cursor] : BinaryPrimitives.ReadUInt16LittleEndian(data[cursor..]);
            if (value == 0)
            {
                length = cursor - start;
                return characters >= 3;
            }
            if (unit == 1)
            {
                if (value is < 0x20 or > 0x7e) return false;
            }
            else
            {
                UnicodeCategory category = char.GetUnicodeCategory((char)value);
                if (category is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.Surrogate
                    or UnicodeCategory.OtherNotAssigned or UnicodeCategory.PrivateUse) return false;
            }
            characters++;
        }
        return false;
    }

    private static List<(uint Start, int Length)> MetadataRanges(PeImage pe)
    {
        var ranges = new List<(uint Start, int Length)>();
        for (int index = 0; index < 16; index++)
        {
            DataDirectory directory = pe.Directory(index);
            if (directory.IsEmpty || index == DataDir.Security || directory.RelativeVirtualAddress == 0)
                continue;
            // BoundImport frequently resides inside the PE headers before the first section.
            if (index == DataDir.BoundImport && directory.RelativeVirtualAddress < pe.SizeOfHeaders)
                continue;
            if (directory.Size > int.MaxValue)
            {
                ExcludeSection(directory.RelativeVirtualAddress);
                continue;
            }
            if (index is DataDir.Import or DataDir.Iat or DataDir.Basereloc
                or DataDir.Debug or DataDir.LoadConfig or DataDir.Exception
                or DataDir.Export or DataDir.Tls or DataDir.BoundImport)
            {
                ranges.Add((directory.RelativeVirtualAddress, (int)directory.Size));
            }
            else
            {
                // Resource and other structured directories retain full-section exclusion.
                ExcludeSection(directory.RelativeVirtualAddress);
            }
        }
        foreach (RelocEntry relocation in Relocations.Enumerate(pe))
            ranges.Add((relocation.Rva, 8));

        // Exclude exact UNWIND_INFO spans rather than the entire containing section
        // (MSVC/Clang typically place .xdata inside .rdata alongside string literals).
        foreach (RuntimeFunction function in ExceptionTable.Parse(pe))
            ExcludeUnwindChain(pe, function.UnwindRva, ranges, ExcludeSection);

        DataDirectory tls = pe.Directory(DataDir.Tls);
        if (!tls.IsEmpty && tls.RelativeVirtualAddress != 0 && tls.Size >= 40)
        {
            ranges.Add((tls.RelativeVirtualAddress, checked((int)Math.Max(tls.Size, 40u))));
            ulong start = pe.ReadU64(tls.RelativeVirtualAddress);
            ulong end = pe.ReadU64(tls.RelativeVirtualAddress + 8);
            if (start != 0 && end > start && start >= pe.ImageBase && end - pe.ImageBase <= pe.SizeOfImage)
                ranges.Add((pe.VaToRva(start), checked((int)(end - start))));
            ulong indexVa = pe.ReadU64(tls.RelativeVirtualAddress + 16);
            if (indexVa >= pe.ImageBase && indexVa - pe.ImageBase < pe.SizeOfImage)
                ranges.Add((pe.VaToRva(indexVa), 4));
            ulong callbacksVa = pe.ReadU64(tls.RelativeVirtualAddress + 24);
            if (callbacksVa >= pe.ImageBase && callbacksVa - pe.ImageBase < pe.SizeOfImage)
            {
                uint cbRva = pe.VaToRva(callbacksVa);
                for (uint i = 0; i < 4096; i++)
                {
                    uint slotRva = checked(cbRva + i * 8);
                    if (!pe.TryRvaToOffset(slotRva, out _) || !pe.TryRvaToOffset(checked(slotRva + 7), out _))
                    {
                        ExcludeSection(cbRva);
                        break;
                    }
                    ranges.Add((slotRva, 8));
                    if (pe.ReadU64(slotRva) == 0)
                        break;
                }
            }
        }

        DataDirectory debug = pe.Directory(DataDir.Debug);
        if (!debug.IsEmpty && debug.RelativeVirtualAddress != 0)
        {
            for (uint offset = 0; (ulong)offset + 28 <= debug.Size; offset += 28)
            {
                uint entryRva = checked(debug.RelativeVirtualAddress + offset);
                uint size = pe.ReadU32(checked(entryRva + 16));
                uint rva = pe.ReadU32(checked(entryRva + 20));
                if (rva != 0 && size != 0 && size <= int.MaxValue)
                    ranges.Add((rva, (int)size));
            }
        }

        DataDirectory loadConfig = pe.Directory(DataDir.LoadConfig);
        if (!loadConfig.IsEmpty && loadConfig.RelativeVirtualAddress != 0 && loadConfig.Size >= 4)
            ExcludeLoadConfig(pe, loadConfig, ranges, ExcludeSection);

        DataDirectory exports = pe.Directory(DataDir.Export);
        if (!exports.IsEmpty && exports.RelativeVirtualAddress != 0 && exports.Size >= 40)
        {
            ExcludeString(pe.ReadU32(exports.RelativeVirtualAddress + 12));
            uint functions = pe.ReadU32(exports.RelativeVirtualAddress + 20);
            uint names = pe.ReadU32(exports.RelativeVirtualAddress + 24);
            uint eat = pe.ReadU32(exports.RelativeVirtualAddress + 28);
            uint nameTable = pe.ReadU32(exports.RelativeVirtualAddress + 32);
            uint ordinals = pe.ReadU32(exports.RelativeVirtualAddress + 36);
            if (names > 1_000_000 || functions > 1_000_000) throw new BadImageFormatException("Export table exceeds string discovery bounds.");
            if (eat != 0 && functions > 0) ranges.Add((eat, checked((int)functions * 4)));
            if (nameTable != 0 && names > 0) ranges.Add((nameTable, checked((int)names * 4)));
            if (ordinals != 0 && names > 0) ranges.Add((ordinals, checked((int)names * 2)));
            if (nameTable != 0)
                for (uint index = 0; index < names; index++) ExcludeString(pe.ReadU32(checked(nameTable + index * 4)));
        }
        DataDirectory resources = pe.Directory(DataDir.Resource);
        if (!resources.IsEmpty && resources.RelativeVirtualAddress != 0)
        {
            var pending = new Stack<uint>();
            var visited = new HashSet<uint>();
            pending.Push(0);
            while (pending.TryPop(out uint offset))
            {
                if (!visited.Add(offset)) continue;
                if (visited.Count > 65536 || (ulong)offset + 16 > resources.Size)
                    throw new BadImageFormatException("Resource tree exceeds string discovery bounds.");
                byte[] header = pe.ReadRva(checked(resources.RelativeVirtualAddress + offset), 16);
                uint count = (uint)(BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(12))
                    + BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(14)));
                if ((ulong)offset + 16 + count * 8 > resources.Size)
                    throw new BadImageFormatException("Resource entries exceed directory bounds.");
                for (uint index = 0; index < count; index++)
                {
                    uint target = pe.ReadU32(checked(resources.RelativeVirtualAddress + offset + 20 + index * 8));
                    if ((target & 0x80000000) != 0) pending.Push(target & 0x7fffffff);
                    else
                    {
                        if ((ulong)target + 16 > resources.Size) throw new BadImageFormatException("Resource data entry exceeds directory bounds.");
                        uint at = checked(resources.RelativeVirtualAddress + target);
                        ranges.Add((pe.ReadU32(at), checked((int)pe.ReadU32(at + 4))));
                    }
                }
            }
        }
        // Delay-import pointer graphs and architecture-specific directories are
        // outside this candidate classifier's supported contract. Leave data
        // unchanged instead of treating their transitive payloads as strings.
        if (new[] { DataDir.DelayImport, DataDir.Architecture, DataDir.GlobalPtr, DataDir.ComDescriptor, 15 }
            .Any(index => !pe.Directory(index).IsEmpty))
            foreach (PeImage.Section section in pe.Sections.Where(value => !value.IsExecutable)) ExcludeSection(section.VirtualAddress);
        DataDirectory imports = pe.Directory(DataDir.Import);
        if (!imports.IsEmpty && imports.RelativeVirtualAddress != 0)
        {
            for (uint offset = 0; (ulong)offset + 20 <= imports.Size; offset += 20)
            {
                byte[] descriptor = pe.ReadRva(checked(imports.RelativeVirtualAddress + offset), 20);
                uint lookup = BinaryPrimitives.ReadUInt32LittleEndian(descriptor);
                uint name = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(12));
                uint iat = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(16));
                if (lookup == 0 && name == 0 && iat == 0) break;
                if (name == 0 || iat == 0) break;
                ranges.Add((name, pe.ReadCStringByteLength(name) + 1));
                if (lookup == 0) lookup = iat;
                for (uint slot = 0; slot < 65536; slot++)
                {
                    uint lookupSlot = checked(lookup + slot * 8);
                    uint iatSlot = checked(iat + slot * 8);
                    ranges.Add((lookupSlot, 8));
                    ranges.Add((iatSlot, 8));
                    ulong entry = pe.ReadU64(lookupSlot);
                    if (entry == 0) break;
                    if ((entry & (1UL << 63)) == 0)
                    {
                        uint hintName = checked((uint)entry);
                        ranges.Add((hintName, pe.ReadCStringByteLength(checked(hintName + 2)) + 3));
                    }
                }
            }
        }
        return ranges;

        void ExcludeSection(uint rva)
        {
            PeImage.Section? section = pe.SectionFromRva(rva);
            if (section is not null) ranges.Add((section.VirtualAddress, checked((int)section.ResolvedVirtualSize)));
        }
        void ExcludeString(uint rva)
        {
            if (rva != 0) ranges.Add((rva, pe.ReadCStringByteLength(rva) + 1));
        }
    }

    private static void ExcludeUnwindChain(
        PeImage pe,
        uint unwindRva,
        List<(uint Start, int Length)> ranges,
        Action<uint> excludeSection)
    {
        for (int depth = 0; depth < 16; depth++)
        {
            if (unwindRva == 0)
                return;
            // Bit 0 indicates RUNTIME_FUNCTION_INDIRECT pointing at another 12-byte RUNTIME_FUNCTION.
            if ((unwindRva & 1) != 0)
            {
                uint targetEntry = unwindRva & ~1u;
                if (!pe.TryRvaToOffset(targetEntry, out _) || !pe.TryRvaToOffset(checked(targetEntry + 11), out _))
                {
                    excludeSection(targetEntry);
                    return;
                }
                ranges.Add((targetEntry, 12));
                unwindRva = pe.ReadU32(checked(targetEntry + 8));
                continue;
            }
            if (!pe.TryRvaToOffset(unwindRva, out _) || !pe.TryRvaToOffset(checked(unwindRva + 3), out _))
            {
                excludeSection(unwindRva);
                return;
            }
            byte[] header = pe.ReadRva(unwindRva, 4);
            byte flags = (byte)(header[0] >> 3);
            int codesBytes = ((header[2] + 1) & ~1) * 2;
            int totalBytes = 4 + codesBytes;
            bool chained = (flags & 0x04) != 0;
            bool hasHandler = !chained && (flags & 0x03) != 0;
            if (chained)
                totalBytes += 12;
            else if (hasHandler)
                totalBytes += 4;
            ranges.Add((unwindRva, totalBytes));
            if (!chained)
                return;
            uint chainedEntryRva = checked(unwindRva + (uint)(4 + codesBytes));
            if (!pe.TryRvaToOffset(checked(chainedEntryRva + 11), out _))
                return;
            unwindRva = pe.ReadU32(checked(chainedEntryRva + 8));
        }
    }

    private static void ExcludeLoadConfig(
        PeImage pe,
        DataDirectory loadConfig,
        List<(uint Start, int Length)> ranges,
        Action<uint> excludeSection)
    {
        PeImage.Section? section = pe.SectionFromRva(loadConfig.RelativeVirtualAddress);
        if (section is null)
            return;
        uint declaredSize = pe.ReadU32(loadConfig.RelativeVirtualAddress);
        uint maxAvail = checked(section.SizeOfRawData - (loadConfig.RelativeVirtualAddress - section.VirtualAddress));
        uint effectiveSize = Math.Min(Math.Max(loadConfig.Size, declaredSize), maxAvail);
        if (effectiveSize > int.MaxValue)
        {
            excludeSection(loadConfig.RelativeVirtualAddress);
            return;
        }
        ranges.Add((loadConfig.RelativeVirtualAddress, (int)effectiveSize));

        // Guard flags tell us whether table entries carry extra stride metadata bytes.
        uint guardFlags = effectiveSize >= 0x94
            ? pe.ReadU32(checked(loadConfig.RelativeVirtualAddress + 0x90))
            : 0;
        int extraStride = (int)((guardFlags >> 28) & 0xF);
        int entryStride = 4 + extraStride;

        // Exclude known pointer targets and counted tables referenced by IMAGE_LOAD_CONFIG_DIRECTORY64.
        ExcludePointerSlot(0x40, 8);  // LockPrefixTable
        ExcludePointerSlot(0x58, 8);  // SecurityCookie
        ExcludeCountedTable(0x60, 0x68, 4); // SEHandlerTable (rare on x64)
        ExcludePointerSlot(0x70, 8);  // GuardCFCheckFunctionPointer
        ExcludePointerSlot(0x78, 8);  // GuardCFDispatchFunctionPointer
        ExcludeCountedTable(0x80, 0x88, entryStride); // GuardCFFunctionTable
        ExcludeCountedTable(0xA0, 0xA8, entryStride); // GuardAddressTakenIatEntryTable
        ExcludeCountedTable(0xB0, 0xB8, entryStride); // GuardLongJumpTargetTable
        ExcludePointerSlot(0xC0, 8);  // DynamicValueRelocTable
        ExcludePointerSlot(0xC8, 8);  // CHPEMetadataPointer
        ExcludePointerSlot(0xD0, 8);  // GuardRFFailureRoutine
        ExcludePointerSlot(0xD8, 8);  // GuardRFFailureRoutineFunctionPointer
        ExcludePointerSlot(0x100, 8); // GuardXFGCheckFunctionPointer
        ExcludePointerSlot(0x108, 8); // GuardXFGDispatchFunctionPointer
        ExcludePointerSlot(0x110, 8); // GuardXFGTableDispatchFunctionPointer
        ExcludePointerSlot(0x118, 8); // CastGuardOsDeterminedFailureMode
        ExcludePointerSlot(0x120, 8); // GuardMemcpyFunctionPointer
        ExcludeCountedTable(0xF0, 0xF8, entryStride); // GuardEHContinuationTable

        void ExcludePointerSlot(uint fieldOffset, int bytes)
        {
            if ((ulong)fieldOffset + 8 > effectiveSize)
                return;
            ulong va = pe.ReadU64(checked(loadConfig.RelativeVirtualAddress + fieldOffset));
            if (va >= pe.ImageBase && va - pe.ImageBase < pe.SizeOfImage)
                ranges.Add(((uint)(va - pe.ImageBase), bytes));
        }

        void ExcludeCountedTable(uint tableOffset, uint countOffset, int stride)
        {
            if ((ulong)countOffset + 8 > effectiveSize)
                return;
            ulong tableVa = pe.ReadU64(checked(loadConfig.RelativeVirtualAddress + tableOffset));
            ulong count = pe.ReadU64(checked(loadConfig.RelativeVirtualAddress + countOffset));
            if (tableVa < pe.ImageBase || tableVa - pe.ImageBase >= pe.SizeOfImage || count == 0)
                return;
            ulong total = count > (ulong)(int.MaxValue / Math.Max(1, stride)) ? ulong.MaxValue : count * (ulong)stride;
            uint rva = (uint)(tableVa - pe.ImageBase);
            if (total > int.MaxValue)
                excludeSection(rva);
            else
                ranges.Add((rva, (int)total));
        }
    }
}
