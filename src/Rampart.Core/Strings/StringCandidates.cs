using System.Buffers.Binary;
using System.Globalization;
using Rampart.Config;
using Rampart.Engine;
using Rampart.Pe;
using Rampart.X64;

namespace Rampart.Strings;

internal readonly record struct StringCandidate(uint Rva, int Length, int Characters, int UnitSize,
    ProtectionLevel Encryption, ProtectionLevel Coverage, ProtectionLevel Integrity);

/// <summary>Conservative address-taking discovery, not a scan of arbitrary printable bytes.</summary>
internal static class StringCandidates
{
    internal static List<StringCandidate> Find(BuildContext context)
    {
        PeImage pe = context.Pe;
        var excluded = MergeRanges(MetadataRanges(pe));
        var found = new Dictionary<uint, StringCandidate>();
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
                if (!Measure(pe, instruction.RipTargetRva, out int bytes, out int chars, out int unit)) continue;
                uint target = instruction.RipTargetRva;
                if (IsExcluded(excluded, target, bytes + unit)) continue;
                var candidate = new StringCandidate(target, bytes, chars, unit,
                    context.LevelFor("strings.encryption", function),
                    context.LevelFor("strings.coverage", function),
                    context.LevelFor("strings.anti-instrumentation", function));
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
        int end = (int)Math.Min((uint)section.Data.Length, section.VirtualSize);
        if (start < 0 || start >= end) return false;
        ReadOnlySpan<byte> data = section.Data.AsSpan(0, end);
        // A preceding terminator is deliberately not required: linker suffix
        // pooling is valid. Overlap rejection is based on all observed targets.
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
            if (directory.IsEmpty || index == DataDir.Security) continue;
            if (index is DataDir.Import or DataDir.Iat or DataDir.Basereloc)
                ranges.Add((directory.RelativeVirtualAddress, checked((int)directory.Size)));
            else
            {
                // Unwind, resources, exports, TLS, and load-config records have
                // nested ownership. Do not guess strings within their sections.
                PeImage.Section? section = pe.SectionFromRva(directory.RelativeVirtualAddress);
                if (section is not null) ranges.Add((section.VirtualAddress, checked((int)section.ResolvedVirtualSize)));
            }
        }
        foreach (RelocEntry relocation in Relocations.Enumerate(pe))
            ranges.Add((relocation.Rva, 8));
        foreach (RuntimeFunction function in ExceptionTable.Parse(pe)) ExcludeSection(function.UnwindRva);
        DataDirectory tls = pe.Directory(DataDir.Tls);
        if (!tls.IsEmpty)
        {
            ulong start = pe.ReadU64(tls.RelativeVirtualAddress), end = pe.ReadU64(tls.RelativeVirtualAddress + 8);
            if (start != 0 && end > start) ranges.Add((pe.VaToRva(start), checked((int)(end - start))));
            // The TLS index and callback array are loader-owned even when placed
            // outside the section containing IMAGE_TLS_DIRECTORY64.
            for (uint offset = 16; offset <= 24; offset += 8)
            {
                ulong pointer = pe.ReadU64(tls.RelativeVirtualAddress + offset);
                if (pointer != 0) ExcludeSection(pe.VaToRva(pointer));
            }
        }
        DataDirectory debug = pe.Directory(DataDir.Debug);
        for (uint offset = 0; (ulong)offset + 28 <= debug.Size; offset += 28)
        {
            uint size = pe.ReadU32(debug.RelativeVirtualAddress + offset + 16);
            uint rva = pe.ReadU32(debug.RelativeVirtualAddress + offset + 20);
            if (rva != 0 && size != 0) ranges.Add((rva, checked((int)size)));
        }
        DataDirectory loadConfig = pe.Directory(DataDir.LoadConfig);
        // Load-config evolves across toolchains. Conservatively retain every
        // section targeted by an in-image VA, rather than claiming knowledge of
        // future security-cookie/CFG/XFG/dynamic-relocation record layouts.
        for (uint offset = 0; (ulong)offset + 8 <= loadConfig.Size; offset += 8)
        {
            ulong pointer = pe.ReadU64(loadConfig.RelativeVirtualAddress + offset);
            if (pointer >= pe.ImageBase && pointer - pe.ImageBase < pe.SizeOfImage)
                ExcludeSection((uint)(pointer - pe.ImageBase));
        }
        DataDirectory exports = pe.Directory(DataDir.Export);
        if (!exports.IsEmpty)
        {
            ExcludeString(pe.ReadU32(exports.RelativeVirtualAddress + 12));
            uint functions = pe.ReadU32(exports.RelativeVirtualAddress + 20);
            uint names = pe.ReadU32(exports.RelativeVirtualAddress + 24);
            uint eat = pe.ReadU32(exports.RelativeVirtualAddress + 28);
            uint nameTable = pe.ReadU32(exports.RelativeVirtualAddress + 32);
            uint ordinals = pe.ReadU32(exports.RelativeVirtualAddress + 36);
            if (names > 1_000_000 || functions > 1_000_000) throw new BadImageFormatException("Export table exceeds string discovery bounds.");
            ranges.Add((eat, checked((int)functions * 4)));
            ranges.Add((nameTable, checked((int)names * 4)));
            ranges.Add((ordinals, checked((int)names * 2)));
            for (uint index = 0; index < names; index++) ExcludeString(pe.ReadU32(nameTable + index * 4));
        }
        DataDirectory resources = pe.Directory(DataDir.Resource);
        if (!resources.IsEmpty)
        {
            var pending = new Stack<uint>();
            var visited = new HashSet<uint>();
            pending.Push(0);
            while (pending.TryPop(out uint offset))
            {
                if (!visited.Add(offset)) continue;
                if (visited.Count > 65536 || (ulong)offset + 16 > resources.Size)
                    throw new BadImageFormatException("Resource tree exceeds string discovery bounds.");
                byte[] header = pe.ReadRva(resources.RelativeVirtualAddress + offset, 16);
                uint count = (uint)(BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(12))
                    + BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(14)));
                if ((ulong)offset + 16 + count * 8 > resources.Size)
                    throw new BadImageFormatException("Resource entries exceed directory bounds.");
                for (uint index = 0; index < count; index++)
                {
                    uint target = pe.ReadU32(resources.RelativeVirtualAddress + offset + 20 + index * 8);
                    if ((target & 0x80000000) != 0) pending.Push(target & 0x7fffffff);
                    else
                    {
                        if ((ulong)target + 16 > resources.Size) throw new BadImageFormatException("Resource data entry exceeds directory bounds.");
                        uint at = resources.RelativeVirtualAddress + target;
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
        for (uint offset = 0; (ulong)offset + 20 <= imports.Size; offset += 20)
        {
            byte[] descriptor = pe.ReadRva(imports.RelativeVirtualAddress + offset, 20);
            if (descriptor.All(value => value == 0)) break;
            uint lookup = BinaryPrimitives.ReadUInt32LittleEndian(descriptor);
            uint name = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(12));
            uint iat = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(16));
            ranges.Add((name, pe.ReadCString(name).Length + 1));
            if (lookup == 0) lookup = iat;
            for (uint slot = 0; slot < 65536; slot++)
            {
                ranges.Add((checked(lookup + slot * 8), 8));
                ranges.Add((checked(iat + slot * 8), 8));
                ulong entry = pe.ReadU64(checked(lookup + slot * 8));
                if (entry == 0) break;
                if ((entry & (1UL << 63)) == 0)
                {
                    uint hintName = checked((uint)entry);
                    ranges.Add((hintName, pe.ReadCString(checked(hintName + 2)).Length + 3));
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
            if (rva != 0) ranges.Add((rva, pe.ReadCString(rva).Length + 1));
        }
    }
}
