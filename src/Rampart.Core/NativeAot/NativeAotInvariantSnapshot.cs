using System.Buffers.Binary;
using System.Security.Cryptography;
using Rampart.Engine;
using Rampart.Pe;

namespace Rampart.NativeAot;

/// <summary>Conservative ownership: every byte is runtime-owned except explicitly
/// selected cosmetic header fields. No runtime table discovery grants write access.</summary>
public sealed class NativeAotInvariantSnapshot
{
    public const int MaximumRuntimeFunctions = 1_000_000;
    public const int MaximumImportDescriptors = 4096;
    public const int MaximumImportThunks = 65_536;
    private readonly byte[] _original;
    public IReadOnlyList<NativeAotOwnedRange> OwnedRanges { get; }
    internal int PeOffset { get; }
    internal int OptionalOffset => PeOffset + 24;
    internal int SectionTableOffset { get; }
    internal int SectionCount { get; }

    private NativeAotInvariantSnapshot(byte[] image, PeImage pe)
    {
        _original = (byte[])image.Clone();
        PeOffset = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(0x3c));
        SectionTableOffset = OptionalOffset + pe.SizeOfOptionalHeader;
        SectionCount = pe.Sections.Count;
        var ranges = pe.Sections.Select((section, index) => new NativeAotOwnedRange(
            $"section:{index}:{section.Name}", checked((int)section.PointerToRawData),
            checked((int)section.SizeOfRawData), Hash(image.AsSpan(checked((int)section.PointerToRawData), checked((int)section.SizeOfRawData))))).ToList();
        string[] names = ["exports", "imports", "resources", "exception-unwind", "certificate", "relocations", "debug", "architecture", "global-pointer", "tls", "load-configuration", "bound-imports", "iat", "delay-imports", "clr", "reserved"];
        for (int index = 0; index < Math.Min(pe.NumberOfRvaAndSizes, 16); index++)
        {
            var directory = pe.Directory(index);
            if (directory.Size == 0) continue;
            int offset = index == DataDir.Security ? checked((int)directory.RelativeVirtualAddress) : pe.RvaToOffset(directory.RelativeVirtualAddress);
            ranges.Add(new(names[index], offset, checked((int)directory.Size), Hash(image.AsSpan(offset, checked((int)directory.Size)))));
        }
        int rawEnd = checked((int)pe.Sections.Max(section => (ulong)section.PointerToRawData + section.SizeOfRawData));
        if (rawEnd < image.Length) ranges.Add(new("overlay", rawEnd, image.Length - rawEnd, Hash(image.AsSpan(rawEnd))));
        OwnedRanges = ranges;
    }

    public static NativeAotInvariantSnapshot Capture(byte[] image)
    {
        ArgumentNullException.ThrowIfNull(image);
        if (image.Length > 256 * 1024 * 1024) throw Error("Image exceeds the 256 MiB validation limit.");
        try
        {
            PeImage pe = ValidateImage(image);
            return new(image, pe);
        }
        catch (NativeAotCompatibilityException) { throw; }
        catch (Exception exception) when (exception is BadImageFormatException or ArgumentException or OverflowException or InvalidOperationException)
        { throw Error("The image contains malformed or unsupported PE metadata."); }
    }

    public void ValidateUnchanged(byte[] candidate) => Validate(candidate, []);

    internal void Validate(byte[] candidate, IReadOnlyList<(int Offset, int Length)> allowed)
    {
        if (candidate.Length != _original.Length)
            throw new NativeAotCompatibilityException("NAOT_INVARIANT_FAILED", "A pass changed the image length.");
        // Compare the complement of a short, fixed allowlist instead of trusting
        // a table inventory to enumerate every NativeAOT runtime-owned structure.
        int cursor = 0;
        foreach (var range in allowed.OrderBy(range => range.Offset))
        {
            if (range.Offset < cursor || range.Length < 0 || range.Offset > candidate.Length - range.Length)
                throw new NativeAotCompatibilityException("NAOT_INVARIANT_FAILED", "A pass declared an invalid byte range.");
            if (!_original.AsSpan(cursor, range.Offset - cursor).SequenceEqual(candidate.AsSpan(cursor, range.Offset - cursor)))
                throw new NativeAotCompatibilityException("NAOT_INVARIANT_FAILED", "A pass modified runtime-owned bytes.");
            cursor = range.Offset + range.Length;
        }
        if (!_original.AsSpan(cursor).SequenceEqual(candidate.AsSpan(cursor)))
            throw new NativeAotCompatibilityException("NAOT_INVARIANT_FAILED", "A pass modified runtime-owned bytes.");
        _ = ValidateImage(candidate);
    }

    internal static PeImage ValidateImage(byte[] image)
    {
        if (image.Length < 256 || BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(0x3c)) < 64)
            throw Error("The image header is truncated.");
        PeImage pe = PeImage.Load(image);
        if (pe.Sections.Count is 0 or > 96) throw Error("The section count is outside the supported range.");
        if (pe.Directory(DataDir.Exception).Size > MaximumRuntimeFunctions * 12u)
            throw Error("The exception directory exceeds the runtime-function limit.");
        if (pe.Directory(DataDir.Import).Size > MaximumImportDescriptors * 20u
            || pe.Directory(DataDir.DelayImport).Size > MaximumImportDescriptors * 32u
            || pe.Directory(DataDir.BoundImport).Size > 65536)
            throw Error("An import directory exceeds the descriptor limit.");
        ValidateBoundImportNames(pe);
        PeCompatibility.Validate(pe);
        var raw = pe.Sections.Where(section => section.SizeOfRawData > 0).OrderBy(section => section.PointerToRawData).ToArray();
        ulong end = pe.SizeOfHeaders;
        foreach (var section in raw)
        {
            if (section.PointerToRawData < end || section.PointerToRawData % pe.FileAlignment != 0)
                throw Error("Section file ranges overlap or have invalid alignment.");
            end = (ulong)section.PointerToRawData + section.SizeOfRawData;
        }
        end = pe.SizeOfHeaders;
        foreach (var section in pe.Sections.OrderBy(section => section.VirtualAddress))
        {
            if (section.VirtualAddress < end || section.VirtualAddress % pe.SectionAlignment != 0)
                throw Error("Section virtual ranges overlap or have invalid alignment.");
            end = (ulong)section.VirtualAddress + section.ResolvedVirtualSize;
            if (end > pe.SizeOfImage) throw Error("A section exceeds SizeOfImage.");
        }
        for (int index = 0; index < pe.NumberOfRvaAndSizes; index++)
        {
            var directory = pe.Directory(index);
            if (directory.RelativeVirtualAddress == 0 && directory.Size == 0) continue;
            // GlobalPtr has an address and no size by PE specification.
            if (index == 8 && directory.Size == 0) { _ = pe.RvaToOffset(directory.RelativeVirtualAddress); continue; }
            if (directory.RelativeVirtualAddress == 0 || directory.Size == 0 || directory.Size > image.Length)
                throw Error("A data directory has invalid bounds.");
            if (index == DataDir.Security)
            {
                if ((ulong)directory.RelativeVirtualAddress + directory.Size > (ulong)image.Length || directory.RelativeVirtualAddress % 8 != 0)
                    throw Error("The certificate table has invalid bounds.");
            }
            else EnsureBacked(pe, directory.RelativeVirtualAddress, directory.Size);
        }
        var exceptionDirectory = pe.Directory(DataDir.Exception);
        if (exceptionDirectory.Size % 12 != 0) throw Error("The exception directory contains an incomplete entry.");
        uint priorFunctionEnd = 0;
        for (uint cursor = 0; cursor < exceptionDirectory.Size; cursor += 12)
        {
            byte[] row = pe.ReadRva(checked(exceptionDirectory.RelativeVirtualAddress + cursor), 12);
            uint begin = BinaryPrimitives.ReadUInt32LittleEndian(row);
            uint endRva = BinaryPrimitives.ReadUInt32LittleEndian(row.AsSpan(4));
            if (begin == 0 || begin < priorFunctionEnd || endRva <= begin)
                throw Error("The exception table is unsorted or has overlapping function ranges.");
            priorFunctionEnd = endRva;
        }
        foreach (var function in ExceptionTable.Parse(pe))
        {
            if (function.EndRva <= function.BeginRva || pe.SectionFromRva(function.BeginRva) is not { IsExecutable: true })
                throw Error("A runtime function has invalid code bounds.");
            EnsureBacked(pe, function.BeginRva, function.EndRva - function.BeginRva);
            EnsureBacked(pe, function.UnwindRva, 4);
            var unwind = pe.ReadRva(function.UnwindRva, 4);
            if ((unwind[0] & 7) is not (1 or 2)) throw Error("A runtime function uses an unsupported unwind encoding.");
            uint unwindSize = 4u + (uint)((unwind[2] + 1) & ~1) * 2u;
            int flags = unwind[0] >> 3;
            if ((flags & 4) != 0) unwindSize += 12;
            else if ((flags & 3) != 0) unwindSize += 4;
            EnsureBacked(pe, function.UnwindRva, unwindSize);
        }
        var relocationDirectory = pe.Directory(DataDir.Basereloc);
        uint consumed = 0;
        while (consumed < relocationDirectory.Size)
        {
            if (relocationDirectory.Size - consumed < 8) throw Error("A relocation block is truncated.");
            byte[] header = pe.ReadRva(relocationDirectory.RelativeVirtualAddress + consumed, 8);
            uint page = BinaryPrimitives.ReadUInt32LittleEndian(header);
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(4));
            if (size < 8 || size % 2 != 0 || size > relocationDirectory.Size - consumed)
                throw Error("A relocation block has invalid bounds.");
            byte[] entries = pe.ReadRva(relocationDirectory.RelativeVirtualAddress + consumed + 8, checked((int)size - 8));
            for (int index = 0; index < entries.Length; index += 2)
            {
                ushort entry = BinaryPrimitives.ReadUInt16LittleEndian(entries.AsSpan(index));
                int type = entry >> 12;
                if (type == 0) continue;
                if (type != 10) throw Error("A relocation has an unsupported NativeAOT x64 type.");
                EnsureBacked(pe, checked(page + (uint)(entry & 0xfff)), 8);
            }
            consumed += size;
        }
        ValidateImports(pe);
        return pe;
    }

    private static void ValidateImports(PeImage pe)
    {
        var directory = pe.Directory(DataDir.Import);
        if (directory.IsEmpty) return;
        int totalThunks = 0;
        for (uint cursor = 0; cursor + 20 <= directory.Size; cursor += 20)
        {
            byte[] descriptor = pe.ReadRva(checked(directory.RelativeVirtualAddress + cursor), 20);
            uint lookup = BinaryPrimitives.ReadUInt32LittleEndian(descriptor);
            uint name = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(12));
            uint iat = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(16));
            if (lookup == 0 && name == 0 && iat == 0) return;
            if (name == 0 || iat == 0) throw Error("An import descriptor is incomplete.");
            ValidateName(pe, name);
            if (lookup == 0) lookup = iat;
            for (uint index = 0; ; index++)
            {
                // A global budget prevents thousands of descriptors from each
                // aliasing the same long thunk array and multiplying allocations.
                if (++totalThunks > MaximumImportThunks) throw Error("The image exceeds the aggregate import-thunk limit.");
                ulong value = pe.ReadU64(checked(lookup + index * 8));
                if (value == 0) break;
                EnsureBacked(pe, checked(iat + index * 8), 8);
                if ((value & 0x8000000000000000UL) == 0)
                {
                    uint hint = checked((uint)value);
                    EnsureBacked(pe, hint, 2);
                    ValidateName(pe, checked(hint + 2));
                }
            }
        }
        throw Error("The import directory has no terminating descriptor.");
    }

    private static void ValidateBoundImportNames(PeImage pe)
    {
        var directory = pe.Directory(DataDir.BoundImport);
        for (uint cursor = 0; !directory.IsEmpty && cursor + 8 <= directory.Size;)
        {
            byte[] descriptor = pe.ReadRva(checked(directory.RelativeVirtualAddress + cursor), 8);
            uint timestamp = BinaryPrimitives.ReadUInt32LittleEndian(descriptor);
            ushort name = BinaryPrimitives.ReadUInt16LittleEndian(descriptor.AsSpan(4));
            ushort forwarders = BinaryPrimitives.ReadUInt16LittleEndian(descriptor.AsSpan(6));
            if (timestamp == 0 && name == 0 && forwarders == 0) return;
            if (name >= directory.Size) throw Error("A bound import name is outside its directory.");
            ValidateName(pe, checked(directory.RelativeVirtualAddress + name));
            cursor = checked(cursor + 8u + (uint)forwarders * 8u);
        }
    }

    private static void ValidateName(PeImage pe, uint rva)
    {
        var section = pe.SectionFromRva(rva);
        if (section is null || rva - section.VirtualAddress >= section.SizeOfRawData)
            throw Error("An import name is outside file-backed data.");
        int offset = checked((int)(rva - section.VirtualAddress));
        int available = Math.Min(4096, section.Data.Length - offset);
        if (section.Data.AsSpan(offset, available).IndexOf((byte)0) < 0)
            throw Error("An import name exceeds its bounded string length.");
    }

    private static void EnsureBacked(PeImage pe, uint rva, uint size)
    {
        var section = pe.SectionFromRva(rva);
        if (section is null || (ulong)rva - section.VirtualAddress + size > section.SizeOfRawData)
            throw Error("A runtime-owned range is not completely backed by one section.");
    }

    internal static string Hash(ReadOnlySpan<byte> bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    private static NativeAotCompatibilityException Error(string message) => new("NAOT_INVALID_IMAGE", message);
}
