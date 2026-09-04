using System.Buffers.Binary;
using Rampart.Engine;
using Rampart.Pe;

namespace Rampart.Packing;

/// <summary>Captures eligibility before other transforms can erase loader metadata
/// or make originally read-only sections writable.</summary>
internal sealed class PackingInputPlan
{
    public IReadOnlyList<PeImage.Section> Sections { get; }
    private const SectionCharacteristics Eligible = SectionCharacteristics.CntInitializedData
        | SectionCharacteristics.MemRead | SectionCharacteristics.MemWrite;

    public PackingInputPlan(BuildContext context)
    {
        PeImage pe = context.Pe;
        if (!pe.IsPe32Plus || pe.Machine != MachineType.Amd64 || (pe.Characteristics & 0x2000) != 0)
            Reject("requires a native AMD64 executable");
        if (pe.SectionAlignment < 4096 || pe.DllChars.HasFlag(DllCharacteristics.GuardCf))
            Reject("does not support shared section pages or Guard CF images");
        if (context.Stub != null || context.Data != null)
            Reject("must inspect the original image before runtime sections are allocated");

        Sections = pe.Sections.Where(s => s.Characteristics == Eligible && s.SizeOfRawData > 0).ToArray();
        if (Sections.Count == 0)
            Reject("found no original initialized writable non-executable sections");
        foreach (PeImage.Section section in Sections)
        {
            if (section.SizeOfRawData > 16 * 1024 * 1024 || section.Data.Length != section.SizeOfRawData)
                Reject("requires complete data sections no larger than 16 MiB");
            ulong start = section.VirtualAddress;
            ulong end = start + section.ResolvedVirtualSize;
            if (start % pe.SectionAlignment != 0 || end > pe.SizeOfImage)
                Reject("found an invalid writable section mapping");
            foreach (PeImage.Section other in pe.Sections.Where(s => s != section))
                if (start < (ulong)other.VirtualAddress + other.ResolvedVirtualSize && other.VirtualAddress < end)
                    Reject("does not support overlapping virtual sections");
        }
        ValidateMetadata(pe, original: true);
    }

    public void ValidateMetadata(PeImage pe, bool original)
    {
        for (int i = 0; i < 16; i++)
        {
            DataDirectory directory = pe.Directory(i);
            if (directory.IsEmpty)
                continue;
            // Security is a file offset, not a loader RVA; the pipeline clears
            // invalidated signatures before compacting the file, retaining overlay bytes.
            if (i == DataDir.Security)
                continue;
            if (i is not (DataDir.Import or DataDir.Iat or DataDir.Exception or DataDir.Basereloc))
                Reject($"does not support {(original ? "original" : "generated")} {DataDir.Names[i]} metadata");
            RequireOutside(pe, directory.RelativeVirtualAddress, directory.Size);
        }
        ValidateImports(pe);
        ValidateUnwind(pe);
        ValidateRelocations(pe);
    }

    private void ValidateImports(PeImage pe)
    {
        DataDirectory imports = pe.Directory(DataDir.Import);
        if (imports.IsEmpty)
            return;
        bool terminated = false;
        for (uint offset = 0; (ulong)offset + 20 <= imports.Size; offset += 20)
        {
            uint at = checked(imports.RelativeVirtualAddress + offset);
            byte[] descriptor = pe.ReadRva(at, 20);
            if (descriptor.All(b => b == 0)) { terminated = true; break; }
            uint originalThunk = U32(0), name = U32(12), firstThunk = U32(16);
            if (U32(4) != 0 || U32(8) != 0 || name == 0 || firstThunk == 0)
                Reject("requires unbound ordinary import descriptors");
            RequireString(pe, name);
            uint lookup = originalThunk == 0 ? firstThunk : originalThunk;
            bool end = false;
            for (uint slot = 0; slot < 65536; slot++)
            {
                uint source = checked(lookup + slot * 8);
                uint target = checked(firstThunk + slot * 8);
                RequireOutside(pe, source, 8);
                RequireOutside(pe, target, 8);
                ulong thunk = pe.ReadU64(source);
                if (thunk == 0) { end = true; break; }
                if ((thunk & (1UL << 63)) != 0)
                {
                    if ((thunk & 0x7FFF_FFFF_FFFF_0000UL) != 0)
                        Reject("found an invalid ordinal import");
                }
                else
                {
                    if (thunk > uint.MaxValue - 2) Reject("found an invalid import-name RVA");
                    RequireOutside(pe, (uint)thunk, 2);
                    RequireString(pe, (uint)thunk + 2);
                }
            }
            if (!end) Reject("found an unterminated import thunk table");
            uint U32(int p) => BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(p));
        }
        if (!terminated) Reject("found an unterminated import descriptor table");
    }

    private void ValidateUnwind(PeImage pe)
    {
        DataDirectory directory = pe.Directory(DataDir.Exception);
        if (directory.Size % 12 != 0) Reject("found a truncated exception directory");
        foreach (RuntimeFunction function in ExceptionTable.Parse(pe))
        {
            if (function.EndRva <= function.BeginRva) Reject("found an invalid runtime-function extent");
            RequireOutside(pe, function.BeginRva, function.EndRva - function.BeginRva);
            RequireOutside(pe, function.UnwindRva, 4);
            byte[] header = pe.ReadRva(function.UnwindRva, 4);
            // Language-specific and chained unwind data can contain further
            // pointer graphs. Light packing does not guess their ownership.
            if (header[0] != 1) Reject("requires version-one handler-free, unchained unwind records");
            RequireOutside(pe, function.UnwindRva, (uint)(4 + ((header[2] + 1) & ~1) * 2));
        }
    }

    private void ValidateRelocations(PeImage pe)
    {
        DataDirectory directory = pe.Directory(DataDir.Basereloc);
        for (uint offset = 0; offset < directory.Size;)
        {
            if (directory.Size - offset < 8) Reject("found a truncated relocation block");
            uint at = checked(directory.RelativeVirtualAddress + offset);
            uint page = pe.ReadU32(at), size = pe.ReadU32(at + 4);
            if (size < 8 || size % 4 != 0 || size > directory.Size - offset || page % 4096 != 0)
                Reject("found an invalid relocation block");
            byte[] entries = pe.ReadRva(at + 8, checked((int)size - 8));
            for (int i = 0; i < entries.Length; i += 2)
            {
                ushort entry = BinaryPrimitives.ReadUInt16LittleEndian(entries.AsSpan(i));
                int type = entry >> 12;
                if (type == 0) continue;
                if (type != 10) Reject("supports only AMD64 DIR64 relocations");
                // The Windows loader must never relocate an as-yet unpacked value.
                RequireOutside(pe, checked(page + (uint)(entry & 0xFFF)), 8);
            }
            offset += size;
        }
    }

    private void RequireString(PeImage pe, uint rva)
    {
        for (uint length = 0; length < 65536; length++)
        {
            uint at = checked(rva + length);
            RequireOutside(pe, at, 1);
            if (pe.ReadRva(at, 1)[0] == 0) return;
        }
        Reject("found an unterminated import name");
    }

    private void RequireOutside(PeImage pe, uint rva, uint size)
    {
        PeImage.Section? section = pe.SectionFromRva(rva);
        if (size == 0 || section is null || (ulong)rva + size > (ulong)section.VirtualAddress + section.SizeOfRawData)
            Reject("requires fully file-backed metadata in a single section");
        if (Sections.Any(s => (ulong)rva < (ulong)s.VirtualAddress + s.ResolvedVirtualSize
            && s.VirtualAddress < (ulong)rva + size))
            Reject("cannot pack data read or relocated by the Windows loader");
    }

    private static void Reject(string reason) =>
        throw new NotSupportedException($"Light initialized-data packing {reason}.");
}
