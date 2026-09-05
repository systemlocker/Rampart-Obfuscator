using System.Buffers.Binary;
using Rampart.Pe;

namespace Rampart.Engine.Passes;

/// <summary>Symbol scrub: delete what static analysis indexes first — debug
/// directory, PDB path strings, the Rich header, section names, and (at Heavy+)
/// timestamp clocks. "Defeats PDB matching, source correlation, packer signatures."</summary>
public sealed class SymbolScrubPass
{
    public void Run(BuildContext ctx)
    {
        var level = ctx.Level("packaging.symbol-scrub");
        if (level == Config.ProtectionLevel.Off)
            return;
        var pe = ctx.Pe;
        int items = 0;

        // Debug directory + everything it points at (CODEVIEW RSD records carry
        // the PDB path — the single most identifying string in a release build).
        var debugDir = pe.Directory(DataDir.Debug);
        if (!debugDir.IsEmpty)
        {
            int count = (int)(debugDir.Size / 28);
            for (int i = 0; i < count; i++)
            {
                var desc = pe.ReadRva(debugDir.RelativeVirtualAddress + (uint)(i * 28), 28);
                uint sizeOfData = BinaryPrimitives.ReadUInt32LittleEndian(desc.AsSpan(16));
                uint addressOfRawData = BinaryPrimitives.ReadUInt32LittleEndian(desc.AsSpan(20));
                uint pointerToRawData = BinaryPrimitives.ReadUInt32LittleEndian(desc.AsSpan(24));
                if (sizeOfData > 0 && sizeOfData < 0x100000)
                {
                    bool cleared = false;
                    if (addressOfRawData != 0
                        && pe.TryRvaToOffset(addressOfRawData, out int payloadOffset)
                        && pe.TryGetFileRange((uint)payloadOffset, (int)sizeOfData, out Memory<byte> payload))
                    {
                        payload.Span.Clear();
                        cleared = true;
                    }
                    else if (pointerToRawData != 0
                        && pe.TryGetFileRange(pointerToRawData, (int)sizeOfData, out payload))
                    {
                        // The PE format permits unmapped debug data at the end
                        // of the file, represented only by PointerToRawData.
                        payload.Span.Clear();
                        cleared = true;
                    }
                    if (cleared)
                        items++;
                }
            }
            // Zero the descriptors themselves, then the directory entry.
            ZeroRva(pe, debugDir.RelativeVirtualAddress, (int)debugDir.Size);
            pe.SetDirectory(DataDir.Debug, 0, 0);
            items++;
        }

        // Rich header: scrub immediately so the later disguise pass can place
        // deliberate decoy metadata without serialization wiping it again.
        if (level >= Config.ProtectionLevel.Balanced)
        {
            pe.ScrubDosStubContent();
            items++;
        }

        // Section names.
        if (level >= Config.ProtectionLevel.Balanced)
        {
            foreach (var s in pe.Sections)
            {
                if (s.Name.Length > 0 && s.Name != ".rmpt")
                {
                    s.Name = "";
                    items++;
                }
            }
        }

        // Timestamps (header + export/import table clocks) at Heavy+. Give the
        // COFF header a seeded value to avoid a zero-timestamp packer heuristic;
        // clear each directory timestamp so stale binding metadata is not kept.
        if (level >= Config.ProtectionLevel.Heavy)
        {
            pe.TimeDateStamp = (uint)ctx.Rng.NextInt64(1, int.MaxValue);
            var export = pe.Directory(DataDir.Export);
            if (!export.IsEmpty && export.Size >= 8)
                ZeroRva(pe, export.RelativeVirtualAddress + 4, 4);

            var imports = pe.Directory(DataDir.Import);
            for (uint offset = 0; !imports.IsEmpty && (ulong)offset + 20 <= imports.Size; offset += 20)
            {
                byte[] descriptor = pe.ReadRva(imports.RelativeVirtualAddress + offset, 20);
                if (descriptor.All(value => value == 0))
                    break;
                ZeroRva(pe, imports.RelativeVirtualAddress + offset + 4, 4);
            }
            items++;
        }

        if (level == Config.ProtectionLevel.Maximum)
        {
            int coffBytes = pe.ScrubCoffSymbolPayload();
            if (coffBytes > 0) items++;
            ctx.Log.Add(new("symbol-scrub", $"verified COFF payload ownership and cleared {coffBytes} symbol/string-table bytes"));
        }
        ctx.Log.Add(new("symbol-scrub", $"scrubbed {items} items (level {level})"));
    }

    /// <summary>Zeroes raw bytes backing an RVA range (clipped to what has file
    /// backing — header-only RVAs are skipped).</summary>
    internal static void ZeroRva(PeImage pe, uint rva, int size)
    {
        int done = 0;
        while (done < size)
        {
            if (!pe.TryRvaToOffset(rva + (uint)done, out int off))
                return;
            var sec = pe.SectionFromRva(rva + (uint)done)!;
            int avail = Math.Min(size - done, (int)(sec.PointerToRawData + sec.SizeOfRawData - (uint)off));
            sec.Data.AsSpan(off - (int)sec.PointerToRawData, avail).Clear();
            done += avail;
        }
    }
}
