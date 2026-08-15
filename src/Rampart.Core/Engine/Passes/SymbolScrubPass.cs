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
                if (addressOfRawData != 0 && sizeOfData > 0 && sizeOfData < 0x100000)
                {
                    ZeroRva(pe, addressOfRawData, (int)sizeOfData);
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

        // Timestamps (header + export/import table clocks) at Heavy+. Disguised
        // with build-random values rather than zeroed — a zero timestamp is
        // itself a packer heuristic worth avoiding.
        if (level >= Config.ProtectionLevel.Heavy)
        {
            pe.TimeDateStamp = (uint)ctx.Rng.NextInt64(1, int.MaxValue);
            foreach (var dirIndex in new[] { DataDir.Export, DataDir.Import })
            {
                var d = pe.Directory(dirIndex);
                if (!d.IsEmpty)
                    ZeroRva(pe, d.RelativeVirtualAddress + 4, 4); // TimeDateStamp fields
            }
            items++;
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
