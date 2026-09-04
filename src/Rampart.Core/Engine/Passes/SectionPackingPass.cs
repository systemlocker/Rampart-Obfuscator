using Rampart.Codecs;
using Rampart.Config;
using Rampart.Packing;
using Rampart.Pe;

namespace Rampart.Engine.Passes;

/// <summary>Light packing for conservatively verified initialized RW data.
/// Code, loader tables, virtual addresses, and page protections stay unchanged.</summary>
public sealed class SectionPackingPass
{
    private PackingInputPlan? _plan;
    private BuildContext? _context;

    /// <summary>Must precede every transform: later passes may erase metadata or
    /// change section flags, neither of which is evidence of original eligibility.</summary>
    public void Prepare(BuildContext context)
    {
        if (context.Level("packaging.packer") == ProtectionLevel.Off) return;
        if (context.Level("packaging.packer") != ProtectionLevel.Light)
            throw new NotSupportedException("Initialized-data packing supports Light only.");
        if (context.Level("packaging.ep-confusion") == ProtectionLevel.Off)
            throw new NotSupportedException("Initialized-data packing requires the startup dispatcher.");
        if (context.Level("anti-inject.cet-shadow-stack") != ProtectionLevel.Off)
            throw new NotSupportedException("Light initialized-data packing does not yet support generated CET debug metadata.");
        _plan = new PackingInputPlan(context);
        _context = context;
    }

    /// <summary>Run after all byte-mutating transforms and before the startup
    /// dispatcher snapshots InitChain. The decompression leaves no persistent RWX.</summary>
    public void Run(BuildContext context)
    {
        if (context.Level("packaging.packer") == ProtectionLevel.Off) return;
        if (_plan is null || _context != context)
            throw new InvalidOperationException("Prepare initialized-data packing on the original build context first.");
        PeImage pe = context.Pe;
        _plan.ValidateMetadata(pe, original: false);
        if (context.RelocSlots.Any(rva => _plan.Sections.Any(section =>
                (ulong)rva < (ulong)section.VirtualAddress + section.ResolvedVirtualSize
                && section.VirtualAddress < (ulong)rva + 8)))
            throw new NotSupportedException("Initialized-data packing cannot overwrite pending loader relocations.");
        if (!pe.Directory(DataDir.Security).IsEmpty)
            throw new NotSupportedException("Clear the invalidated certificate directory before initialized-data packing.");
        var payloads = _plan.Sections.Select(section => (Section: section, Packed: Lzss.Compress(section.Data)))
            .Where(item => item.Packed.Length < item.Section.SizeOfRawData).ToArray();
        if (payloads.Length == 0)
            throw new NotSupportedException("Initialized-data packing found no compressible eligible section.");
        if (payloads.Sum(item => (long)item.Packed.Length + 512) > 512 * 1024)
            throw new NotSupportedException("Light initialized-data packing exceeds its 512 KiB payload budget.");
        var initializers = new List<uint>();
        long rawBytes = 0, packedBytes = 0;
        foreach (var item in payloads)
        {
            PeImage.Section section = item.Section;
            uint payloadRva = context.Alloc(item.Packed.Length, 8);
            context.WriteStub(payloadRva, item.Packed);
            int decoderLength = LzssDecoderEmitter.Emit(0, 0, item.Packed.Length, 0, section.Data.Length).Length;
            uint decoderRva = context.Alloc(decoderLength, 16);
            context.WriteStub(decoderRva, LzssDecoderEmitter.Emit(decoderRva, payloadRva,
                item.Packed.Length, section.VirtualAddress, section.Data.Length));
            initializers.Add(decoderRva);
            rawBytes += section.SizeOfRawData;
            packedBytes += item.Packed.Length;
            // Retain the loader mapping, including raw alignment padding which
            // may be referenced by native code; remove only its disk backing.
            section.VirtualSize = section.ResolvedVirtualSize;
            section.SizeOfRawData = 0;
            section.PointerToRawData = 0;
            section.Data = [];
        }
        context.InitChain.InsertRange(0, initializers);
        // No supported input metadata stores raw file offsets; signatures were
        // cleared above. Repacking changes disk offsets only, not any PE RVAs.
        uint cursor = PeImage.AlignUp(pe.SizeOfHeaders, pe.FileAlignment);
        foreach (PeImage.Section section in pe.Sections.Where(s => s.SizeOfRawData != 0))
        {
            section.PointerToRawData = cursor;
            cursor = checked(cursor + PeImage.AlignUp(section.SizeOfRawData, pe.FileAlignment));
        }
        context.MarkApplied("packaging.packer");
        context.Log.Add(new("packaging.packer", $"packed {payloads.Length} initialized writable data sections: "
            + $"{rawBytes} raw bytes into {packedBytes} payload bytes; original RVAs and protections retained"));
        _plan = null;
    }
}
