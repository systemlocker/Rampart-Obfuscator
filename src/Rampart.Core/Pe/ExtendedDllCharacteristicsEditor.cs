using System.Buffers.Binary;
using Rampart.Engine;

namespace Rampart.Pe;

/// <summary>Preserves the PE debug-directory array while adding the extended DLL
/// characteristics record used by modern Windows loaders.</summary>
public static class ExtendedDllCharacteristicsEditor
{
    public const uint ImageDebugTypeExtendedDllCharacteristics = 20;
    public const ushort CetCompatible = 0x0001;
    private const int DebugDirectorySize = 28;

    public static void Add(BuildContext ctx, ushort characteristics) =>
        Add(ctx, (uint)characteristics);

    /// <summary>Adds or updates the 32-bit IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS
    /// flags record (DWORD per Windows PE specification).</summary>
    public static void Add(BuildContext ctx, uint characteristics)
    {
        ArgumentNullException.ThrowIfNull(ctx);
        if (characteristics == 0)
            return;

        DataDirectory directory = ctx.Pe.Directory(DataDir.Debug);
        var descriptors = new List<byte[]>();
        if (!directory.IsEmpty)
        {
            if (directory.Size % DebugDirectorySize != 0)
                throw new BadImageFormatException("Debug directory size is not a whole number of entries.");
            int count = checked((int)(directory.Size / DebugDirectorySize));
            for (int i = 0; i < count; i++)
            {
                uint descRva = checked(directory.RelativeVirtualAddress + checked((uint)(i * DebugDirectorySize)));
                byte[] descriptor = ctx.Pe.ReadRva(descRva, DebugDirectorySize);
                descriptors.Add(descriptor);
                if (BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(12))
                    != ImageDebugTypeExtendedDllCharacteristics)
                    continue;

                uint dataRva = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(20));
                uint size = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(16));
                if (dataRva != 0 && size >= sizeof(uint))
                {
                    uint current = BinaryPrimitives.ReadUInt32LittleEndian(ctx.Pe.ReadRva(dataRva, sizeof(uint)));
                    Span<byte> updated = stackalloc byte[sizeof(uint)];
                    BinaryPrimitives.WriteUInt32LittleEndian(updated, current | characteristics);
                    ctx.Pe.WriteRva(dataRva, updated);
                    return;
                }
                if (dataRva != 0 && size >= sizeof(ushort))
                {
                    // Upgrade an undersized 2-byte record to a compliant 4-byte DWORD slot.
                    uint current = BinaryPrimitives.ReadUInt16LittleEndian(ctx.Pe.ReadRva(dataRva, sizeof(ushort)));
                    uint upgradedRva = AllocatePayload(ctx, current | characteristics, out uint upgradedRaw);
                    // Allocating the replacement can grow .rmpd and relocate raw
                    // debug payloads. Re-read the descriptor so its raw pointer is
                    // not restored from the stale pre-growth copy below.
                    descriptor = ctx.Pe.ReadRva(descRva, DebugDirectorySize);
                    BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(16), sizeof(uint));
                    BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(20), upgradedRva);
                    BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(24), upgradedRaw);
                    ctx.Pe.WriteRva(descRva, descriptor);
                    return;
                }
            }
        }

        uint payloadRva = AllocatePayload(ctx, characteristics, out uint payloadRaw);

        // The allocation above may have shifted a later section or the overlay.
        // Preserve the raw pointers that PeImage adjusted in the live directory,
        // rather than rebuilding it from copies captured before the growth.
        if (!directory.IsEmpty)
        {
            for (int i = 0; i < descriptors.Count; i++)
            {
                uint descRva = checked(directory.RelativeVirtualAddress + checked((uint)(i * DebugDirectorySize)));
                descriptors[i] = ctx.Pe.ReadRva(descRva, DebugDirectorySize);
            }
        }

        var added = new byte[DebugDirectorySize];
        BinaryPrimitives.WriteUInt32LittleEndian(added.AsSpan(4), ctx.Pe.TimeDateStamp);
        BinaryPrimitives.WriteUInt32LittleEndian(
            added.AsSpan(12), ImageDebugTypeExtendedDllCharacteristics);
        BinaryPrimitives.WriteUInt32LittleEndian(added.AsSpan(16), sizeof(uint));
        BinaryPrimitives.WriteUInt32LittleEndian(added.AsSpan(20), payloadRva);
        BinaryPrimitives.WriteUInt32LittleEndian(added.AsSpan(24), payloadRaw);
        descriptors.Add(added);

        var rebuilt = new byte[checked(descriptors.Count * DebugDirectorySize)];
        for (int i = 0; i < descriptors.Count; i++)
            descriptors[i].CopyTo(rebuilt, i * DebugDirectorySize);
        uint rebuiltRva = ctx.AllocData(rebuilt.Length, 4);
        ctx.WriteData(rebuiltRva, rebuilt);
        ctx.Pe.SetDirectory(DataDir.Debug, rebuiltRva, checked((uint)rebuilt.Length));
    }

    private static uint AllocatePayload(BuildContext ctx, uint value, out uint rawOffset)
    {
        uint payloadRva = ctx.AllocData(sizeof(uint), 4);
        Span<byte> bytes = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, value);
        ctx.WriteData(payloadRva, bytes);
        PeImage.Section payloadSection = ctx.Pe.SectionFromRva(payloadRva)
            ?? throw new InvalidOperationException("Extended-characteristics payload was not allocated in a section.");
        rawOffset = checked(payloadSection.PointerToRawData + payloadRva - payloadSection.VirtualAddress);
        return payloadRva;
    }
}
