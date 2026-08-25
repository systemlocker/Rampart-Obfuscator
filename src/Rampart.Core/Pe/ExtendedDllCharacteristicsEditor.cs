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

    public static void Add(BuildContext ctx, ushort characteristics)
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
                byte[] descriptor = ctx.Pe.ReadRva(
                    directory.RelativeVirtualAddress + (uint)(i * DebugDirectorySize),
                    DebugDirectorySize);
                descriptors.Add(descriptor);
                if (BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(12))
                    != ImageDebugTypeExtendedDllCharacteristics)
                    continue;

                uint dataRva = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(20));
                uint size = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(16));
                if (dataRva != 0 && size >= sizeof(ushort))
                {
                    ushort current = BinaryPrimitives.ReadUInt16LittleEndian(ctx.Pe.ReadRva(dataRva, 2));
                    ctx.Pe.WriteRva(dataRva, BitConverter.GetBytes((ushort)(current | characteristics)));
                    return;
                }
            }
        }

        uint payloadRva = ctx.AllocData(sizeof(ushort), 2);
        ctx.WriteData(payloadRva, BitConverter.GetBytes(characteristics));
        PeImage.Section payloadSection = ctx.Pe.SectionFromRva(payloadRva)
            ?? throw new InvalidOperationException("Extended-characteristics payload was not allocated in a section.");
        uint payloadRaw = checked(payloadSection.PointerToRawData
            + payloadRva - payloadSection.VirtualAddress);

        var added = new byte[DebugDirectorySize];
        BinaryPrimitives.WriteUInt32LittleEndian(added.AsSpan(4), ctx.Pe.TimeDateStamp);
        BinaryPrimitives.WriteUInt32LittleEndian(
            added.AsSpan(12), ImageDebugTypeExtendedDllCharacteristics);
        BinaryPrimitives.WriteUInt32LittleEndian(added.AsSpan(16), sizeof(ushort));
        BinaryPrimitives.WriteUInt32LittleEndian(added.AsSpan(20), payloadRva);
        BinaryPrimitives.WriteUInt32LittleEndian(added.AsSpan(24), payloadRaw);
        descriptors.Add(added);

        var rebuilt = new byte[checked(descriptors.Count * DebugDirectorySize)];
        for (int i = 0; i < descriptors.Count; i++)
            descriptors[i].CopyTo(rebuilt, i * DebugDirectorySize);
        uint rebuiltRva = ctx.AllocData(rebuilt.Length, 4);
        ctx.WriteData(rebuiltRva, rebuilt);
        ctx.Pe.SetDirectory(DataDir.Debug, rebuiltRva, (uint)rebuilt.Length);
    }
}
