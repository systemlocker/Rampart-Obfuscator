using System.Buffers.Binary;

namespace Rampart.Pe;

/// <summary>PE image checksum over final file bytes, including an odd-length overlay.</summary>
public static class PeChecksum
{
    public static uint Compute(ReadOnlySpan<byte> file)
    {
        if (file.Length < 64 || BinaryPrimitives.ReadUInt16LittleEndian(file) != PeImage.DosMagic)
            throw new BadImageFormatException("Missing DOS header for PE checksum.");
        int pe = BinaryPrimitives.ReadInt32LittleEndian(file[60..]);
        long checksumOffset = (long)pe + 24 + 64;
        if (pe < 64 || checksumOffset + 4 > file.Length
            || BinaryPrimitives.ReadUInt32LittleEndian(file[pe..]) != PeImage.PeSignature)
            throw new BadImageFormatException("Invalid PE header for checksum.");
        uint sum = 0;
        for (int index = 0; index < file.Length; index += 2)
        {
            uint word = index >= checksumOffset && index < checksumOffset + 4 ? 0u : file[index];
            if (index + 1 < file.Length && !(index + 1 >= checksumOffset && index + 1 < checksumOffset + 4))
                word |= (uint)file[index + 1] << 8;
            sum += word;
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (sum & 0xFFFF) + (sum >> 16) + (uint)file.Length;
    }
}
