using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Rampart.NativeAot;

/// <summary>Recognizes a completed transformation. This is a repeat-processing
/// guard and corruption check, not a publisher signature or authenticity claim.</summary>
public static class NativeAotMarker
{
    internal const int Offset = 64;
    internal const int Length = 48;
    private static ReadOnlySpan<byte> Magic => "RMPAOT01"u8;

    public static bool TryInspect(byte[] image, out bool valid)
    {
        valid = false;
        if (image.Length < Offset + Magic.Length || !image.AsSpan(Offset, Magic.Length).SequenceEqual(Magic)) return false;
        if (!TryBounds(image, out int optional) || image.Length < Offset + Length) return true;
        uint encodedLength = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(Offset + 8));
        if (encodedLength < optional + 152 || encodedLength > image.Length || encodedLength > 256 * 1024 * 1024) return true;
        if (BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(Offset + 12)) != 0) return true;
        int originalLength = (int)encodedLength;
        uint certificateOffset = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(optional + 144));
        uint certificateLength = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(optional + 148));
        if (certificateOffset == 0 && certificateLength == 0)
        {
            if (originalLength != image.Length) return true;
        }
        else
        {
            // Authenticode may append aligned certificate bytes and update the two
            // excluded header fields after protection. Other trailing bytes fail.
            if (certificateOffset < originalLength || certificateOffset - originalLength > 7 || certificateOffset % 8 != 0
                || certificateLength < 8 || (ulong)certificateOffset + certificateLength != (ulong)image.Length) return true;
            for (int index = originalLength; index < certificateOffset; index++) if (image[index] != 0) return true;
        }
        valid = CryptographicOperations.FixedTimeEquals(Digest(image.AsSpan(0, originalLength), optional), image.AsSpan(Offset + 16, 32));
        return true;
    }

    internal static void Write(byte[] image)
    {
        if (!TryBounds(image, out int optional))
            throw new NativeAotCompatibilityException("NAOT_MARKER_SPACE_REQUIRED", "The image has no space for a transformation marker in its DOS stub.");
        image.AsSpan(Offset, Length).Clear();
        Magic.CopyTo(image.AsSpan(Offset));
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(Offset + 8), (uint)image.Length);
        Digest(image, optional).CopyTo(image.AsSpan(Offset + 16));
    }

    private static bool TryBounds(byte[] image, out int optional)
    {
        optional = 0;
        if (image.Length < 64 || image[0] != 'M' || image[1] != 'Z') return false;
        int pe = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(60));
        if (pe < Offset + Length || pe > image.Length - 176 || BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(pe)) != 0x4550) return false;
        optional = pe + 24;
        return BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(optional)) == 0x20b;
    }

    private static byte[] Digest(ReadOnlySpan<byte> image, int optional)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(image[..Offset]);
        hash.AppendData(image[(Offset + Length)..(optional + 64)]);
        hash.AppendData(image[(optional + 68)..(optional + 144)]);
        hash.AppendData(image[(optional + 152)..]);
        return hash.GetHashAndReset();
    }
}
