using System.Buffers.Binary;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;

namespace Rampart.Managed;

internal static class ManagedStrongNameValidator
{
    internal static void Validate(byte[] image, byte[] publicKey)
    {
        using var pe = new PEReader(new MemoryStream(image, false));
        var directory = pe.PEHeaders.CorHeader!.StrongNameSignatureDirectory;
        if (publicKey.Length < 32 || publicKey[12] != 6 || BinaryPrimitives.ReadUInt32LittleEndian(publicKey.AsSpan(20)) != 0x31415352)
            Fail();
        var bits = BinaryPrimitives.ReadInt32LittleEndian(publicKey.AsSpan(24));
        if (bits is < 512 or > 16384 || bits % 8 != 0 || publicKey.Length != 32 + bits / 8 || directory.Size != bits / 8) Fail();
        var modulus = publicKey.AsSpan(32).ToArray(); Array.Reverse(modulus);
        var exponentValue = BinaryPrimitives.ReadUInt32LittleEndian(publicKey.AsSpan(28));
        var exponent = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(exponent, exponentValue);
        var section = pe.PEHeaders.SectionHeaders.Single(s => directory.RelativeVirtualAddress >= s.VirtualAddress && directory.RelativeVirtualAddress - s.VirtualAddress < s.SizeOfRawData);
        var signatureOffset = section.PointerToRawData + directory.RelativeVirtualAddress - section.VirtualAddress;
        var signature = image.AsSpan(signatureOffset, directory.Size).ToArray(); Array.Reverse(signature);
        var headerLength = pe.PEHeaders.CoffHeaderStartOffset + 20 + pe.PEHeaders.CoffHeader.SizeOfOptionalHeader + 40 * pe.PEHeaders.CoffHeader.NumberOfSections;
        var firstSection = pe.PEHeaders.SectionHeaders.Min(s => s.PointerToRawData);
        // Strong-name hashing omits header-alignment padding and the signature slot.
        // SHA-1 is the ECMA strong-name format algorithm, not an integrity claim.
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        hash.AppendData(image.AsSpan(0, headerLength));
        hash.AppendData(image.AsSpan(firstSection, signatureOffset - firstSection));
        hash.AppendData(image.AsSpan(signatureOffset + directory.Size));
        using var rsa = RSA.Create(); rsa.ImportParameters(new RSAParameters { Modulus = modulus, Exponent = exponent });
        if (!rsa.VerifyHash(hash.GetHashAndReset(), signature, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1)) Fail();
    }
    private static void Fail() => ManagedPreflight.Fail("MANAGED_STRONG_NAME_INVALID", "The rewritten assembly failed strong-name signature verification.");
}
