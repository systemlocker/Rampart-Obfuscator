using System.Buffers.Binary;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;

namespace Rampart.Managed;

internal static class ManagedStrongNameValidator
{
    internal static void Validate(byte[] image, byte[] publicKey)
    {
        using var pe = new PEReader(new MemoryStream(image, false));
        var cor = pe.PEHeaders.CorHeader;
        var peHeader = pe.PEHeaders.PEHeader;
        if (cor is null || peHeader is null || (cor.Flags & CorFlags.StrongNameSigned) == 0) Fail();
        var directory = cor!.StrongNameSignatureDirectory;
        if (directory.RelativeVirtualAddress <= 0 || directory.Size <= 0) Fail();
        if (publicKey.Length < 32 || publicKey[12] != 6 || BinaryPrimitives.ReadUInt32LittleEndian(publicKey.AsSpan(20)) != 0x31415352)
            Fail();
        var bits = BinaryPrimitives.ReadInt32LittleEndian(publicKey.AsSpan(24));
        if (bits is < 512 or > 16384 || bits % 8 != 0 || publicKey.Length != 32 + bits / 8 || directory.Size != bits / 8) Fail();
        var modulus = publicKey.AsSpan(32).ToArray(); Array.Reverse(modulus);
        var exponentValue = BinaryPrimitives.ReadUInt32LittleEndian(publicKey.AsSpan(28));
        if (exponentValue == 0) Fail();
        var rawExponent = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(rawExponent, exponentValue);
        var firstNonZero = 0;
        while (firstNonZero < rawExponent.Length - 1 && rawExponent[firstNonZero] == 0) firstNonZero++;
        var exponent = rawExponent[firstNonZero..];

        var containing = pe.PEHeaders.SectionHeaders
            .Where(s => s.SizeOfRawData > 0
                && directory.RelativeVirtualAddress >= s.VirtualAddress
                && (long)directory.RelativeVirtualAddress - s.VirtualAddress + directory.Size <= s.SizeOfRawData)
            .ToArray();
        if (containing.Length != 1) Fail();
        var section = containing[0];
        var signatureOffset = checked(section.PointerToRawData + (directory.RelativeVirtualAddress - section.VirtualAddress));
        if (signatureOffset < 0 || signatureOffset > image.Length - directory.Size) Fail();
        var signature = image.AsSpan(signatureOffset, directory.Size).ToArray(); Array.Reverse(signature);

        var headerLength = checked(pe.PEHeaders.CoffHeaderStartOffset + 20 + pe.PEHeaders.CoffHeader.SizeOfOptionalHeader + 40 * pe.PEHeaders.CoffHeader.NumberOfSections);
        if (headerLength <= 0 || headerLength > image.Length) Fail();

        // Strong-name hashing covers PE/COFF/section headers (with PE CheckSum and
        // Certificate Table directory zeroed) plus each file-backed section minus
        // the strong-name signature slot. SHA-1 is the ECMA strong-name format
        // algorithm, not an integrity claim.
        var header = image.AsSpan(0, headerLength).ToArray();
        var peHeaderStart = pe.PEHeaders.PEHeaderStartOffset;
        if (peHeaderStart >= 0 && peHeaderStart + 68 <= header.Length)
            Array.Clear(header, peHeaderStart + 64, 4); // PE CheckSum
        var certDirOffset = peHeaderStart + (peHeader!.Magic == PEMagic.PE32Plus ? 144 : 128);
        if (peHeader.NumberOfRvaAndSizes > 4 && certDirOffset >= 0 && certDirOffset + 8 <= header.Length)
            Array.Clear(header, certDirOffset, 8); // Certificate Table directory entry

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        hash.AppendData(header);
        var sigEnd = checked(signatureOffset + directory.Size);
        foreach (var rawSection in pe.PEHeaders.SectionHeaders)
        {
            if (rawSection.SizeOfRawData <= 0) continue;
            var start = rawSection.PointerToRawData;
            var end = checked(start + rawSection.SizeOfRawData);
            if (start < 0 || end > image.Length) Fail();
            if (signatureOffset >= start && sigEnd <= end)
            {
                if (signatureOffset > start) hash.AppendData(image.AsSpan(start, signatureOffset - start));
                if (end > sigEnd) hash.AppendData(image.AsSpan(sigEnd, end - sigEnd));
            }
            else
            {
                hash.AppendData(image.AsSpan(start, rawSection.SizeOfRawData));
            }
        }
        using var rsa = RSA.Create(); rsa.ImportParameters(new RSAParameters { Modulus = modulus, Exponent = exponent });
        if (!rsa.VerifyHash(hash.GetHashAndReset(), signature, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1)) Fail();
    }
    private static void Fail() => ManagedPreflight.Fail("MANAGED_STRONG_NAME_INVALID", "The rewritten assembly failed strong-name signature verification.");
}
