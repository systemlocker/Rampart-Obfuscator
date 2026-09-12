using Rampart.Pe;
using System.Buffers.Binary;

namespace Rampart.Engine;

/// <summary>Preflight checks for the input shapes the current pipeline can
/// preserve. Rejecting an unverified shape is safer than emitting a plausible
/// PE that fails later in the Windows loader.</summary>
public static class PeCompatibility
{
    private const ushort ImageFileDll = 0x2000;

    public static void Validate(PeImage pe)
    {
        if (pe.Machine != MachineType.Amd64 || !pe.IsPe32Plus)
        {
            throw new NotSupportedException(
                $"Rampart protects PE32+ x64 images only (input is {pe.Machine}, " +
                $"magic 0x{pe.OptionalMagic:X}).");
        }

        if ((pe.Characteristics & ImageFileDll) != 0)
            throw new NotSupportedException("Rampart protects executable images, not DLLs.");

        if (!pe.Directory(DataDir.ComDescriptor).IsEmpty)
            throw new NotSupportedException("Managed .NET images are not supported by the native x64 pipeline.");

        _ = Inspect(pe);

        if (pe.Sections.Any(s => string.Equals(s.Name, ".rmpt", StringComparison.Ordinal)))
            throw new InvalidOperationException("The input already contains a Rampart section.");

        if (pe.EntryPointRva == 0
            || pe.SectionFromRva(pe.EntryPointRva) is not { IsExecutable: true } entrySection
            || pe.EntryPointRva - entrySection.VirtualAddress >= entrySection.SizeOfRawData)
        {
            throw new BadImageFormatException(
                $"Entry point RVA 0x{pe.EntryPointRva:X8} is not backed by an executable section.");
        }
    }

    /// <summary>Validates and inventories loader metadata Rampart must preserve.</summary>
    public static PeCompatibilityFeatures Inspect(PeImage pe)
    {
        ValidateAlignments(pe.FileAlignment, pe.SectionAlignment);
        int delayImports = CountDelayImports(pe);
        int boundImports = CountBoundImports(pe);
        int tlsCallbacks = CountTlsCallbacks(pe);

        uint loadConfigSize = 0;
        ImageGuardFlags guardFlags = 0;
        DataDirectory loadConfig = pe.Directory(DataDir.LoadConfig);
        if (!loadConfig.IsEmpty)
        {
            EnsureReadable(pe, loadConfig, 4, "load-config");
            loadConfigSize = BinaryPrimitives.ReadUInt32LittleEndian(
                pe.ReadRva(loadConfig.RelativeVirtualAddress, 4));
            if (loadConfigSize < 4 || loadConfigSize > loadConfig.Size)
            {
                throw new BadImageFormatException(
                    $"Load-config size {loadConfigSize} is outside directory size {loadConfig.Size}.");
            }
            // IMAGE_LOAD_CONFIG_DIRECTORY64::GuardFlags is at offset 0x90.
            if (loadConfigSize >= 0x94)
            {
                guardFlags = (ImageGuardFlags)BinaryPrimitives.ReadUInt32LittleEndian(
                    pe.ReadRva(loadConfig.RelativeVirtualAddress + 0x90, 4));
            }
        }

        bool guardCf = pe.DllChars.HasFlag(DllCharacteristics.GuardCf)
            || guardFlags.HasFlag(ImageGuardFlags.CfInstrumented);
        bool cetContinuationMetadata =
            guardFlags.HasFlag(ImageGuardFlags.EhContinuationTablePresent);
        return new PeCompatibilityFeatures(
            delayImports,
            boundImports,
            loadConfigSize,
            guardFlags,
            guardCf,
            cetContinuationMetadata,
            tlsCallbacks,
            pe.FileAlignment,
            pe.SectionAlignment,
            pe.OverlaySize);
    }

    private static int CountDelayImports(PeImage pe)
    {
        DataDirectory directory = pe.Directory(DataDir.DelayImport);
        if (directory.IsEmpty)
            return 0;
        EnsureReadable(pe, directory, 32, "delay-import");
        int maximum = checked((int)(directory.Size / 32));
        for (int i = 0; i < maximum; i++)
        {
            byte[] descriptor = pe.ReadRva(directory.RelativeVirtualAddress + (uint)(i * 32), 32);
            if (descriptor.All(value => value == 0))
                return i;
        }
        throw new BadImageFormatException("Delay-import directory has no terminating descriptor.");
    }

    private static int CountBoundImports(PeImage pe)
    {
        DataDirectory directory = pe.Directory(DataDir.BoundImport);
        if (directory.IsEmpty)
            return 0;
        EnsureReadable(pe, directory, 8, "bound-import");

        uint offset = 0;
        int count = 0;
        while (offset + 8 <= directory.Size)
        {
            byte[] descriptor = pe.ReadRva(directory.RelativeVirtualAddress + offset, 8);
            uint timestamp = BinaryPrimitives.ReadUInt32LittleEndian(descriptor);
            ushort nameOffset = BinaryPrimitives.ReadUInt16LittleEndian(descriptor.AsSpan(4));
            ushort forwarders = BinaryPrimitives.ReadUInt16LittleEndian(descriptor.AsSpan(6));
            if (timestamp == 0 && nameOffset == 0 && forwarders == 0)
                return count;
            if (nameOffset >= directory.Size)
                throw new BadImageFormatException("Bound-import module name points outside its directory.");
            _ = pe.ReadCString(directory.RelativeVirtualAddress + nameOffset);
            offset = checked(offset + 8u + (uint)forwarders * 8u);
            count++;
        }
        throw new BadImageFormatException("Bound-import directory has no terminating descriptor.");
    }

    private static int CountTlsCallbacks(PeImage pe)
    {
        DataDirectory directory = pe.Directory(DataDir.Tls);
        if (directory.IsEmpty)
            return 0;
        EnsureReadable(pe, directory, 40, "TLS");
        ulong callbacksVa = BinaryPrimitives.ReadUInt64LittleEndian(
            pe.ReadRva(directory.RelativeVirtualAddress + 24, 8));
        if (callbacksVa == 0)
            return 0;
        uint callbacksRva = pe.VaToRva(callbacksVa);
        for (int i = 0; i < 4096; i++)
        {
            if (pe.ReadU64(callbacksRva + (uint)(i * 8)) == 0)
                return i;
        }
        throw new BadImageFormatException("TLS callback array is not terminated within 4096 entries.");
    }

    private static void EnsureReadable(PeImage pe, DataDirectory directory, uint minimum, string name)
    {
        if (directory.RelativeVirtualAddress == 0 || directory.Size < minimum)
            throw new BadImageFormatException($"{name} directory is present but smaller than {minimum} bytes.");
        _ = pe.ReadRva(directory.RelativeVirtualAddress, checked((int)minimum));
    }

    private static void ValidateAlignments(uint fileAlignment, uint sectionAlignment)
    {
        if (!IsPowerOfTwo(fileAlignment) || !IsPowerOfTwo(sectionAlignment))
            throw new BadImageFormatException("PE file and section alignments must be non-zero powers of two.");
        if (sectionAlignment < 0x1000)
        {
            if (fileAlignment != sectionAlignment)
                throw new BadImageFormatException(
                    "Low-alignment PE images require FileAlignment to equal SectionAlignment.");
            return;
        }
        if (fileAlignment is < 0x200 or > 0x10000 || fileAlignment > sectionAlignment)
            throw new BadImageFormatException("PE file alignment is outside the loader-supported range.");
    }

    private static bool IsPowerOfTwo(uint value) => value != 0 && (value & (value - 1)) == 0;
}

public sealed record PeCompatibilityFeatures(
    int DelayImportDescriptors,
    int BoundImportDescriptors,
    uint LoadConfigSize,
    ImageGuardFlags GuardFlags,
    bool GuardCf,
    bool CetContinuationMetadata,
    int TlsCallbacks,
    uint FileAlignment,
    uint SectionAlignment,
    int OverlayBytes)
{
    public string Summary =>
        $"delay imports {DelayImportDescriptors}, bound imports {BoundImportDescriptors}, " +
        $"load-config {LoadConfigSize} bytes, CFG {(GuardCf ? "on" : "off")}, " +
        $"CET continuation metadata {(CetContinuationMetadata ? "on" : "off")}, " +
        $"TLS callbacks {TlsCallbacks}, alignment {FileAlignment:X}/{SectionAlignment:X}, " +
        $"overlay {OverlayBytes} bytes";
}
