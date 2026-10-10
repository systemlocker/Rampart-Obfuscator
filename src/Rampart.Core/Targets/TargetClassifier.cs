using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text.Json;

namespace Rampart.Targets;

/// <summary>Classifies input without loading its code or changing its bytes.</summary>
public static class TargetClassifier
{
    public const int MaximumInputBytes = 512 * 1024 * 1024;
    private const int MaximumMetadataBytes = 64 * 1024 * 1024;
    private const int MaximumMetadataRows = 1_000_000;
    private const int MaximumExportNames = 65_536;
    // The SDK embeds this SHA-256 marker in apphost; its preceding Int64 is
    // zero for an ordinary host and the file offset of a completed bundle otherwise.
    private static ReadOnlySpan<byte> BundleSignature =>
    [0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
     0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
     0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18,
     0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae];

    public static TargetClassification Classify(byte[] bytes, string? inputPath = null)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length > MaximumInputBytes)
            return Result(ProtectionTargetKind.Unknown, TargetDisposition.Unsupported, "target.input-limit");
        try
        {
            return ClassifyCore(bytes, inputPath);
        }
        catch (Exception error) when (error is BadImageFormatException or ArgumentOutOfRangeException
            or OverflowException or InvalidOperationException or IOException or JsonException)
        {
            // Parser messages can contain paths and vary across runtime versions.
            // Stable codes and bounded format facts are the public diagnostic contract.
            return Result(ProtectionTargetKind.Unknown, TargetDisposition.Unsupported,
                "target.malformed", evidence: ["The image contains invalid or truncated format data."]);
        }
    }

    private static TargetClassification ClassifyCore(byte[] bytes, string? inputPath)
    {
        if (bytes.Length < 64 || BinaryPrimitives.ReadUInt16LittleEndian(bytes) != 0x5a4d)
            return Result(ProtectionTargetKind.Unknown, TargetDisposition.Unsupported, "target.not-pe");
        int peOffset = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3c));
        RequireRange(bytes, peOffset, 24);
        if (BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(peOffset)) != 0x4550)
            throw new BadImageFormatException();
        int sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(peOffset + 6));
        if (sectionCount is < 1 or > 96)
            return Result(ProtectionTargetKind.Unknown, TargetDisposition.Unsupported, "target.section-limit");
        int optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(peOffset + 20));
        RequireRange(bytes, peOffset + 24, checked(optionalSize + sectionCount * 40));

        using var stream = new MemoryStream(bytes, writable: false);
        using var reader = new PEReader(stream);
        PEHeaders headers = reader.PEHeaders;
        PEHeader pe = headers.PEHeader ?? throw new BadImageFormatException();
        foreach (SectionHeader section in headers.SectionHeaders)
        {
            if (section.SizeOfRawData != 0)
                RequireRange(bytes, section.PointerToRawData, section.SizeOfRawData);
            if (section.VirtualAddress < 0 || section.VirtualSize < 0)
                throw new BadImageFormatException();
        }
        string arch = headers.CoffHeader.Machine switch
        {
            Machine.Amd64 => "x64",
            Machine.I386 => "x86",
            Machine.Arm64 => "arm64",
            _ => "unknown"
        };
        string signing = pe.CertificateTableDirectory.Size > 0 ? "authenticode-present" : "unsigned";
        string[] peEvidence = [$"PE machine: {arch}.", $"Section count: {sectionCount}."];
        if (headers.SectionHeaders.Any(section => section.Name == ".rmpt"))
            return Result(ProtectionTargetKind.AlreadyProtected, TargetDisposition.Unsupported,
                "target.already-protected", arch, signing: signing, evidence: peEvidence);
        if (Rampart.NativeAot.NativeAotMarker.TryInspect(bytes, out bool validMarker))
            return Result(validMarker ? ProtectionTargetKind.AlreadyProtected : ProtectionTargetKind.Unknown,
                TargetDisposition.Unsupported,
                validMarker ? "target.already-protected" : "target.protection-marker-invalid",
                arch, signing: signing, evidence: peEvidence);

        CorHeader? cor = headers.CorHeader;
        if (cor is not null)
            return ClassifyManaged(bytes, reader, cor, arch, signing, peEvidence);
        if (pe.CorHeaderTableDirectory.RelativeVirtualAddress != 0 || pe.CorHeaderTableDirectory.Size != 0)
            throw new BadImageFormatException();

        int marker = bytes.AsSpan().IndexOf(BundleSignature);
        bool aotExport = TryFindExport(bytes, headers, "DotNetRuntimeDebugHeader"u8, out uint debugRva);
        if (marker >= 0 && aotExport)
            return Result(ProtectionTargetKind.Unknown, TargetDisposition.Ambiguous,
                "target.conflicting-fingerprints", arch, evidence: peEvidence);
        if (marker >= 0)
            return ClassifyHost(bytes, marker, inputPath, arch, signing, peEvidence);
        if (aotExport)
        {
            int offset = RvaOffset(bytes, headers, debugRva, 12);
            if (!bytes.AsSpan(offset, 4).SequenceEqual("DNDH"u8)
                || BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset + 4)) == 0
                || (BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset + 8)) & 3) != 1)
                return Result(ProtectionTargetKind.Unknown, TargetDisposition.Ambiguous,
                    "target.nativeaot-header-invalid", arch, evidence: peEvidence);
            bool eligible = arch == "x64" && pe.Magic == PEMagic.PE32Plus
                && !headers.CoffHeader.Characteristics.HasFlag(Characteristics.Dll);
            return Result(ProtectionTargetKind.NativeAot,
                eligible ? TargetDisposition.Supported : TargetDisposition.Unsupported,
                eligible ? "target.nativeaot" : "target.nativeaot-platform", arch, ".NET NativeAOT",
                "native-executable", signing,
                ["nativeaot-runtime-tables"], [.. peEvidence, "NativeAOT debug export and DNDH header are present."]);
        }

        // A damaged or unfamiliar host must not silently become a native target.
        // These hints never positively identify NativeAOT or a particular host shape.
        if (Contains(bytes, "hostfxr_main_startupinfo"u8)
            || Contains(bytes, "hostfxr.dll"u8) || Contains(bytes, "h\0o\0s\0t\0f\0x\0r\0.\0d\0l\0l\0"u8)
            || Contains(bytes, "DotNetRuntimeDebugHeader"u8)
            || headers.SectionHeaders.Any(section => section.Name == ".managed"))
            return Result(ProtectionTargetKind.Unknown, TargetDisposition.Ambiguous,
                "target.runtime-fingerprint-incomplete", arch, evidence: peEvidence);

        bool nativeEligible = arch == "x64" && pe.Magic == PEMagic.PE32Plus
            && !headers.CoffHeader.Characteristics.HasFlag(Characteristics.Dll);
        return Result(ProtectionTargetKind.NativePe,
            nativeEligible ? TargetDisposition.Supported : TargetDisposition.Unsupported,
            nativeEligible ? "target.native-pe" : "target.native-platform", arch,
            "native", "native-executable", signing, evidence: peEvidence);
    }

    private static TargetClassification ClassifyManaged(byte[] bytes, PEReader reader, CorHeader cor,
        string arch, string signing, string[] evidence)
    {
        PEHeaders headers = reader.PEHeaders;
        if (cor.ManagedNativeHeaderDirectory.RelativeVirtualAddress != 0 || cor.ManagedNativeHeaderDirectory.Size != 0)
        {
            if (cor.ManagedNativeHeaderDirectory.Size < 16) throw new BadImageFormatException();
            int offset = RvaOffset(bytes, headers, (uint)cor.ManagedNativeHeaderDirectory.RelativeVirtualAddress, 16);
            bool r2r = bytes.AsSpan(offset, 4).SequenceEqual("RTR\0"u8);
            return Result(r2r ? ProtectionTargetKind.ReadyToRun : ProtectionTargetKind.Unknown,
                TargetDisposition.Unsupported, r2r ? "target.readytorun" : "target.managed-native-header",
                arch, ".NET", "precompiled-managed", signing,
                ["managed-native-header"], [.. evidence, "The CLR header points to precompiled native data."]);
        }
        if (!cor.Flags.HasFlag(CorFlags.ILOnly) || cor.Flags.HasFlag(CorFlags.NativeEntryPoint)
            || cor.VtableFixupsDirectory.Size != 0)
            return Result(ProtectionTargetKind.MixedMode, TargetDisposition.Unsupported,
                "target.mixed-mode", arch, ".NET", "mixed-mode", signing, evidence: evidence);
        if (cor.MetadataDirectory.Size is <= 0 or > MaximumMetadataBytes)
            return Result(ProtectionTargetKind.Unknown, TargetDisposition.Unsupported, "target.metadata-limit", arch);
        _ = RvaOffset(bytes, headers, (uint)cor.MetadataDirectory.RelativeVirtualAddress, cor.MetadataDirectory.Size);
        MetadataReader metadata = reader.GetMetadataReader(MetadataReaderOptions.None);
        long totalRows = 0;
        foreach (TableIndex table in Enum.GetValues<TableIndex>())
            totalRows += metadata.GetTableRowCount(table);
        if (totalRows > MaximumMetadataRows)
            return Result(ProtectionTargetKind.Unknown, TargetDisposition.Unsupported, "target.metadata-limit", arch);
        if (!metadata.IsAssembly || metadata.AssemblyFiles.Any(handle => metadata.GetAssemblyFile(handle).ContainsMetadata))
            return Result(ProtectionTargetKind.ManagedIl, TargetDisposition.Unsupported, "target.multi-module", arch, ".NET");
        AssemblyDefinition assembly = metadata.GetAssemblyDefinition();
        foreach (ManifestResourceHandle handle in metadata.ManifestResources)
        {
            StringHandle name = metadata.GetManifestResource(handle).Name;
            // The prefix is reserved to protector-owned resources. It also prevents
            // an accidental second rewrite after a managed helper has been injected.
            if (metadata.StringComparer.StartsWith(name, "Rampart.Managed."))
                return Result(ProtectionTargetKind.AlreadyProtected, TargetDisposition.Unsupported,
                    "target.already-protected", arch, ".NET", signing: signing, evidence: evidence);
        }
        if ((assembly.Flags & AssemblyFlags.WindowsRuntime) != 0)
            return Result(ProtectionTargetKind.ManagedIl, TargetDisposition.Unsupported, "target.windows-runtime", arch, ".NET");
        bool strongName = !assembly.PublicKey.IsNil || cor.StrongNameSignatureDirectory.Size != 0;
        if (strongName)
            signing = cor.Flags.HasFlag(CorFlags.StrongNameSigned) ? "strong-name-signed" : "strong-name-delay-signed";
        bool anyCpu = headers.CoffHeader.Machine == Machine.I386 && !cor.Flags.HasFlag(CorFlags.Requires32Bit);
        if (anyCpu) arch = "AnyCPU";
        bool eligible = (anyCpu && headers.PEHeader!.Magic == PEMagic.PE32
                || arch == "x64" && headers.PEHeader!.Magic == PEMagic.PE32Plus)
            && !cor.Flags.HasFlag(CorFlags.Requires32Bit) && !cor.Flags.HasFlag(CorFlags.Prefers32Bit);
        var features = new List<string> { "pure-il" };
        if (strongName) features.Add("strong-name-identity");
        if (headers.PEHeader!.CertificateTableDirectory.Size != 0) features.Add("authenticode-present");
        return Result(ProtectionTargetKind.ManagedIl,
            eligible ? TargetDisposition.Supported : TargetDisposition.Unsupported,
            eligible ? "target.managed-il" : "target.managed-platform", arch, ".NET",
            headers.CoffHeader.Characteristics.HasFlag(Characteristics.Dll) ? "managed-library" : "managed-executable",
            signing, features.ToArray(), [.. evidence, "CLR IL-only flag and assembly metadata are present."]);
    }

    private static TargetClassification ClassifyHost(byte[] bytes, int marker, string? inputPath,
        string arch, string signing, string[] evidence)
    {
        if (marker < 8 || bytes.AsSpan(marker + 32).IndexOf(BundleSignature) >= 0)
            return Result(ProtectionTargetKind.Unknown, TargetDisposition.Ambiguous,
                "target.bundle-marker-invalid", arch, evidence: evidence);
        long bundleOffset = BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(marker - 8, 8));
        if (bundleOffset != 0)
        {
            if (bundleOffset < 0 || bundleOffset > bytes.Length - 12)
                return Result(ProtectionTargetKind.Unknown, TargetDisposition.Unsupported,
                    "target.bundle-header-invalid", arch, evidence: evidence);
            int offset = (int)bundleOffset;
            uint major = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset));
            int files = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(offset + 8));
            if (major is < 1 or > 6 || files is < 1 or > 100_000)
                return Result(ProtectionTargetKind.Unknown, TargetDisposition.Unsupported,
                    "target.bundle-header-invalid", arch, evidence: evidence);
            return Result(ProtectionTargetKind.SingleFileBundle, TargetDisposition.Inspect,
                "target.single-file-bundle", arch, ".NET", "single-file", signing,
                ["bundle"], [.. evidence, "SDK bundle marker and nonzero bundle header offset are present."]);
        }
        // Only read a bounded adjacent runtimeconfig. It refines a positively
        // identified host; external JSON can never turn a native image into a host.
        bool? selfContained = ReadSelfContained(inputPath);
        ProtectionTargetKind kind = selfContained == true
            ? ProtectionTargetKind.SelfContainedAppHost : ProtectionTargetKind.FrameworkDependentAppHost;
        return Result(kind, selfContained.HasValue ? TargetDisposition.Inspect : TargetDisposition.Ambiguous,
            selfContained switch
            {
                true => "target.self-contained-apphost",
                false => "target.framework-dependent-apphost",
                null => "target.apphost-deployment-unknown"
            }, arch, ".NET", selfContained == true ? "self-contained-folder" : "apphost", signing,
            ["apphost"], [.. evidence, "SDK apphost marker is present; bundle offset is zero.",
                selfContained.HasValue ? "Deployment shape is declared by adjacent runtime configuration."
                    : "Deployment shape requires the application's runtime configuration."]);
    }

    private static bool? ReadSelfContained(string? inputPath)
    {
        if (string.IsNullOrWhiteSpace(inputPath)) return null;
        string path = Path.ChangeExtension(inputPath, ".runtimeconfig.json");
        try
        {
            if (!File.Exists(path)) return null;
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length > 1024 * 1024) return null;
            // Read a fixed maximum even if another process grows the file.
            byte[] json = new byte[(int)stream.Length];
            stream.ReadExactly(json);
            using JsonDocument document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 32 });
            if (!document.RootElement.TryGetProperty("runtimeOptions", out JsonElement runtime)) return null;
            bool included = runtime.TryGetProperty("includedFrameworks", out JsonElement includedFrameworks)
                && includedFrameworks.ValueKind == JsonValueKind.Array && includedFrameworks.GetArrayLength() > 0;
            bool framework = runtime.TryGetProperty("framework", out JsonElement singleFramework)
                && singleFramework.ValueKind == JsonValueKind.Object;
            bool frameworks = runtime.TryGetProperty("frameworks", out JsonElement multipleFrameworks)
                && multipleFrameworks.ValueKind == JsonValueKind.Array && multipleFrameworks.GetArrayLength() > 0;
            return included == (framework || frameworks) ? null : included;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException
            or ArgumentException or NotSupportedException or InvalidOperationException)
        {
            return null;
        }
    }

    private static bool TryFindExport(byte[] bytes, PEHeaders headers, ReadOnlySpan<byte> name, out uint rva)
    {
        rva = 0;
        DirectoryEntry directory = headers.PEHeader!.ExportTableDirectory;
        if (directory.RelativeVirtualAddress == 0 && directory.Size == 0) return false;
        if (directory.Size < 40) throw new BadImageFormatException();
        int offset = RvaOffset(bytes, headers, (uint)directory.RelativeVirtualAddress, 40);
        uint functions = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset + 20));
        uint names = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset + 24));
        if (names > MaximumExportNames || functions > MaximumExportNames) throw new BadImageFormatException();
        uint functionsRva = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset + 28));
        uint namesRva = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset + 32));
        uint ordinalsRva = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset + 36));
        if (names == 0) return false;
        int namesOffset = RvaOffset(bytes, headers, namesRva, checked((int)names * 4));
        int ordinalsOffset = RvaOffset(bytes, headers, ordinalsRva, checked((int)names * 2));
        int functionsOffset = RvaOffset(bytes, headers, functionsRva, checked((int)functions * 4));
        for (int i = 0; i < names; i++)
        {
            uint nameRva = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(namesOffset + i * 4));
            int nameOffset = RvaOffset(bytes, headers, nameRva, 1);
            int length = Math.Min(name.Length + 1, bytes.Length - nameOffset);
            if (length != name.Length + 1 || bytes[nameOffset + name.Length] != 0
                || !bytes.AsSpan(nameOffset, name.Length).SequenceEqual(name)) continue;
            _ = RvaOffset(bytes, headers, nameRva, name.Length + 1);
            ushort ordinal = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(ordinalsOffset + i * 2));
            if (ordinal >= functions) throw new BadImageFormatException();
            rva = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(functionsOffset + ordinal * 4));
            // Forwarded exports are strings, not the runtime's data structure.
            if (rva >= directory.RelativeVirtualAddress
                && (ulong)rva < (ulong)directory.RelativeVirtualAddress + (uint)directory.Size)
                throw new BadImageFormatException();
            return true;
        }
        return false;
    }

    private static int RvaOffset(byte[] bytes, PEHeaders headers, uint rva, int count)
    {
        if (count < 0 || rva == 0) throw new BadImageFormatException();
        int? match = null;
        foreach (SectionHeader section in headers.SectionHeaders)
        {
            long delta = (long)rva - section.VirtualAddress;
            if (delta < 0 || delta + count > section.SizeOfRawData) continue;
            int offset = checked(section.PointerToRawData + (int)delta);
            RequireRange(bytes, offset, count);
            if (match is not null) throw new BadImageFormatException();
            match = offset;
        }
        return match ?? throw new BadImageFormatException();
    }

    private static void RequireRange(byte[] bytes, int offset, int count)
    {
        if (offset < 0 || count < 0 || offset > bytes.Length - count) throw new BadImageFormatException();
    }

    private static bool Contains(byte[] bytes, ReadOnlySpan<byte> value) => bytes.AsSpan().IndexOf(value) >= 0;

    private static TargetClassification Result(ProtectionTargetKind kind, TargetDisposition disposition,
        string code, string architecture = "unknown", string runtime = "unknown", string deployment = "unknown",
        string signing = "unknown", IReadOnlyList<string>? features = null, IReadOnlyList<string>? evidence = null) =>
        new(new(kind, architecture, runtime, deployment, signing, features ?? []), disposition, code, evidence ?? []);
}
