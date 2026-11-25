using System.Buffers.Binary;
using System.IO.Compression;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using Rampart.Config;

namespace Rampart.Managed;

internal static class ManagedPreflight
{
    internal static void ValidatePortablePdb(ReadOnlySpan<byte> pdb, ManagedProtectionOptions options)
    {
        if (pdb.Length > options.MaximumInputBytes)
            Fail("MANAGED_SYMBOL_LIMIT", "The symbol file exceeds the configured input limit.");
        ManagedMetadataBounds.Validate(pdb, options, portablePdb: true);
    }

    internal static void Validate(byte[] image, ManagedProtectionOptions options)
    {
        if (options.MaximumInputBytes is < 1024 or > 268435456 || options.MaximumMethods is < 1 or > 200000
            || options.MaximumMethodBytes is < 1 or > 4194304 || options.MaximumMetadataRows is < 1 or > 2000000
            || options.MaximumOutputGrowthPercent is < 0 or > 1000)
            Fail("MANAGED_LIMITS", "Managed resource limits are outside the supported bounds.");
        if (image.Length > options.MaximumInputBytes) Fail("MANAGED_INPUT_LIMIT", "The assembly exceeds the configured input size limit.");
        try
        {
            using var pe = new PEReader(new MemoryStream(image, false));
            var optional = pe.PEHeaders.PEHeader;
            if (optional is null || optional.SizeOfImage <= 0 || optional.SizeOfImage > 268435456
                || optional.SizeOfHeaders < 0 || optional.SizeOfHeaders > image.Length)
                Fail("MANAGED_IMAGE_LIMIT", "The PE image exceeds the supported header or virtual image bounds.");
            // SRM only touches sections needed for metadata. Cecil materializes every
            // section, so validate even unused resource/debug section ranges first.
            foreach (var section in pe.PEHeaders.SectionHeaders)
                if (section.SizeOfRawData < 0 || section.PointerToRawData < 0
                    || section.PointerToRawData > image.Length - section.SizeOfRawData
                    || section.VirtualSize < 0 || section.VirtualSize > 268435456)
                    Fail("MANAGED_SECTION_RANGE", "A PE section exceeds the file or supported image bounds.");
            var cor = pe.PEHeaders.CorHeader;
            if (cor is null || !pe.HasMetadata) Fail("MANAGED_NO_CLI", "A CLI metadata header is required.");
            if ((cor!.Flags & CorFlags.ILOnly) == 0
                || (cor.Flags & (CorFlags.Requires32Bit | CorFlags.Prefers32Bit | CorFlags.NativeEntryPoint)) != 0)
                Fail("MANAGED_NOT_PURE_IL", "Only pure-IL AnyCPU and x64 assemblies are supported.");
            if (cor.ManagedNativeHeaderDirectory.Size != 0) Fail("MANAGED_READYTORUN", "Protect the assembly before ReadyToRun compilation.");
            if (pe.PEHeaders.CoffHeader.Machine is not (Machine.I386 or Machine.Amd64)) Fail("MANAGED_ARCHITECTURE", "The managed architecture is unsupported.");
            if (pe.PEHeaders.PEHeader!.CertificateTableDirectory.Size != 0) Fail("MANAGED_AUTHENTICODE", "Protect the assembly before Authenticode signing.");
            var debug = pe.ReadDebugDirectory();
            if (debug.Length > 1024) Fail("MANAGED_SYMBOL_LIMIT", "The debug directory exceeds its entry limit.");
            foreach (var entry in debug)
                if (entry.Type == DebugDirectoryEntryType.EmbeddedPortablePdb)
                {
                    if (entry.DataSize < 8 || entry.DataPointer < 0 || entry.DataPointer > image.Length - entry.DataSize)
                        Fail("MANAGED_INVALID_SYMBOLS", "An embedded symbol directory is malformed.");
                    if (!image.AsSpan(entry.DataPointer, 4).SequenceEqual("MPDB"u8))
                        Fail("MANAGED_INVALID_SYMBOLS", "An embedded symbol entry does not begin with the MPDB header.");
                    var expanded = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(entry.DataPointer + 4, 4));
                    if (expanded < 20 || expanded > options.MaximumInputBytes)
                        Fail("MANAGED_SYMBOL_LIMIT", "The embedded symbols exceed the configured expansion limit.");
                    var inflated = InflateBounded(image, entry.DataPointer + 8, entry.DataSize - 8, expanded);
                    ManagedMetadataBounds.Validate(inflated, options, portablePdb: true);
                }
            if (cor.MetadataDirectory.Size < 0 || cor.MetadataDirectory.Size > options.MaximumInputBytes)
                Fail("MANAGED_METADATA_LIMIT", "The metadata root exceeds the configured size limit.");
            ManagedMetadataBounds.Validate(pe.GetMetadata().GetContent().AsSpan(), options);
            var reader = pe.GetMetadataReader();
            if (!reader.IsAssembly) Fail("MANAGED_NETMODULE", "Multi-module assemblies are unsupported.");
            if ((reader.MetadataKind != MetadataKind.Ecma335)) Fail("MANAGED_WINRT", "Windows Runtime metadata is unsupported.");
            var moduleDef = reader.GetModuleDefinition();
            _ = reader.GetString(moduleDef.Name);
            if (!moduleDef.Mvid.IsNil) _ = reader.GetGuid(moduleDef.Mvid);
            if (!moduleDef.GenerationId.IsNil) _ = reader.GetGuid(moduleDef.GenerationId);
            if (!moduleDef.BaseGenerationId.IsNil) _ = reader.GetGuid(moduleDef.BaseGenerationId);
            long rows = 0;
            foreach (TableIndex table in Enum.GetValues<TableIndex>()) rows += reader.GetTableRowCount(table);
            if (rows > options.MaximumMetadataRows || reader.MethodDefinitions.Count > options.MaximumMethods)
                Fail("MANAGED_METADATA_LIMIT", "The metadata exceeds the configured row limit.");
            ManagedSignatureBounds.Validate(reader);
            foreach (var file in reader.AssemblyFiles)
                if (reader.GetAssemblyFile(file).ContainsMetadata) Fail("MANAGED_MULTIMODULE", "Multi-module assemblies are unsupported.");
            if (cor.ResourcesDirectory.Size < 0 || cor.ResourcesDirectory.Size > options.MaximumInputBytes)
                Fail("MANAGED_RESOURCE_LIMIT", "The managed resources exceed the configured size limit.");
            var resourceBytes = cor.ResourcesDirectory.Size == 0 ? Array.Empty<byte>()
                : pe.GetSectionData(cor.ResourcesDirectory.RelativeVirtualAddress).GetContent(0, cor.ResourcesDirectory.Size).ToArray();
            foreach (var handle in reader.ManifestResources)
            {
                var resource = reader.GetManifestResource(handle);
                if (!resource.Implementation.IsNil) continue;
                if (resource.Offset < 0 || resource.Offset > resourceBytes.Length - 4)
                    Fail("MANAGED_RESOURCE_RANGE", "An embedded resource has an invalid data offset.");
                var length = BinaryPrimitives.ReadUInt32LittleEndian(resourceBytes.AsSpan((int)resource.Offset));
                if (length > resourceBytes.Length - resource.Offset - 4)
                    Fail("MANAGED_RESOURCE_RANGE", "An embedded resource exceeds its containing data directory.");
            }
            foreach (var type in reader.TypeDefinitions)
            {
                if (reader.GetTypeDefinition(type).GetLayout().Size > options.MaximumInputBytes)
                    Fail("MANAGED_LAYOUT_LIMIT", "A type layout exceeds the configured data size limit.");
                var current = type;
                for (var depth = 0; !current.IsNil; depth++)
                {
                    if (depth > 64) Fail("MANAGED_NESTING_LIMIT", "The metadata nesting limit was exceeded.");
                    current = reader.GetTypeDefinition(current).GetDeclaringType();
                }
            }
            foreach (var handle in reader.MethodDefinitions)
            {
                var method = reader.GetMethodDefinition(handle);
                if (method.RelativeVirtualAddress == 0) continue;
                var body = pe.GetMethodBody(method.RelativeVirtualAddress);
                if (body.Size > options.MaximumMethodBytes) Fail("MANAGED_METHOD_LIMIT", "A method exceeds the configured size limit.");
                var ilBytes = body.GetILBytes()!;
                var starts = ManagedInstructionBounds.Validate(ilBytes, reader);
                var length = ilBytes.Length;
                foreach (var region in body.ExceptionRegions)
                {
                    if (region.TryOffset < 0 || region.TryLength <= 0 || region.TryOffset > length - region.TryLength
                        || region.HandlerOffset < 0 || region.HandlerLength <= 0 || region.HandlerOffset > length - region.HandlerLength)
                        Fail("MANAGED_INVALID_EH", "A method has an invalid exception region.");
                    int tryEnd = region.TryOffset + region.TryLength;
                    int handlerEnd = region.HandlerOffset + region.HandlerLength;
                    if (!starts.Contains(region.TryOffset) || (tryEnd < length && !starts.Contains(tryEnd))
                        || !starts.Contains(region.HandlerOffset) || (handlerEnd < length && !starts.Contains(handlerEnd)))
                        Fail("MANAGED_INVALID_EH", "A method exception region does not align with instruction boundaries.");
                    if (region.Kind == ExceptionRegionKind.Filter
                        && (region.FilterOffset < 0 || region.FilterOffset >= region.HandlerOffset || !starts.Contains(region.FilterOffset)))
                        Fail("MANAGED_INVALID_EH", "A method filter exception region has an invalid filter offset.");
                }
            }
        }
        catch (ManagedProtectionException) { throw; }
        catch (Exception error) when (error is BadImageFormatException or InvalidDataException or ArgumentException or InvalidOperationException or OverflowException or IndexOutOfRangeException)
        { throw new ManagedProtectionException("MANAGED_INVALID_METADATA", "The assembly metadata is malformed.", error); }
    }

    private static byte[] InflateBounded(byte[] image, int offset, int length, int expectedSize)
    {
        using var compressed = new MemoryStream(image, offset, length, writable: false);
        using var deflate = new DeflateStream(compressed, CompressionMode.Decompress);
        var buffer = new byte[expectedSize];
        var read = 0;
        while (read < expectedSize)
        {
            var count = deflate.Read(buffer, read, expectedSize - read);
            if (count == 0) Fail("MANAGED_INVALID_SYMBOLS", "The embedded symbol stream is truncated.");
            read += count;
        }
        var extra = new byte[1];
        if (deflate.Read(extra, 0, 1) != 0)
            Fail("MANAGED_SYMBOL_LIMIT", "The embedded symbol stream exceeds its declared expanded size.");
        return buffer;
    }

    internal static void Fail(string code, string message) => throw new ManagedProtectionException(code, message);
}
