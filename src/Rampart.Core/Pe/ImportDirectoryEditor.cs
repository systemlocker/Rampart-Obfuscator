using System.Buffers.Binary;
using System.Text;
using Rampart.Engine;

namespace Rampart.Pe;

/// <summary>Adds ordinary named imports without disturbing existing descriptors.
/// Runtime guard modules use this after import concealment has inspected the
/// application's own imports, keeping guard-only APIs isolated from call-site
/// rewriting.</summary>
public static class ImportDirectoryEditor
{
    private const int DescriptorSize = 20;
    private const int MaximumDescriptors = 16_384;

    public static IReadOnlyDictionary<string, uint> EnsureNamedImports(
        BuildContext ctx,
        string dll,
        params string[] names)
    {
        ArgumentNullException.ThrowIfNull(ctx);
        if (!ctx.Pe.IsPe32Plus)
            throw new NotSupportedException("Runtime import editing requires a PE32+ image.");
        if (!IsValidAsciiName(dll, allowSpaces: true))
            throw new ArgumentException("A valid printable ASCII DLL name is required.", nameof(dll));
        if (names.Length == 0 || names.Any(name => !IsValidAsciiName(name, allowSpaces: false) || name.StartsWith('#')))
            throw new ArgumentException("At least one valid printable ASCII named import is required.", nameof(names));

        var result = new Dictionary<string, uint>(StringComparer.Ordinal);
        string normalizedDll = ImportTable.NormalizeDll(dll);
        List<ImportedFunction> existingFunctions = ImportTable.Parse(ctx.Pe);
        foreach (string name in names.Distinct(StringComparer.Ordinal))
        {
            ImportedFunction? existing = existingFunctions.FirstOrDefault(imported =>
                string.Equals(ImportTable.NormalizeDll(imported.Dll), normalizedDll, StringComparison.OrdinalIgnoreCase)
                && string.Equals(imported.Name, name, StringComparison.Ordinal));
            if (existing is not null)
                result[name] = existing.ThunkRva;
        }

        string[] missing = names
            .Distinct(StringComparer.Ordinal)
            .Where(name => !result.ContainsKey(name))
            .ToArray();
        if (missing.Length == 0)
            return result;

        List<byte[]> descriptors = ReadDescriptors(ctx.Pe);
        uint dllNameRva = WriteAsciiZ(ctx, dll);
        var hintNameRvas = new uint[missing.Length];
        for (int i = 0; i < missing.Length; i++)
        {
            byte[] name = Encoding.ASCII.GetBytes(missing[i] + "\0");
            uint rva = ctx.AllocData(2 + name.Length, 2);
            var hintName = new byte[2 + name.Length];
            name.CopyTo(hintName, 2); // hint zero: the loader falls back to the name.
            ctx.WriteData(rva, hintName);
            hintNameRvas[i] = rva;
        }

        int thunkBytes = checked((missing.Length + 1) * 8);
        uint intRva = ctx.AllocData(thunkBytes, 8);
        uint iatRva = ctx.AllocData(thunkBytes, 8);
        var thunks = new byte[thunkBytes];
        for (int i = 0; i < missing.Length; i++)
            BinaryPrimitives.WriteUInt64LittleEndian(thunks.AsSpan(i * 8), hintNameRvas[i]);
        ctx.WriteData(intRva, thunks);
        ctx.WriteData(iatRva, thunks);

        var descriptor = new byte[DescriptorSize];
        BinaryPrimitives.WriteUInt32LittleEndian(descriptor, intRva);
        BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(12), dllNameRva);
        BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(16), iatRva);
        descriptors.Add(descriptor);

        var rebuilt = new byte[checked((descriptors.Count + 1) * DescriptorSize)];
        for (int i = 0; i < descriptors.Count; i++)
            descriptors[i].CopyTo(rebuilt, i * DescriptorSize);
        uint descriptorsRva = ctx.AllocData(rebuilt.Length, 8);
        ctx.WriteData(descriptorsRva, rebuilt);
        ctx.Pe.SetDirectory(DataDir.Import, descriptorsRva, checked((uint)rebuilt.Length));

        for (int i = 0; i < missing.Length; i++)
            result[missing[i]] = checked(iatRva + (uint)(i * 8));
        ctx.Log.Add(new("guard-imports",
            $"added {missing.Length} runtime import(s) from {dll} at RVA {iatRva:X8}"));
        return result;
    }

    private static bool IsValidAsciiName(string value, bool allowSpaces)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;
        foreach (char c in value)
        {
            if (c < (allowSpaces ? 0x20 : 0x21) || c > 0x7E)
                return false;
        }
        return true;
    }

    private static List<byte[]> ReadDescriptors(PeImage pe)
    {
        var descriptors = new List<byte[]>();
        DataDirectory directory = pe.Directory(DataDir.Import);
        if (directory.IsEmpty)
            return descriptors;
        if (directory.RelativeVirtualAddress == 0 || directory.Size < DescriptorSize)
            throw new BadImageFormatException("Import directory is present but smaller than one descriptor.");

        int maxBySize = checked((int)(directory.Size / DescriptorSize));
        int limit = Math.Min(maxBySize, MaximumDescriptors);
        for (int i = 0; i < limit; i++)
        {
            uint rva = checked(directory.RelativeVirtualAddress + (uint)(i * DescriptorSize));
            byte[] descriptor = pe.ReadRva(rva, DescriptorSize);
            uint originalFirstThunk = BinaryPrimitives.ReadUInt32LittleEndian(descriptor);
            uint nameRva = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(12));
            uint firstThunk = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(16));
            if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0)
                return descriptors;
            descriptors.Add(descriptor);
        }
        if (maxBySize > MaximumDescriptors)
            throw new BadImageFormatException(
                $"Import directory has more than {MaximumDescriptors} descriptors or no terminator.");
        // Some linkers omit the trailing null descriptor from directory.Size;
        // if a null descriptor immediately follows in raw backing, accept it cleanly.
        return descriptors;
    }

    private static uint WriteAsciiZ(BuildContext ctx, string value)
    {
        byte[] data = Encoding.ASCII.GetBytes(value + "\0");
        uint rva = ctx.AllocData(data.Length);
        ctx.WriteData(rva, data);
        return rva;
    }
}
