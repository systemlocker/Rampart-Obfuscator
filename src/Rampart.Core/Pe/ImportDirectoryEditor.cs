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
        if (string.IsNullOrWhiteSpace(dll))
            throw new ArgumentException("A DLL name is required.", nameof(dll));
        if (names.Length == 0 || names.Any(string.IsNullOrWhiteSpace))
            throw new ArgumentException("At least one non-empty import name is required.", nameof(names));

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
        ctx.Pe.SetDirectory(DataDir.Import, descriptorsRva, (uint)rebuilt.Length);

        for (int i = 0; i < missing.Length; i++)
            result[missing[i]] = iatRva + (uint)(i * 8);
        ctx.Log.Add(new("guard-imports",
            $"added {missing.Length} runtime import(s) from {dll} at RVA {iatRva:X8}"));
        return result;
    }

    private static List<byte[]> ReadDescriptors(PeImage pe)
    {
        var descriptors = new List<byte[]>();
        DataDirectory directory = pe.Directory(DataDir.Import);
        if (directory.IsEmpty)
            return descriptors;

        uint rva = directory.RelativeVirtualAddress;
        for (int i = 0; i < MaximumDescriptors; i++, rva += DescriptorSize)
        {
            byte[] descriptor = pe.ReadRva(rva, DescriptorSize);
            if (descriptor.All(value => value == 0))
                return descriptors;
            descriptors.Add(descriptor);
        }
        throw new BadImageFormatException(
            $"Import directory has more than {MaximumDescriptors} descriptors or no terminator.");
    }

    private static uint WriteAsciiZ(BuildContext ctx, string value)
    {
        byte[] data = Encoding.ASCII.GetBytes(value + "\0");
        uint rva = ctx.AllocData(data.Length);
        ctx.WriteData(rva, data);
        return rva;
    }
}
