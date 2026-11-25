using System.Buffers.Binary;
using Rampart.Config;

namespace Rampart.Managed;

internal static class ManagedMetadataBounds
{
    internal static void Validate(ReadOnlySpan<byte> metadata, ManagedProtectionOptions options, bool portablePdb = false)
    {
        if (metadata.Length < 20 || BinaryPrimitives.ReadUInt32LittleEndian(metadata) != 0x424a5342) Fail();
        var versionLength = BinaryPrimitives.ReadInt32LittleEndian(metadata[12..]);
        if (versionLength is < 1 or > 256 || versionLength > metadata.Length - 20 || metadata.Slice(16, versionLength).IndexOf((byte)0) < 0) Fail();
        var position = (16 + versionLength + 3) & ~3;
        if (position > metadata.Length - 4 || BinaryPrimitives.ReadUInt16LittleEndian(metadata[position..]) != 0) Fail();
        var streams = BinaryPrimitives.ReadUInt16LittleEndian(metadata[(position + 2)..]); position += 4;
        if (streams is < 1 or > 16) Fail();
        var names = new HashSet<string>(StringComparer.Ordinal); var ranges = new List<(int Start, int Length)>();
        // Portable PDB #~ streams use debug table indices 0x30..0x37 (bits 48..55)
        // in addition to ECMA-335 type-system table indices 0x00..0x2C (bits 0..44).
        ulong allowedTables = portablePdb ? (((1UL << 45) - 1) | (0xFFUL << 48)) : ((1UL << 45) - 1);
        int maxTableIndex = portablePdb ? 56 : 45;
        for (var stream = 0; stream < streams; stream++)
        {
            if (position > metadata.Length - 12) Fail();
            var offset = BinaryPrimitives.ReadInt32LittleEndian(metadata[position..]);
            var size = BinaryPrimitives.ReadInt32LittleEndian(metadata[(position + 4)..]); position += 8;
            if (offset < 0 || size < 0 || offset > metadata.Length - size) Fail();
            var length = metadata.Slice(position, Math.Min(32, metadata.Length - position)).IndexOf((byte)0);
            if (length < 1) Fail();
            var name = System.Text.Encoding.ASCII.GetString(metadata.Slice(position, length));
            if (!names.Add(name)) Fail(); position = (position + length + 4) & ~3;
            ranges.Add((offset, size));
            if (name is "#~" or "#-")
            {
                var table = metadata.Slice(offset, size);
                if (table.Length < 24) Fail();
                var valid = BinaryPrimitives.ReadUInt64LittleEndian(table[8..]);
                if ((valid & ~allowedTables) != 0) Fail();
                var cursor = 24; long rows = 0;
                for (var index = 0; index < maxTableIndex; index++)
                {
                    if ((valid & (1UL << index)) == 0) continue;
                    if (cursor > table.Length - 4) Fail();
                    var count = BinaryPrimitives.ReadUInt32LittleEndian(table[cursor..]); cursor += 4; rows += count;
                    if (rows > options.MaximumMetadataRows || count > metadata.Length) Fail();
                }
            }
        }
        if (!names.Contains("#~") && !names.Contains("#-")) Fail();
        // ECMA-335 CLI assemblies require #Strings, #GUID, and #Blob heaps; Mono.Cecil
        // dereferences those heap tables unconditionally when reading module metadata.
        if (!portablePdb && (!names.Contains("#Strings") || !names.Contains("#GUID") || !names.Contains("#Blob"))) Fail();
        foreach (var range in ranges) if (range.Start < position) Fail();
        var ordered = ranges.OrderBy(r => r.Start).ToArray();
        for (var i = 1; i < ordered.Length; i++) if (ordered[i].Start < ordered[i - 1].Start + ordered[i - 1].Length) Fail();
    }
    private static void Fail() => ManagedPreflight.Fail("MANAGED_METADATA_ROOT", "The metadata root is malformed or exceeds the supported stream limits.");
}
