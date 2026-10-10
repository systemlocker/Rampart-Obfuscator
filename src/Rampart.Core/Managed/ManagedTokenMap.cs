using System.Buffers.Binary;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using Mono.Cecil;
using ModuleDefinition = Mono.Cecil.ModuleDefinition;
using TypeReference = Mono.Cecil.TypeReference;

namespace Rampart.Managed;

internal sealed class ManagedTokenMap
{
    internal static int[] OriginalTokens(byte[] input)
    {
        using var metadata = new MetadataRows(input);
        return Enumerable.Range(0, Schemas.Length).SelectMany(table => Enumerable.Range(1, metadata.Reader.GetTableRowCount((TableIndex)table))
            .Select(row => table << 24 | row)).Concat(metadata.UserStrings().Select(item => item.Token)).ToArray();
    }
    private readonly Dictionary<int, IMetadataTokenProvider> definitions = [];
    private readonly Dictionary<int, string> references = [];
    private readonly byte[] input;

    internal ManagedTokenMap(byte[] input, ModuleDefinition module)
    {
        this.input = input;
        using var metadata = new MetadataRows(input);
        foreach (var provider in Providers(module))
        {
            var token = provider.MetadataToken.ToInt32();
            if ((token & 0xffffff) != 0) definitions[token] = provider;
        }
        foreach (var table in new[] { 1, 10, 27, 43 })
            for (var row = 1; row <= metadata.Reader.GetTableRowCount((TableIndex)table); row++)
            {
                var token = table << 24 | row;
                if (module.LookupToken(token) is { } provider) references[token] = ReferenceKey(provider);
            }
    }

    internal IReadOnlyList<ManagedTokenMapping> Build(byte[] output, ModuleDefinition emitted, Func<string, string> normalize)
    {
        using var original = new MetadataRows(input); using var rewritten = new MetadataRows(output);
        var mappings = definitions.ToDictionary(p => p.Key, p => p.Value.MetadataToken.ToInt32());
        var rewrittenReferences = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var table in new[] { 1, 10, 27, 43 })
            for (var row = 1; row <= rewritten.Reader.GetTableRowCount((TableIndex)table); row++)
            {
                var token = table << 24 | row;
                if (emitted.LookupToken(token) is { } provider) rewrittenReferences.TryAdd(normalize(ReferenceKey(provider)), token);
            }
        foreach (var reference in references)
            if (rewrittenReferences.TryGetValue(reference.Value, out var token)) mappings[reference.Key] = token;

        // Local signature tokens belong to method bodies, rather than Cecil's token
        // lookup API. Follow the retained MethodDef identity to the emitted signature.
        foreach (var methodHandle in original.Reader.MethodDefinitions)
        {
            var oldMethod = original.Reader.GetMethodDefinition(methodHandle);
            if (oldMethod.RelativeVirtualAddress == 0) continue;
            var signature = original.Pe.GetMethodBody(oldMethod.RelativeVirtualAddress).LocalSignature;
            if (signature.IsNil) continue;
            if (!mappings.TryGetValue(MetadataTokens.GetToken(methodHandle), out var methodToken)) continue;
            var newMethod = rewritten.Reader.GetMethodDefinition((MethodDefinitionHandle)MetadataTokens.EntityHandle(methodToken));
            if (newMethod.RelativeVirtualAddress == 0) continue;
            var newSignature = rewritten.Pe.GetMethodBody(newMethod.RelativeVirtualAddress).LocalSignature;
            if (!newSignature.IsNil) mappings[MetadataTokens.GetToken(signature)] = MetadataTokens.GetToken(newSignature);
        }

        // Remaining rows are relationships. Canonicalize their heap contents and
        // remap every referenced entity before comparing with the emitted table.
        // Several passes allow ExportedType and other relationships to depend on
        // rows whose identity is established later in table order.
        for (var iteration = 0; iteration < 64; iteration++)
        {
            var additions = 0;
            for (var table = 0; table < Schemas.Length; table++)
            {
                var destinations = new Dictionary<string, Queue<int>>(StringComparer.Ordinal);
                for (var row = 1; row <= rewritten.Reader.GetTableRowCount((TableIndex)table); row++)
                {
                    var token = table << 24 | row;
                    var key = rewritten.Key(table, row, null);
                    if (key is null) continue;
                    if (!destinations.TryGetValue(key, out var queue)) destinations.Add(key, queue = new());
                    queue.Enqueue(token);
                }
                for (var row = 1; row <= original.Reader.GetTableRowCount((TableIndex)table); row++)
                {
                    var token = table << 24 | row;
                    if (mappings.ContainsKey(token)) continue;
                    var key = original.Key(table, row, mappings);
                    if (key is null || !destinations.TryGetValue(key, out var queue) || queue.Count == 0) continue;
                    mappings[token] = queue.Dequeue(); additions++;
                }
            }
            if (additions == 0) break;
        }
        var result = new List<ManagedTokenMapping>();
        for (var table = 0; table < Schemas.Length; table++)
            for (var row = 1; row <= original.Reader.GetTableRowCount((TableIndex)table); row++)
            {
                var token = table << 24 | row;
                if (mappings.TryGetValue(token, out var mapped)) result.Add(new(token, mapped));
                else if (references.ContainsKey(token) || table == 17 || table == 40
                    && original.Reader.GetString(original.Reader.GetManifestResource(MetadataTokens.ManifestResourceHandle(row)).Name) == "Rampart.Managed.Watermark")
                    result.Add(new(token, 0) { Status = "removed" });
                else ManagedPreflight.Fail("MANAGED_TOKEN_MAP_UNRESOLVED", $"Original metadata row 0x{token:X8} has no proven output identity.");
            }
        var emittedStrings = rewritten.UserStrings().GroupBy(item => item.Value, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.First().Token, StringComparer.Ordinal);
        foreach (var item in original.UserStrings())
            result.Add(emittedStrings.TryGetValue(item.Value, out var token) ? new(item.Token, token) : new(item.Token, 0) { Status = "removed" });
        return result;
    }

    private static string ReferenceKey(IMetadataTokenProvider provider) => provider switch
    {
        TypeReference type => "T|" + type.FullName + "|" + type.Scope?.Name,
        MethodReference method => "M|" + method.FullName + "|" + method.DeclaringType.Scope?.Name,
        FieldReference field => "F|" + field.FullName + "|" + field.DeclaringType.Scope?.Name,
        _ => provider.MetadataToken.ToString()
    };
    private static IEnumerable<IMetadataTokenProvider> Providers(ModuleDefinition module)
    {
        yield return module; yield return module.Assembly;
        foreach (var reference in module.AssemblyReferences) yield return reference;
        foreach (var reference in module.ModuleReferences) yield return reference;
        foreach (var type in module.ExportedTypes) yield return type;
        foreach (var type in module.GetTypes())
        {
            yield return type;
            foreach (var implementation in type.Interfaces) yield return implementation;
            foreach (var parameter in type.GenericParameters)
            { yield return parameter; foreach (var constraint in parameter.Constraints) yield return constraint; }
            foreach (var field in type.Fields) yield return field;
            foreach (var property in type.Properties) yield return property;
            foreach (var item in type.Events) yield return item;
            foreach (var method in type.Methods)
            {
                yield return method;
                yield return method.MethodReturnType;
                foreach (var parameter in method.Parameters) yield return parameter;
                foreach (var parameter in method.GenericParameters)
                { yield return parameter; foreach (var constraint in parameter.Constraints) yield return constraint; }
            }
        }
    }

    // ECMA-335 II.22 column layouts. Lowercase letters denote heap indices;
    // numeric columns are fixed bytes; @N is a table index, and #N a coded index.
    private static readonly string[][] Schemas = new[]
    {
        "2 s g g g", "#0 s s", "4 s s #1 @4 @6", "@4", "2 s b", "@6", "x4 2 2 s b @8", "@8", "2 2 s",
        "@2 #1", "#2 s b", "2 #3 b", "#4 #5 b", "#6 b", "2 #7 b", "2 4 @2", "4 @4", "b",
        "@2 @20", "@20", "2 s #1", "@2 @23", "@23", "2 s b", "2 @6 #8", "@2 #9 #9", "s", "b",
        "2 #10 s @26", "x4 @4", "4 4", "4", "4 2 2 2 2 4 b s s", "4", "4 4 4", "2 2 2 2 4 b s s b",
        "4 @35", "4 4 4 @35", "4 s b", "4 4 s s #11", "x4 4 s #11", "@2 @2", "2 2 #12 s", "#9 b", "@42 #1"
    }.Select(s => s.Split(' ')).ToArray();

    private static readonly (int Bits, int[] Tables)[] Coded =
    [
        (2, [0, 26, 35, 1]), (2, [2, 1, 27]), (3, [2, 1, 26, 6, 27]), (2, [4, 8, 23]),
        (5, [6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43]),
        (3, [-1, -1, 6, 10, -1]), (1, [4, 8]), (2, [2, 6, 32]), (1, [20, 23]), (1, [6, 10]), (1, [4, 6]),
        (2, [38, 35, 39]), (1, [2, 6])
    ];

    private sealed class MetadataRows : IDisposable
    {
        internal PEReader Pe { get; }
        internal MetadataReader Reader { get; }
        private readonly byte[] metadata;
        private readonly byte heapSizes;
        internal MetadataRows(byte[] image)
        {
            Pe = new PEReader(new MemoryStream(image, false)); Reader = Pe.GetMetadataReader(); metadata = Pe.GetMetadata().GetContent().ToArray();
            var versionLength = BinaryPrimitives.ReadInt32LittleEndian(metadata.AsSpan(12));
            var position = (16 + versionLength + 3) & ~3;
            var streams = BinaryPrimitives.ReadUInt16LittleEndian(metadata.AsSpan(position + 2)); position += 4;
            for (var stream = 0; stream < streams; stream++)
            {
                var offset = BinaryPrimitives.ReadInt32LittleEndian(metadata.AsSpan(position)); position += 8;
                var end = Array.IndexOf(metadata, (byte)0, position);
                var name = System.Text.Encoding.ASCII.GetString(metadata, position, end - position); position = (end + 4) & ~3;
                if (name is "#~" or "#-") { heapSizes = metadata[offset + 6]; return; }
            }
            ManagedPreflight.Fail("MANAGED_TABLE_STREAM", "The metadata table stream is unavailable.");
        }
        internal string? Key(int table, int row, Dictionary<int, int>? mapping)
        {
            var offset = Reader.GetTableMetadataOffset((TableIndex)table) + (row - 1) * Reader.GetTableRowSize((TableIndex)table);
            var parts = new List<string>();
            foreach (var column in Schemas[table])
            {
                var width = column switch
                {
                    "s" => (heapSizes & 1) != 0 ? 4 : 2,
                    "g" => (heapSizes & 2) != 0 ? 4 : 2,
                    "b" => (heapSizes & 4) != 0 ? 4 : 2,
                    "2" => 2,
                    "4" or "x4" => 4,
                    _ when column[0] == '@' => Reader.GetTableRowCount((TableIndex)int.Parse(column[1..])) < 65536 ? 2 : 4,
                    _ => Coded[int.Parse(column[1..])] is var coded && coded.Tables.Where(t => t >= 0).Max(t => Reader.GetTableRowCount((TableIndex)t)) < (1 << (16 - coded.Bits)) ? 2 : 4
                };
                var value = width == 2 ? BinaryPrimitives.ReadUInt16LittleEndian(metadata.AsSpan(offset)) : BinaryPrimitives.ReadInt32LittleEndian(metadata.AsSpan(offset)); offset += width;
                if (column == "x4") continue;
                if (column == "s") { parts.Add("s:" + Reader.GetString(MetadataTokens.StringHandle(value))); continue; }
                if (column == "g") { parts.Add("g:" + (value == 0 ? "" : Reader.GetGuid(MetadataTokens.GuidHandle(value)))); continue; }
                if (column == "b") { parts.Add("b:" + Convert.ToHexString(Reader.GetBlobBytes(MetadataTokens.BlobHandle(value)))); continue; }
                if (column[0] is '@' or '#')
                {
                    var target = int.Parse(column[1..]);
                    if (column[0] == '#')
                    {
                        var coded = Coded[target]; var tag = value & ((1 << coded.Bits) - 1); value >>= coded.Bits;
                        if (tag >= coded.Tables.Length || coded.Tables[tag] < 0) { if (value != 0) return null; target = 0; } else target = coded.Tables[tag];
                    }
                    value = value == 0 ? 0 : target << 24 | value;
                    if (mapping is not null && value != 0 && !mapping.TryGetValue(value, out value)) return null;
                }
                parts.Add(value.ToString(System.Globalization.CultureInfo.InvariantCulture));
            }
            return string.Join("|", parts);
        }
        internal IEnumerable<(int Token, string Value)> UserStrings()
        {
            var start = Reader.GetHeapMetadataOffset(HeapIndex.UserString); var length = Reader.GetHeapSize(HeapIndex.UserString);
            if (length <= 1) yield break;
            for (var position = 1; position < length;)
            {
                var token = position; var first = metadata[start + position++]; int size;
                if ((first & 0x80) == 0) size = first;
                else if ((first & 0xc0) == 0x80)
                { if (position >= length) Invalid(); size = (first & 0x3f) << 8 | metadata[start + position++]; }
                else if ((first & 0xe0) == 0xc0)
                {
                    if (position > length - 3) Invalid();
                    size = (first & 0x1f) << 24 | metadata[start + position] << 16 | metadata[start + position + 1] << 8 | metadata[start + position + 2]; position += 3;
                }
                else { Invalid(); yield break; }
                if (size < 0 || size > length - position) Invalid();
                if (size != 0) yield return (0x70000000 | token, Reader.GetUserString(MetadataTokens.UserStringHandle(token)));
                position += size;
            }
        }
        private static void Invalid() => ManagedPreflight.Fail("MANAGED_USER_STRING_HEAP", "The user-string heap is malformed.");
        public void Dispose() => Pe.Dispose();
    }
}
