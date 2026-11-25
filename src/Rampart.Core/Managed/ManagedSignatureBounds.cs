using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;

namespace Rampart.Managed;

internal static class ManagedSignatureBounds
{
    private const int MaximumDepth = 64;

    internal static void Validate(MetadataReader reader)
    {
        foreach (var handle in reader.TypeReferences)
        {
            var seen = new HashSet<EntityHandle> { handle };
            var scope = reader.GetTypeReference(handle).ResolutionScope;
            for (var depth = 0; scope.Kind == HandleKind.TypeReference; depth++)
            {
                if (depth >= MaximumDepth || !seen.Add(scope)) Fail();
                scope = reader.GetTypeReference((TypeReferenceHandle)scope).ResolutionScope;
            }
        }
        foreach (var handle in reader.ExportedTypes)
        {
            var seen = new HashSet<EntityHandle> { handle };
            var implementation = reader.GetExportedType(handle).Implementation;
            for (var depth = 0; implementation.Kind == HandleKind.ExportedType; depth++)
            {
                if (depth >= MaximumDepth || !seen.Add(implementation)) Fail();
                implementation = reader.GetExportedType((ExportedTypeHandle)implementation).Implementation;
            }
        }

        // Memoize each TypeSpec row's validated nesting height so DAG-shaped TypeSpec
        // references validate in linear time rather than exponential tree traversal.
        var visitingTypeSpecs = new HashSet<int>();
        var typeSpecHeights = new Dictionary<int, int>();

        foreach (var handle in reader.MethodDefinitions) Check(reader.GetMethodDefinition(handle).Signature, false);
        foreach (var handle in reader.FieldDefinitions) Check(reader.GetFieldDefinition(handle).Signature, false);
        foreach (var handle in reader.MemberReferences) Check(reader.GetMemberReference(handle).Signature, false);
        foreach (var handle in reader.PropertyDefinitions) Check(reader.GetPropertyDefinition(handle).Signature, false);
        for (var row = 1; row <= reader.GetTableRowCount(TableIndex.StandAloneSig); row++) Check(reader.GetStandaloneSignature(MetadataTokens.StandaloneSignatureHandle(row)).Signature, false);
        for (var row = 1; row <= reader.GetTableRowCount(TableIndex.TypeSpec); row++) _ = CheckTypeSpec(row, 0);
        for (var row = 1; row <= reader.GetTableRowCount(TableIndex.MethodSpec); row++) Check(reader.GetMethodSpecification(MetadataTokens.MethodSpecificationHandle(row)).Signature, false);

        void Check(BlobHandle handle, bool type)
        {
            var blob = reader.GetBlobReader(handle);
            if (blob.Length > 1024 * 1024 || blob.Length == 0) Fail();
            var height = type ? Type(ref blob, 0) : Signature(ref blob, 0);
            if (height >= MaximumDepth || blob.RemainingBytes != 0) Fail();
        }
        int CheckTypeSpec(int row, int depth)
        {
            if (depth >= MaximumDepth) Fail();
            if (typeSpecHeights.TryGetValue(row, out var cachedHeight))
            {
                if (depth + cachedHeight >= MaximumDepth) Fail();
                return cachedHeight;
            }
            if (!visitingTypeSpecs.Add(row)) Fail();
            var blob = reader.GetBlobReader(reader.GetTypeSpecification(MetadataTokens.TypeSpecificationHandle(row)).Signature);
            if (blob.Length > 1024 * 1024 || blob.Length == 0) Fail();
            var height = Type(ref blob, depth);
            if (blob.RemainingBytes != 0) Fail();
            visitingTypeSpecs.Remove(row);
            typeSpecHeights[row] = height;
            if (depth + height >= MaximumDepth) Fail();
            return height;
        }
        int Signature(ref BlobReader blob, int depth)
        {
            if (depth >= MaximumDepth) Fail();
            var header = blob.ReadByte();
            if (header == 0x06) return 1 + Type(ref blob, depth + 1);
            if (header == 0x07 || header == 0x0a)
            {
                var count = Count(ref blob, 16384);
                var max = 0;
                for (var i = 0; i < count; i++) max = Math.Max(max, Type(ref blob, depth + 1));
                return 1 + max;
            }
            if ((header & 0x10) != 0) Count(ref blob, 1024);
            var parameters = Count(ref blob, 4096);
            var height = Type(ref blob, depth + 1);
            for (var i = 0; i < parameters; i++)
            {
                if (blob.RemainingBytes > 0)
                {
                    var position = blob.Offset; if (blob.ReadByte() != 0x41) blob.Offset = position;
                }
                height = Math.Max(height, Type(ref blob, depth + 1));
            }
            return 1 + height;
        }
        int Type(ref BlobReader blob, int depth)
        {
            if (depth >= MaximumDepth) Fail();
            var code = blob.ReadByte();
            switch (code)
            {
                case >= 0x01 and <= 0x0e: case 0x16: case 0x18: case 0x19: case 0x1c: return 0;
                case 0x0f: case 0x10: case 0x1d: case 0x45: return 1 + Type(ref blob, depth + 1);
                case 0x11: case 0x12: return 1 + Token(ref blob, depth + 1);
                case 0x13: case 0x1e: Count(ref blob, 1024); return 0;
                case 0x1f: case 0x20: return 1 + Math.Max(Token(ref blob, depth + 1), Type(ref blob, depth + 1));
                case 0x15:
                    if (blob.ReadByte() is not (0x11 or 0x12)) Fail();
                    var genericHeight = Token(ref blob, depth + 1);
                    var arguments = Count(ref blob, 1024);
                    for (var i = 0; i < arguments; i++) genericHeight = Math.Max(genericHeight, Type(ref blob, depth + 1));
                    return 1 + genericHeight;
                case 0x14:
                    var elementHeight = Type(ref blob, depth + 1);
                    var rank = Count(ref blob, 32);
                    if (rank == 0) Fail();
                    var sizes = Count(ref blob, rank); for (var i = 0; i < sizes; i++) Count(ref blob, int.MaxValue);
                    var bounds = Count(ref blob, rank); for (var i = 0; i < bounds; i++) blob.ReadCompressedSignedInteger();
                    return 1 + elementHeight;
                case 0x1b: return 1 + Signature(ref blob, depth + 1);
                default: Fail(); return 0;
            }
        }
        int Token(ref BlobReader blob, int depth)
        {
            var coded = blob.ReadCompressedInteger(); var row = coded >> 2;
            if (row == 0 || coded < 0) Fail();
            var table = (coded & 3) switch { 0 => TableIndex.TypeDef, 1 => TableIndex.TypeRef, 2 => TableIndex.TypeSpec, _ => (TableIndex)255 };
            if (table == (TableIndex)255 || row > reader.GetTableRowCount(table)) Fail();
            return table == TableIndex.TypeSpec ? CheckTypeSpec(row, depth) : 0;
        }
    }

    private static int Count(ref BlobReader blob, int maximum)
    { var count = blob.ReadCompressedInteger(); if (count < 0 || count > maximum) Fail(); return count; }
    private static void Fail() => ManagedPreflight.Fail("MANAGED_SIGNATURE_LIMIT", "A metadata signature is malformed or exceeds the supported complexity limits.");
}
