using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;

namespace Rampart.Managed;

internal static class ManagedSignatureBounds
{
    internal static void Validate(MetadataReader reader)
    {
        foreach (var handle in reader.TypeReferences)
        {
            var scope = reader.GetTypeReference(handle).ResolutionScope;
            for (var depth = 0; scope.Kind == HandleKind.TypeReference; depth++)
            {
                if (depth >= 64) Fail();
                scope = reader.GetTypeReference((TypeReferenceHandle)scope).ResolutionScope;
            }
        }
        foreach (var handle in reader.MethodDefinitions) Check(reader.GetMethodDefinition(handle).Signature, false);
        foreach (var handle in reader.FieldDefinitions) Check(reader.GetFieldDefinition(handle).Signature, false);
        foreach (var handle in reader.MemberReferences) Check(reader.GetMemberReference(handle).Signature, false);
        foreach (var handle in reader.PropertyDefinitions) Check(reader.GetPropertyDefinition(handle).Signature, false);
        for (var row = 1; row <= reader.GetTableRowCount(TableIndex.StandAloneSig); row++) Check(reader.GetStandaloneSignature(MetadataTokens.StandaloneSignatureHandle(row)).Signature, false);
        for (var row = 1; row <= reader.GetTableRowCount(TableIndex.TypeSpec); row++) Check(reader.GetTypeSpecification(MetadataTokens.TypeSpecificationHandle(row)).Signature, true);
        for (var row = 1; row <= reader.GetTableRowCount(TableIndex.MethodSpec); row++) Check(reader.GetMethodSpecification(MetadataTokens.MethodSpecificationHandle(row)).Signature, false);

        void Check(BlobHandle handle, bool type)
        {
            var blob = reader.GetBlobReader(handle);
            if (blob.Length > 1024 * 1024 || blob.Length == 0) Fail();
            if (type) Type(ref blob, 0); else Signature(ref blob, 0);
            if (blob.RemainingBytes != 0) Fail();
        }
        void Signature(ref BlobReader blob, int depth)
        {
            if (depth >= 64) Fail();
            var header = blob.ReadByte();
            if (header == 0x06) { Type(ref blob, depth + 1); return; }
            if (header == 0x07 || header == 0x0a)
            {
                var count = Count(ref blob, 16384);
                for (var i = 0; i < count; i++) Type(ref blob, depth + 1);
                return;
            }
            if ((header & 0x10) != 0) Count(ref blob, 1024);
            var parameters = Count(ref blob, 4096);
            Type(ref blob, depth + 1);
            for (var i = 0; i < parameters; i++)
            {
                if (blob.RemainingBytes > 0)
                {
                    var position = blob.Offset; if (blob.ReadByte() != 0x41) blob.Offset = position;
                }
                Type(ref blob, depth + 1);
            }
        }
        void Type(ref BlobReader blob, int depth)
        {
            if (depth >= 64) Fail();
            var code = blob.ReadByte();
            switch (code)
            {
                case >= 0x01 and <= 0x0e: case 0x16: case 0x18: case 0x19: case 0x1c: return;
                case 0x0f: case 0x10: case 0x1d: case 0x45: Type(ref blob, depth + 1); return;
                case 0x11: case 0x12: Token(ref blob, depth + 1); return;
                case 0x13: case 0x1e: Count(ref blob, 1024); return;
                case 0x1f: case 0x20: Token(ref blob, depth + 1); Type(ref blob, depth + 1); return;
                case 0x15:
                    if (blob.ReadByte() is not (0x11 or 0x12)) Fail();
                    Token(ref blob, depth + 1);
                    var arguments = Count(ref blob, 1024);
                    for (var i = 0; i < arguments; i++) Type(ref blob, depth + 1);
                    return;
                case 0x14:
                    Type(ref blob, depth + 1); var rank = Count(ref blob, 32);
                    var sizes = Count(ref blob, rank); for (var i = 0; i < sizes; i++) Count(ref blob, int.MaxValue);
                    var bounds = Count(ref blob, rank); for (var i = 0; i < bounds; i++) blob.ReadCompressedSignedInteger();
                    return;
                case 0x1b: Signature(ref blob, depth + 1); return;
                default: Fail(); return;
            }
        }
        void Token(ref BlobReader blob, int depth)
        {
            var coded = blob.ReadCompressedInteger(); var row = coded >> 2;
            if (row == 0 || coded < 0) Fail();
            var table = (coded & 3) switch { 0 => TableIndex.TypeDef, 1 => TableIndex.TypeRef, 2 => TableIndex.TypeSpec, _ => (TableIndex)255 };
            if (table == (TableIndex)255 || row > reader.GetTableRowCount(table)) Fail();
            if (table == TableIndex.TypeSpec)
            {
                var nested = reader.GetBlobReader(reader.GetTypeSpecification(MetadataTokens.TypeSpecificationHandle(row)).Signature);
                Type(ref nested, depth + 1);
                if (nested.RemainingBytes != 0) Fail();
            }
        }
    }

    private static int Count(ref BlobReader blob, int maximum)
    { var count = blob.ReadCompressedInteger(); if (count < 0 || count > maximum) Fail(); return count; }
    private static void Fail() => ManagedPreflight.Fail("MANAGED_SIGNATURE_LIMIT", "A metadata signature is malformed or exceeds the supported complexity limits.");
}
