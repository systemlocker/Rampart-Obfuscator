using System.Buffers.Binary;
using System.Text;
using Rampart.Pe;
using Rampart.Testing;
using Rampart.X64;
using Xunit;

namespace Rampart.Tests.Pe;

public class ImportTableTests
{
    [Fact]
    public void ImportNameMayEndAtRawSectionBoundary()
    {
        var pe = PeImage.Load(TestPeBuilder.Build(ctx => ctx.Code.MovRi(Reg.Rax, 7)));
        DataDirectory imports = pe.Directory(DataDir.Import);
        uint intRva = pe.ReadU32(imports.RelativeVirtualAddress);
        PeImage.Section rdata = pe.Sections.Single(section => section.Name == ".rdata");
        byte[] encodedName = Encoding.ASCII.GetBytes("ExitProcess\0");
        uint hintNameRva = rdata.VirtualAddress + rdata.SizeOfRawData - (uint)(encodedName.Length + 2);

        pe.WriteRva(hintNameRva, new byte[2]);
        pe.WriteRva(hintNameRva + 2, encodedName);
        Span<byte> pointer = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(pointer, hintNameRva);
        pe.WriteRva(intRva, pointer);

        ImportedFunction imported = Assert.Single(ImportTable.Parse(pe));
        Assert.Equal("ExitProcess", imported.Name);
    }
}
