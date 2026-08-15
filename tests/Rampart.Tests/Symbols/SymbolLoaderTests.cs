using Rampart.Pe;
using Rampart.Symbols;
using Rampart.Testing;
using Rampart.X64;
using Xunit;

namespace Rampart.Tests.Symbols;

public class SymbolLoaderTests
{
    [Fact]
    public void ParsesMsvcMapPublicsIntoRvas()
    {
        var pe = PeImage.Load(SamplePeBuilder.Build(ctx => ctx.Code.MovRi(Reg.Rax, 40)));
        const string map =
            " 0001:0000000000000000 BirdRodeo::License::Validate 0000000140001000 f license.obj";

        SymbolRecord symbol = Assert.Single(SymbolLoader.ParseMap(map, pe));

        Assert.Equal("BirdRodeo::License::Validate", symbol.Name);
        Assert.Equal(0x1000u, symbol.StartRva);
        Assert.Equal("license.obj", symbol.Module);
    }

    [Fact]
    public void ParsesLlvmPdbPublicDumpUsingSectionOffsets()
    {
        var pe = PeImage.Load(SamplePeBuilder.Build(ctx => ctx.Code.MovRi(Reg.Rax, 40)));
        const string dump = "addr = 0001:00000000, name = BirdRodeo::Gameplay::ScoreBull";

        SymbolRecord symbol = Assert.Single(
            SymbolLoader.ParseLlvmPdbDump(dump, pe, "BirdRodeo.pdb"));

        Assert.Equal("BirdRodeo::Gameplay::ScoreBull", symbol.Name);
        Assert.Equal(0x1000u, symbol.StartRva);
        Assert.Equal("BirdRodeo.pdb", symbol.Source);
    }

    [Fact]
    public void JsonSymbolsRoundTripOptionalSourceMetadata()
    {
        const string json =
            """
            [{"name":"BirdRodeo::Main","startRva":4096,"endRva":4128,"module":"game.obj","source":"main.cpp"}]
            """;

        SymbolRecord symbol = Assert.Single(SymbolLoader.ParseJson(json));

        Assert.Equal(4096u, symbol.StartRva);
        Assert.Equal(4128u, symbol.EndRva);
        Assert.Equal("main.cpp", symbol.Source);
    }
}
