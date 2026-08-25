using System.Diagnostics;
using Rampart.Config;
using Rampart.Engine;
using Rampart.Symbols;
using Rampart.Testing;
using Rampart.X64;
using Xunit;

namespace Rampart.Tests.Engine;

public class ProtectorIntegrationTests
{
    [Fact]
    public void SameSeedProducesIdenticalOutput()
    {
        byte[] input = BuildFixture();

        byte[] first = Protect(input, 12345);
        byte[] second = Protect(input, 12345);

        Assert.Equal(first, second);
    }

    [Fact]
    public void DifferentSeedsProduceDifferentOutput()
    {
        byte[] input = BuildFixture();

        byte[] first = Protect(input, 12345);
        byte[] second = Protect(input, 54321);

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void AppliedAndBudgetExcludeSelectedTransformWithNoEligibleBytes()
    {
        KnobCatalog catalog = KnobCatalog.Load();
        var settings = ProtectionSettings.FromPreset(Presets.Light);
        foreach (KnobDef knob in catalog.All)
            settings.Knobs[knob.Id] = ProtectionLevel.Off;
        settings.Knobs["code-transformation.junk-insertion"] = ProtectionLevel.Balanced;

        ProtectionResult result = new Protector().Protect(BuildFixture(), settings, catalog);

        Assert.DoesNotContain("code-transformation.junk-insertion", result.Applied.Keys);
        Assert.Equal(0, result.BudgetPoints);
    }

    [Fact]
    public void BalancedProtectedFixturePreservesNativeExitCodeOnWindows()
    {
        // PE generation is cross-platform, but only Windows can execute this
        // native verification artifact in the test process.
        if (!OperatingSystem.IsWindows())
            return;

        string directory = Path.Combine(Path.GetTempPath(), $"rampart-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        string output = Path.Combine(directory, "protected.exe");
        try
        {
            File.WriteAllBytes(output, Protect(BuildFixture(), 12345));
            using var process = Process.Start(new ProcessStartInfo(output)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            Assert.NotNull(process);
            Assert.True(process.WaitForExit(10_000), "Protected fixture did not exit within ten seconds.");
            Assert.Equal(40, process.ExitCode);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void PrivateSymbolMapCarriesOriginalAndProtectedAddresses()
    {
        byte[] input = BuildFixture();
        var settings = ProtectionSettings.FromPreset(Presets.Balanced);
        settings.Seed = 12345;
        var symbols = new List<SymbolRecord>
        {
            new()
            {
                Name = "ExampleApp::License::Validate",
                StartRva = 0x1000,
                Module = "license.obj",
                Source = "license.cpp",
            },
        };

        ProtectionResult result = new Protector().Protect(input, settings, symbols: symbols);
        ProtectedSymbolMapEntry function = Assert.Single(result.SymbolMap.Functions);

        Assert.Equal("ExampleApp::License::Validate", function.Name);
        Assert.Equal(function.OriginalRva, function.ProtectedRva);
        Assert.Equal("license.obj", function.Module);
        Assert.NotEmpty(function.Applied);
        Assert.Equal(result.InputSha256, result.SymbolMap.InputSha256);
        Assert.Equal(result.OutputSha256, result.SymbolMap.OutputSha256);
    }

    private static byte[] Protect(byte[] input, long seed)
    {
        var settings = ProtectionSettings.FromPreset(Presets.Balanced);
        settings.Seed = seed;
        return new Protector().Protect(input, settings).Output;
    }

    private static byte[] BuildFixture() => TestPeBuilder.Build(ctx =>
    {
        var a = ctx.Code;
        a.MovRi(Reg.Rax, 0);
        a.MovRi(Reg.Rcx, 6);
        a.MovRi(Reg.Rdx, 7);
        a.Label("loop");
        a.AddRr(Reg.Rax, Reg.Rdx);
        a.DecR(Reg.Rcx);
        a.Jcc(Cc.Ne, "loop");
        a.SubRi(Reg.Rax, 2);
        ctx.LeaString(Reg.Rdx, "demo");
        ctx.String("demo", "rampart integration fixture");
    });
}
