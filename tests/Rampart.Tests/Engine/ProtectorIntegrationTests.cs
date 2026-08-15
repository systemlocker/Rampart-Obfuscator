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
        byte[] input = BuildSample();

        byte[] first = Protect(input, 12345);
        byte[] second = Protect(input, 12345);

        Assert.Equal(first, second);
    }

    [Fact]
    public void DifferentSeedsProduceDifferentOutput()
    {
        byte[] input = BuildSample();

        byte[] first = Protect(input, 12345);
        byte[] second = Protect(input, 54321);

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void BalancedProtectedSamplePreservesNativeExitCodeOnWindows()
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
            File.WriteAllBytes(output, Protect(BuildSample(), 12345));
            using var process = Process.Start(new ProcessStartInfo(output)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            Assert.NotNull(process);
            Assert.True(process.WaitForExit(10_000), "Protected sample did not exit within ten seconds.");
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
        byte[] input = BuildSample();
        var settings = ProtectionSettings.FromPreset(Presets.Balanced);
        settings.Seed = 12345;
        var symbols = new List<SymbolRecord>
        {
            new()
            {
                Name = "BirdRodeo::License::Validate",
                StartRva = 0x1000,
                Module = "license.obj",
                Source = "license.cpp",
            },
        };

        ProtectionResult result = new Protector().Protect(input, settings, symbols: symbols);
        ProtectedSymbolMapEntry function = Assert.Single(result.SymbolMap.Functions);

        Assert.Equal("BirdRodeo::License::Validate", function.Name);
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

    private static byte[] BuildSample() => SamplePeBuilder.Build(ctx =>
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
        ctx.String("demo", "rampart integration sample");
    });
}
