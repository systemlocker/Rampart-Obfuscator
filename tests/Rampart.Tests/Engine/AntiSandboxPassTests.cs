using System.Diagnostics;
using System.Text;
using Rampart.Config;
using Rampart.Engine;
using Rampart.Pe;
using Rampart.Testing;
using Rampart.X64;
using Xunit;

namespace Rampart.Tests.Engine;

public class AntiSandboxPassTests
{
    public static TheoryData<string, string, string[]> IndividualProtections => new()
    {
        {
            "anti-sandbox.virtualisation-detect",
            "RMPT.ASBX.CPUID",
            []
        },
        {
            "anti-sandbox.fingerprint-suite",
            "RMPT.ASBX.FINGERPRINT",
            ["GetEnvironmentVariableW", "GetModuleHandleW"]
        },
        {
            "anti-sandbox.human-gate",
            "RMPT.ASBX.HUMAN",
            ["GetTickCount64", "GetLastInputInfo"]
        },
    };

    [Theory]
    [MemberData(nameof(IndividualProtections))]
    public void EachProtectionEmitsInspectableStateAndRequiredImports(
        string knob,
        string marker,
        string[] expectedImports)
    {
        ProtectionResult result = Protect([knob]);
        List<ImportedFunction> imports = ImportTable.Parse(PeImage.Load(result.Output));

        Assert.Contains(knob, result.Applied.Keys);
        Assert.Contains(result.Log, entry => entry.Pass == knob);
        Assert.True(result.Output.AsSpan().IndexOf(Encoding.ASCII.GetBytes(marker)) >= 0,
            $"Expected marker '{marker}' in protected image.");
        foreach (string function in expectedImports)
            Assert.Contains(imports, import => import.Name == function);

        Assert.True(result.Output.AsSpan().IndexOf(Encoding.ASCII.GetBytes("RMPSTATE")) >= 0,
            "Sandbox producers must share the runtime detection record.");
    }

    [Fact]
    public void AllLightAntiSandboxProtectionsPreserveNativeExitCodeOnWindows()
    {
        if (!OperatingSystem.IsWindows())
            return;

        ProtectionResult result = Protect([
            "anti-sandbox.virtualisation-detect",
            "anti-sandbox.fingerprint-suite",
            "anti-sandbox.human-gate",
        ]);

        string directory = Path.Combine(Path.GetTempPath(), $"rampart-antisandbox-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        string executable = Path.Combine(directory, "protected.exe");
        try
        {
            File.WriteAllBytes(executable, result.Output);
            using Process? process = Process.Start(new ProcessStartInfo(executable)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            Assert.NotNull(process);
            Assert.True(process.WaitForExit(10_000), "Protected fixture did not exit within ten seconds.");
            Assert.Equal(31, process.ExitCode);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static ProtectionResult Protect(string[] enabled)
    {
        KnobCatalog catalog = KnobCatalog.Load();
        var settings = new ProtectionSettings { Preset = Presets.Light, Seed = 0x5A_B0_2026 };
        foreach (KnobDef knob in catalog.All)
            settings.Knobs[knob.Id] = ProtectionLevel.Off;
        settings.Knobs["packaging.ep-confusion"] = ProtectionLevel.Light;
        foreach (string knob in enabled)
            settings.Knobs[knob] = ProtectionLevel.Light;

        return new Protector().Protect(BuildFixture(), settings, catalog);
    }

    private static byte[] BuildFixture() => TestPeBuilder.Build(ctx =>
    {
        ctx.Code.MovRi(Reg.Rax, 31);
        ctx.String("marker", "anti-sandbox behavior fixture");
        ctx.LeaString(Reg.Rdx, "marker");
    });
}
