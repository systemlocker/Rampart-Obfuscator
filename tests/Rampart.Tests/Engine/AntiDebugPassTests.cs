using System.Diagnostics;
using System.Text;
using Rampart.Config;
using Rampart.Engine;
using Rampart.Pe;
using Rampart.Testing;
using Rampart.X64;
using Xunit;

namespace Rampart.Tests.Engine;

public class AntiDebugPassTests
{
    public static TheoryData<string, string, string[]> IndividualProtections => new()
    {
        {
            "anti-debug.channel-sweep",
            "RMPT.ADBG.CHAN",
            ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]
        },
        {
            "anti-debug.inline-hook-check",
            "RMPT.ADBG.HOOK",
            ["NtQueryInformationProcess", "NtProtectVirtualMemory", "LdrLoadDll"]
        },
        {
            "anti-debug.veh-tamper",
            "RMPT.ADBG.VEH.HANDLER",
            ["RtlAddVectoredExceptionHandler", "RaiseException"]
        },
        {
            "anti-debug.dll-notify",
            "RMPT.ADBG.LDR.CALLBACK",
            ["LdrRegisterDllNotification"]
        },
    };

    [Theory]
    [MemberData(nameof(IndividualProtections))]
    public void EachProtectionEmitsInspectableRuntimeStateAndImports(
        string knob,
        string marker,
        string[] expectedImports)
    {
        ProtectionResult result = Protect([knob]);
        PeImage output = PeImage.Load(result.Output);
        List<ImportedFunction> imports = ImportTable.Parse(output);

        Assert.Contains(knob, result.Applied.Keys);
        Assert.Contains(result.Log, entry => entry.Pass == knob);
        Assert.True(Contains(result.Output, Encoding.ASCII.GetBytes(marker)),
            $"Expected marker '{marker}' in protected image.");
        foreach (string function in expectedImports)
            Assert.Contains(imports, import => import.Name == function);
    }

    [Fact]
    public void RuntimeImportAppendPreservesOriginalImports()
    {
        ProtectionResult result = Protect([
            "anti-debug.channel-sweep",
            "anti-debug.inline-hook-check",
            "anti-debug.veh-tamper",
            "anti-debug.dll-notify",
        ]);

        List<ImportedFunction> imports = ImportTable.Parse(PeImage.Load(result.Output));
        Assert.Contains(imports, import => import.Name == "ExitProcess");
        Assert.Equal(9, imports.Select(import => import.Name).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(4, result.Log.Count(entry => entry.Pass.StartsWith("anti-debug.", StringComparison.Ordinal)
            && entry.Pass != "anti-debug.imports"));
    }

    [Fact]
    public void AllLightAntiDebugProtectionsPreserveNativeExitCodeOnWindows()
    {
        if (!OperatingSystem.IsWindows())
            return;

        ProtectionResult result = Protect([
            "anti-debug.channel-sweep",
            "anti-debug.inline-hook-check",
            "anti-debug.veh-tamper",
            "anti-debug.dll-notify",
        ]);

        string directory = Path.Combine(Path.GetTempPath(), $"rampart-antidebug-{Guid.NewGuid():N}");
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
            Assert.Equal(23, process.ExitCode);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static ProtectionResult Protect(string[] enabled)
    {
        KnobCatalog catalog = KnobCatalog.Load();
        var settings = new ProtectionSettings { Preset = Presets.Light, Seed = 0xAD_B6_2026 };
        foreach (KnobDef knob in catalog.All)
            settings.Knobs[knob.Id] = ProtectionLevel.Off;
        settings.Knobs["packaging.ep-confusion"] = ProtectionLevel.Light;
        foreach (string knob in enabled)
            settings.Knobs[knob] = ProtectionLevel.Light;

        return new Protector().Protect(BuildFixture(), settings, catalog);
    }

    private static byte[] BuildFixture() => TestPeBuilder.Build(ctx =>
    {
        ctx.Code.MovRi(Reg.Rax, 23);
        ctx.String("marker", "anti-debug behavior fixture");
        ctx.LeaString(Reg.Rdx, "marker");
    });

    private static bool Contains(byte[] haystack, byte[] needle) =>
        haystack.AsSpan().IndexOf(needle) >= 0;
}
