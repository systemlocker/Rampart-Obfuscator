using System.Diagnostics;
using System.Text;
using Rampart.Config;
using Rampart.Engine;
using Rampart.Pe;
using Rampart.Testing;
using Rampart.X64;
using Xunit;

namespace Rampart.Tests.Engine;

public class RuntimeMonitorPassTests
{
    [Fact]
    public void InjectionHunterEmitsClassifierBaselineAndKeepsPassiveNotifierDistinct()
    {
        ProtectionResult result = Protect(["nuclear.injection-hunter"]);
        List<ImportedFunction> imports = ImportTable.Parse(PeImage.Load(result.Output));

        Assert.Equal(ProtectionLevel.Light, result.Applied["nuclear.injection-hunter"]);
        Assert.Contains(result.Log, entry => entry.Pass == "nuclear.injection-hunter");
        Assert.DoesNotContain(result.Log, entry => entry.Pass == "anti-debug.dll-notify");
        AssertMarker(result.Output, "RMPT.INJECT.HUNTER");
        AssertMarker(result.Output, "RMPSTATE");
        Assert.Contains(imports, import => import.Name == "GetModuleFileNameW");
        Assert.Contains(imports, import => import.Name == "GetWindowsDirectoryW");
        Assert.Contains(imports, import => import.Name == "LdrRegisterDllNotification");
        Assert.Contains(imports, import => import.Name == "ExitProcess");
    }

    [Fact]
    public void HiddenThreadsEmitsRealWorkerHideCallsAndMonitorState()
    {
        ProtectionResult result = Protect(["integrity.hidden-threads"]);
        List<ImportedFunction> imports = ImportTable.Parse(PeImage.Load(result.Output));

        Assert.Equal(ProtectionLevel.Light, result.Applied["integrity.hidden-threads"]);
        Assert.Contains(result.Log, entry => entry.Pass == "integrity.hidden-threads");
        AssertMarker(result.Output, "RMPT.HIDDEN.THREAD");
        AssertMarker(result.Output, "RMPT.HIDDEN.LAUNCHER");
        AssertMarker(result.Output, "RMPSTATE");
        foreach (string function in new[] { "CreateThread", "CloseHandle", "Sleep", "NtSetInformationThread" })
            Assert.Contains(imports, import => import.Name == function);
    }

    [Fact]
    public void InjectionHunterAndHiddenMonitorPreserveNativeExitCodeOnWindows()
    {
        if (!OperatingSystem.IsWindows())
            return;

        ProtectionResult result = Protect([
            "nuclear.injection-hunter",
            "integrity.hidden-threads",
        ]);

        string directory = Path.Combine(Path.GetTempPath(), $"rampart-monitor-{Guid.NewGuid():N}");
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
            Assert.Equal(37, process.ExitCode);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static ProtectionResult Protect(string[] enabled)
    {
        KnobCatalog catalog = KnobCatalog.Load();
        var settings = new ProtectionSettings { Preset = Presets.Light, Seed = 0x1A_7E_2026 };
        foreach (KnobDef knob in catalog.All)
            settings.Knobs[knob.Id] = ProtectionLevel.Off;
        settings.Knobs["packaging.ep-confusion"] = ProtectionLevel.Light;
        foreach (string knob in enabled)
            settings.Knobs[knob] = ProtectionLevel.Light;

        return new Protector().Protect(BuildFixture(), settings, catalog);
    }

    private static byte[] BuildFixture() => TestPeBuilder.Build(ctx =>
    {
        ctx.Code.MovRi(Reg.Rax, 37);
        ctx.String("marker", "runtime monitor behavior fixture");
        ctx.LeaString(Reg.Rdx, "marker");
    });

    private static void AssertMarker(byte[] image, string marker) =>
        Assert.True(image.AsSpan().IndexOf(Encoding.ASCII.GetBytes(marker)) >= 0,
            $"Expected marker '{marker}' in protected image.");
}
