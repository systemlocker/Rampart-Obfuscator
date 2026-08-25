using System.Diagnostics;
using Rampart.Config;
using Rampart.Engine;
using Rampart.Testing;
using Rampart.X64;
using Xunit;

namespace Rampart.Tests.Engine;

public class ProtectionMilestoneIntegrationTests
{
    private static readonly string[] NewBehaviorPreservingProtections =
    [
        "analysis.ida-bomb",
        "analysis.hexrays-denial",
        "analysis.symbolic-denial",
        "analysis.static-decode-denial",
        "analysis.runtime-header-corruption",
        "anti-debug.channel-sweep",
        "anti-debug.inline-hook-check",
        "anti-debug.veh-tamper",
        "anti-debug.dll-notify",
        "anti-sandbox.virtualisation-detect",
        "anti-sandbox.fingerprint-suite",
        "anti-sandbox.human-gate",
        "anti-inject.dacl-hardening",
        "anti-inject.cet-shadow-stack",
        "anti-inject.dynamic-code-policy",
        "anti-inject.iat-hash-check",
        "memory.anti-dump",
        "memory.api-concealment",
        "integrity.header-scrub",
        "integrity.kernel-wall",
        "integrity.measurement-channels",
        "integrity.tls-veh-ownership",
        "integrity.mitigation-stack",
        "integrity.hidden-threads",
        "response.silent-taint",
        "response.brand-overlay",
        "response.custom-messages",
        "nuclear.injection-hunter",
    ];

    [Fact]
    public void NewLightProtectionsComposeWithoutChangingNativeBehavior()
    {
        if (!OperatingSystem.IsWindows())
            return;

        KnobCatalog catalog = KnobCatalog.Load();
        var settings = new ProtectionSettings
        {
            Preset = Presets.Light,
            Seed = 0xB1_7D_2026,
            Watermark = "Example App milestone",
            CustomMessage = "Example App integrity check",
        };
        foreach (KnobDef knob in catalog.All)
            settings.Knobs[knob.Id] = ProtectionLevel.Off;
        settings.Knobs["packaging.ep-confusion"] = ProtectionLevel.Light;
        foreach (string knob in NewBehaviorPreservingProtections)
            settings.Knobs[knob] = ProtectionLevel.Light;

        ProtectionResult result = new Protector().Protect(BuildFixture(), settings, catalog);

        foreach (string knob in NewBehaviorPreservingProtections)
        {
            Assert.Equal(ProtectionLevel.Light, result.Applied[knob]);
            string evidencePass = knob switch
            {
                "analysis.ida-bomb" => "ida-bomb",
                "analysis.hexrays-denial" => "hexrays-denial",
                "analysis.symbolic-denial" => "symbolic-denial",
                "analysis.static-decode-denial" => "static-decode-denial",
                "memory.api-concealment" => "api-concealment",
                _ => knob,
            };
            Assert.True(result.Log.Any(entry => entry.Pass == evidencePass),
                $"Protection '{knob}' did not emit build-log evidence under '{evidencePass}'.");
        }

        AssertNativeExitCode(result.Output, 53);
    }

    private static byte[] BuildFixture() => TestPeBuilder.Build(ctx =>
    {
        ctx.Code.MovRi(Reg.Rax, 53);
        ctx.String("marker", "Example App protection milestone");
        ctx.LeaString(Reg.Rdx, "marker");
    });

    private static void AssertNativeExitCode(byte[] image, int expected)
    {
        string directory = Path.Combine(Path.GetTempPath(), $"rampart-milestone-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        string executable = Path.Combine(directory, "protected.exe");
        try
        {
            File.WriteAllBytes(executable, image);
            using Process? process = Process.Start(new ProcessStartInfo(executable)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            Assert.NotNull(process);
            Assert.True(process.WaitForExit(10_000), "Protected fixture did not exit within ten seconds.");
            Assert.Equal(expected, process.ExitCode);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
