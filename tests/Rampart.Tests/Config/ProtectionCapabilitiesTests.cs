using Rampart.Config;
using Rampart.Engine;
using Xunit;

namespace Rampart.Tests.Config;

public class ProtectionCapabilitiesTests
{
    private static readonly KnobCatalog Catalog = KnobCatalog.Load();

    [Fact]
    public void RequiredRuntimeProtectionsRemainSupported()
    {
        foreach (string required in new[]
        {
            "analysis.ida-bomb",
            "analysis.hexrays-denial",
            "anti-debug.channel-sweep",
            "anti-debug.inline-hook-check",
            "anti-debug.veh-tamper",
            "anti-debug.dll-notify",
        })
        {
            Assert.True(ProtectionCapabilities.MaxReadyLevel(required) >= ProtectionLevel.Light,
                $"Required protection '{required}' is not supported at Light.");
        }
    }

    [Fact]
    public void PresetsOnlyEnableReadyEmitters()
    {
        var settings = ProtectionSettings.FromPreset(Presets.Maximum);

        foreach (var knob in Catalog.All)
        {
            if (!ProtectionCapabilities.IsReady(knob.Id))
                Assert.Equal(ProtectionLevel.Off, settings.LevelOf(knob));
        }
    }

    [Fact]
    public void ExplicitUnsupportedKnobIsRejected()
    {
        var settings = ProtectionSettings.FromPreset(Presets.Light);
        settings.Knobs["virtualization.extended-isa"] = ProtectionLevel.Light;

        var error = Assert.Throws<NotSupportedException>(() =>
            ProtectionCapabilities.Validate(settings, Catalog));

        Assert.Contains("not supported", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PresetLevelsAreClampedToEachReadyEmitter()
    {
        var settings = ProtectionSettings.FromPreset(Presets.Maximum);

        foreach (var knob in Catalog.All)
            Assert.True(settings.LevelOf(knob) <= ProtectionCapabilities.MaxReadyLevel(knob.Id));
    }

    [Fact]
    public void ExplicitLevelAboveEmitterCeilingIsRejected()
    {
        var settings = ProtectionSettings.FromPreset(Presets.Light);
        settings.Knobs["packaging.import-concealment"] = ProtectionLevel.Balanced;

        var error = Assert.Throws<NotSupportedException>(() =>
            ProtectionCapabilities.Validate(settings, Catalog));

        Assert.Contains("supported through Light", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void UnknownExplicitKnobIsRejected()
    {
        var settings = ProtectionSettings.FromPreset(Presets.Light);
        settings.Knobs["packaging.typo"] = ProtectionLevel.Light;

        Assert.Throws<KeyNotFoundException>(() =>
            ProtectionCapabilities.Validate(settings, Catalog));
    }

    [Fact]
    public void StartupProtectionsRequireEntryPointDispatcher()
    {
        var settings = ProtectionSettings.FromPreset(Presets.Light);
        settings.Knobs["packaging.ep-confusion"] = ProtectionLevel.Off;

        var error = Assert.Throws<ArgumentException>(() =>
            ProtectionCapabilities.Validate(settings, Catalog));

        Assert.Contains("startup routine", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void StringSubfeaturesRequireEncryption()
    {
        var settings = ProtectionSettings.FromPreset(Presets.Light);
        settings.Knobs["strings.encryption"] = ProtectionLevel.Off;

        var error = Assert.Throws<ArgumentException>(() =>
            ProtectionCapabilities.Validate(settings, Catalog));

        Assert.Contains("strings.encryption", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void OnlySelectionEnablesRuntimeDependencies()
    {
        var settings = ProtectionSettings.FromPreset(Presets.Balanced);

        ProtectionSelection.ApplyOnly(settings, Catalog, ["strings.coverage"]);
        ProtectionCapabilities.Validate(settings, Catalog);

        Assert.Equal(ProtectionLevel.Balanced, settings.LevelOf(Catalog.Get("strings.coverage")));
        Assert.Equal(ProtectionLevel.Balanced, settings.LevelOf(Catalog.Get("strings.encryption")));
        Assert.Equal(ProtectionLevel.Light, settings.LevelOf(Catalog.Get("packaging.ep-confusion")));
        Assert.Equal(ProtectionLevel.Off, settings.LevelOf(Catalog.Get("packaging.symbol-scrub")));
    }

    [Fact]
    public void GroupLevelClampsEachEmitterIndependently()
    {
        var settings = ProtectionSettings.FromPreset(Presets.Light);

        ProtectionSelection.ApplyGroupLevel(
            settings,
            Catalog,
            KnobGroups.CodeTransformation,
            ProtectionLevel.Maximum);

        Assert.Equal(ProtectionLevel.Maximum,
            settings.LevelOf(Catalog.Get("code-transformation.junk-insertion")));
        Assert.Equal(ProtectionLevel.Balanced,
            settings.LevelOf(Catalog.Get("code-transformation.mba-constants")));
        Assert.Equal(ProtectionLevel.Light,
            settings.LevelOf(Catalog.Get("code-transformation.per-build-mutation")));
    }

    [Fact]
    public void DisablingRequiredKnobProducesDependencyError()
    {
        var settings = ProtectionSettings.FromPreset(Presets.Light);
        ProtectionSelection.Disable(settings, Catalog, ["packaging.ep-confusion"]);

        var error = Assert.Throws<ArgumentException>(() =>
            ProtectionCapabilities.Validate(settings, Catalog));

        Assert.Contains("startup routine", error.Message, StringComparison.Ordinal);
    }
}
