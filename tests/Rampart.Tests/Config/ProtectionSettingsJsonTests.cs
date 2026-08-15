using Rampart.Config;
using Xunit;

namespace Rampart.Tests.Config;

public class ProtectionSettingsJsonTests
{
    [Fact]
    public void DeserializesPlainSettingsDocument()
    {
        var expected = ProtectionSettings.FromPreset(Presets.Heavy);
        expected.Seed = 12345;
        expected.Knobs["packaging.symbol-scrub"] = ProtectionLevel.Light;

        var actual = ProtectionSettingsJson.Deserialize(
            ProtectionSettingsJson.Serialize(expected));

        Assert.Equal(expected.Preset, actual.Preset);
        Assert.Equal(expected.Seed, actual.Seed);
        Assert.Equal(ProtectionLevel.Light, actual.Knobs["packaging.symbol-scrub"]);
    }

    [Fact]
    public void DeserializesSettingsFromDryRunPayloadWrapper()
    {
        const string json = """
            {
              "Input": "BirdRodeo.exe",
              "Output": "BirdRodeo.protected.exe",
              "Settings": {
                "Knobs": { "packaging.symbol-scrub": "Heavy" },
                "Preset": "balanced",
                "Seed": 88442211,
                "ThreatFocus": []
              },
              "BudgetPoints": 8,
              "Concerns": []
            }
            """;

        var actual = ProtectionSettingsJson.Deserialize(json);

        Assert.Equal(Presets.Balanced, actual.Preset);
        Assert.Equal(88442211, actual.Seed);
        Assert.Equal(ProtectionLevel.Heavy, actual.Knobs["packaging.symbol-scrub"]);
    }

    [Fact]
    public void CapabilityValidationRejectsUndefinedNumericLevel()
    {
        var settings = ProtectionSettings.FromPreset(Presets.Light);
        settings.Knobs["packaging.symbol-scrub"] = (ProtectionLevel)99;

        Assert.Throws<ArgumentException>(() =>
            ProtectionCapabilities.Validate(settings, KnobCatalog.Load()));
    }

    [Fact]
    public void RegionRulesAndSymbolInputsRoundTrip()
    {
        var settings = ProtectionSettings.FromPreset(Presets.Balanced);
        settings.SymbolSources.Add("BirdRodeo.map");
        settings.IncludeSymbols.Add("BirdRodeo::*");
        settings.ExcludeSymbols.Add("BirdRodeo::Render::*");
        settings.IncludeRvaRanges.Add(new RvaRange { Start = 0x1000, End = 0x2000 });
        settings.Rules.Add(new ProtectionRule
        {
            Match = "BirdRodeo::License::*",
            Scope = ProtectionRuleScope.Symbol,
            Preset = Presets.Maximum,
            Knobs = { ["strings.coverage"] = ProtectionLevel.Heavy },
        });

        ProtectionSettings actual = ProtectionSettingsJson.Deserialize(
            ProtectionSettingsJson.Serialize(settings));

        Assert.Equal("BirdRodeo.map", Assert.Single(actual.SymbolSources));
        Assert.Equal(0x1000u, Assert.Single(actual.IncludeRvaRanges).Start);
        ProtectionRule rule = Assert.Single(actual.Rules);
        Assert.Equal(ProtectionRuleScope.Symbol, rule.Scope);
        Assert.Equal(ProtectionLevel.Heavy, rule.Knobs["strings.coverage"]);
    }
}
