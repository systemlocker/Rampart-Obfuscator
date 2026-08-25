using Rampart.Config;
using Rampart.Engine;
using Xunit;

namespace Rampart.Tests.Engine;

public class FunctionPolicyTests
{
    private static readonly KnobCatalog Catalog = KnobCatalog.Load();
    private static readonly FunctionDescriptor LicenseFunction = new(
        0x1000,
        0x1100,
        0x3000,
        "ExampleApp::License::Validate",
        "ExampleApp::License",
        "license.obj",
        ".text",
        "src/license.cpp");

    [Fact]
    public void IncludeExcludeAndProfilesResolveRealEmitterCeilings()
    {
        var settings = ProtectionSettings.FromPreset(Presets.Light);
        settings.IncludeSymbols.Add("ExampleApp::*");
        settings.ExcludeSymbols.Add("*::Render::*");
        settings.Rules.Add(new ProtectionRule
        {
            Match = "ExampleApp::License::*",
            Preset = Presets.Maximum,
        });
        var policy = new FunctionPolicy(settings, Catalog);

        Assert.True(policy.IsSelected(LicenseFunction));
        Assert.Equal(ProtectionLevel.Maximum,
            policy.Level("code-transformation.junk-insertion", LicenseFunction));
        Assert.Equal(ProtectionLevel.Balanced,
            policy.Level("strings.encryption", LicenseFunction));
        Assert.Equal(ProtectionLevel.Light,
            policy.Level("packaging.import-concealment", LicenseFunction));
    }

    [Fact]
    public void OffRuleCanExcludeAModuleWithoutChangingGlobalPreset()
    {
        var settings = ProtectionSettings.FromPreset(Presets.Balanced);
        settings.Rules.Add(new ProtectionRule
        {
            Scope = ProtectionRuleScope.Module,
            Match = "ffmpeg*",
            Preset = "off",
        });
        var function = LicenseFunction with { Module = "ffmpeg_codec.obj" };

        var policy = new FunctionPolicy(settings, Catalog);

        Assert.Equal(ProtectionLevel.Off, policy.Level("strings.encryption", function));
        Assert.Equal(ProtectionLevel.Off, policy.Level("code-transformation.junk-insertion", function));
    }

    [Fact]
    public void RvaRangesSelectOverlappingFunctions()
    {
        var settings = ProtectionSettings.FromPreset(Presets.Light);
        settings.IncludeRvaRanges.Add(new RvaRange { Start = 0x1080, End = 0x1200 });
        var policy = new FunctionPolicy(settings, Catalog);

        Assert.True(policy.IsSelected(LicenseFunction));
        Assert.False(policy.IsSelected(LicenseFunction with { BeginRva = 0x2000, EndRva = 0x2100 }));
    }

    [Fact]
    public void SourceGlobsArePathSeparatorIndependent()
    {
        var settings = ProtectionSettings.FromPreset(Presets.Balanced);
        settings.Rules.Add(new ProtectionRule
        {
            Scope = ProtectionRuleScope.Source,
            Match = "*/third_party/*",
            Preset = "off",
        });
        var policy = new FunctionPolicy(settings, Catalog);

        Assert.Equal(ProtectionLevel.Off, policy.Level(
            "strings.encryption",
            LicenseFunction with { Source = "C:\\src\\third_party\\codec.cpp" }));
    }
}
