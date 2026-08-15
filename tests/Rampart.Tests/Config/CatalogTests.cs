using Rampart.Config;
using Xunit;

namespace Rampart.Tests.Config;

/// <summary>Structural invariants of the knob catalog: ids are unique and stable,
/// level arrays are well-formed, and every knob id referenced by literal in the
/// config sources actually resolves to a catalog entry.</summary>
public class CatalogTests
{
    private static readonly KnobCatalog Catalog = KnobCatalog.Load();

    // Knob ids referenced as string literals inside src/Rampart.Core/Config/ConcernRule.cs
    // and src/Rampart.Core/Config/Presets.cs (grepped from those files). Keep in sync when
    // a rule or preset clamp starts referencing another knob.
    //
    // Known-stale literals that exist in those files but intentionally have NO catalog
    // entry (ConcernRules.R guards with TryGet, so the rules stay inert):
    //   - "packaging.strip-relocs"  (no such knob; relocations are not stripped)
    //   - "strings.vm-route"        (no strings group in KnobGroups.All)
    //   - "integrity.cet-shadow-stack" — wrong group prefix; the actual knob is
    //     "anti-inject.cet-shadow-stack", asserted below.
    private static readonly string[] ReferencedIds =
    [
        // Referenced by Presets.cs (preset clamps)
        "nuclear.nanomites",
        "nuclear.exception-flow",
        "nuclear.memory-ambush",
        "nuclear.injection-hunter",
        "integrity.self-debug-port",
        "integrity.loader-hijack",

        // Referenced by ConcernRule.cs (concern rules RP01..RP10)
        "packaging.packer",
        "anti-inject.dynamic-code-policy",
        "virtualization.jit-handlers",
        "memory.page-mode-decrypt",
        "memory.sleep-mask",
        "anti-inject.cet-shadow-stack",
        "anti-sandbox.human-gate",
        "memory.at-rest-encryption",
        "analysis.ida-bomb",
        "virtualization.coverage",
        "response.tool-response",
    ];

    [Fact]
    public void AllIdsAreUnique()
    {
        var ids = Catalog.All.Select(k => k.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void PointsAndLevelTextsHaveFourEntries()
    {
        foreach (var knob in Catalog.All)
        {
            Assert.Equal(4, knob.Points.Length);
            Assert.Equal(4, knob.LevelTexts.Length);
            // Every level must be described and every point value sane (no negatives:
            // raising a level never subtracts budget).
            Assert.All(knob.LevelTexts, t => Assert.False(string.IsNullOrWhiteSpace(t)));
            Assert.All(knob.Points, p => Assert.True(p >= 0));
        }
    }

    [Fact]
    public void EveryReferencedKnobIdExistsInCatalog()
    {
        var missing = ReferencedIds.Where(id => !Catalog.TryGet(id, out _)).ToList();
        Assert.True(missing.Count == 0,
            $"Ids referenced by ConcernRule.cs/Presets.cs but absent from the catalog: {string.Join(", ", missing)}");
    }

    [Fact]
    public void EveryKnobGroupIsKnown()
    {
        foreach (var knob in Catalog.All)
            Assert.Contains(knob.Group, KnobGroups.All);
    }

    [Fact]
    public void EveryKnobTagIsKnown()
    {
        foreach (var knob in Catalog.All)
        {
            Assert.NotEmpty(knob.Tags);
            foreach (var tag in knob.Tags)
                Assert.Contains(tag, ThreatTags.All);
        }
    }
}
