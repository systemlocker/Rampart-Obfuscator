using Rampart.Config;
using Rampart.Engine;
using Rampart.Pe;
using Rampart.Symbols;

namespace Rampart.Targets;

/// <summary>Adapts the established native pipeline without changing its pass order
/// or configuration resolution.</summary>
public sealed class NativePeBackend : IProtectionBackend
{
    public string Name => "native-pe";
    public ProtectionTargetKind Kind => ProtectionTargetKind.NativePe;
    public TargetClassification Inspect(byte[] input) => TargetClassifier.Classify(input);

    public ProtectionPlan Plan(byte[] input, ProtectionSettings settings)
    {
        var classification = Inspect(input);
        ProtectionPipeline.RequireTarget(classification, settings, Kind);
        if (settings.Targets?.Managed is not null || settings.Targets?.NativeAot is not null)
            throw new NotSupportedException("RP_TARGET_OPTIONS_MISMATCH: The target settings do not apply to a native PE executable.");
        var catalog = KnobCatalog.Load();
        ProtectionCapabilities.Validate(settings, catalog);
        var pe = PeImage.Load(input);
        PeCompatibility.Validate(pe);
        var effective = ProtectionSettingsJson.Deserialize(ProtectionSettingsJson.Serialize(settings));
        ThreatDials.Apply(effective, catalog);
        var records = SymbolLoader.Load(effective.SymbolSources, pe, effective.PdbTool);
        var functions = FunctionDescriptor.Attach(pe, ExceptionTable.Parse(pe), records);
        ProtectionCapabilities.ValidateEffectiveFunctionPolicies(effective, catalog, functions);
        return new(classification, Name, catalog.All.Select(k => new PlannedProtection(
            k.Id, effective.LevelOf(k).ToString(), effective.LevelOf(k).ToString(), "RP_NATIVE_POLICY")).ToArray(), []);
    }

    public BackendProtectionResult Protect(byte[] input, ProtectionSettings settings, byte[]? symbols = null)
    {
        ProtectionPlan plan = Plan(input, settings);
        var pe = PeImage.Load(input);
        var records = SymbolLoader.Load(settings.SymbolSources, pe, settings.PdbTool);
        var result = new Protector().Protect(input, settings, symbols: records);
        var evidence = new List<ProtectionEvidence>();
        var imageSubject = new ProtectionSubject("image");
        foreach (var planned in plan.Protections.Where(p => p.Effective != nameof(ProtectionLevel.Off)
            && !ProtectionCapabilities.FunctionScopedKnobs.Contains(p.Id)))
        {
            bool applied = result.Applied.TryGetValue(planned.Id, out var appliedLevel) && appliedLevel != ProtectionLevel.Off;
            evidence.Add(new(planned.Id, imageSubject, imageSubject,
                applied ? appliedLevel.ToString() : planned.Effective,
                applied ? EvidenceDisposition.Applied : EvidenceDisposition.Skipped,
                applied ? "RP_APPLIED" : "RP_NATIVE_NO_ELIGIBLE_SITES",
                input.Length, result.Output.Length));
        }
        foreach (var function in result.SymbolMap.Functions)
        {
            var original = new ProtectionSubject(function.Name, Module: function.Module, Rva: function.OriginalRva);
            var updated = original with { Rva = function.ProtectedRva };
            foreach (var requested in function.Requested.Where(k => k.Value != ProtectionLevel.Off))
            {
                bool applied = function.Applied.TryGetValue(requested.Key, out var level) && level != ProtectionLevel.Off;
                evidence.Add(new(requested.Key, original, updated, requested.Value.ToString(),
                    applied ? EvidenceDisposition.Applied : EvidenceDisposition.Skipped,
                    applied ? "RP_APPLIED" : "RP_NATIVE_INELIGIBLE_OR_OWNED",
                    checked((int)function.Size), checked((int)(function.ProtectedSize ?? function.Size))));
            }
        }
        return new BackendProtectionResult
        {
            Output = result.Output,
            Plan = plan,
            Evidence = evidence,
            PrivateMap = result.SymbolMap,
            InputSha256 = result.InputSha256,
            OutputSha256 = result.OutputSha256,
            Seed = result.Seed,
            InputSize = input.Length,
            Details = result,
        };
    }

    public void Validate(byte[] original, BackendProtectionResult result)
    {
        // Protected output intentionally has a Rampart section. Validate its
        // structure instead of applying the unprotected-input admission rule.
        _ = PeCompatibility.Inspect(PeImage.Load(result.Output));
    }

    public IReadOnlyList<ProtectionEvidence> DescribeEvidence(BackendProtectionResult result) => result.Evidence;
}
