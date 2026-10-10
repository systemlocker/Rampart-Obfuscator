using Rampart.Config;
using Rampart.NativeAot;

namespace Rampart.Targets;

public sealed class NativeAotProtectionBackend : IProtectionBackend
{
    public string Name => "nativeaot";
    public ProtectionTargetKind Kind => ProtectionTargetKind.NativeAot;
    public TargetClassification Inspect(byte[] input) => TargetClassifier.Classify(input);

    public ProtectionPlan Plan(byte[] input, ProtectionSettings settings)
    {
        var classification = Inspect(input);
        ProtectionPipeline.RequireTarget(classification, settings, Kind);
        if (settings.Targets?.Managed is not null)
            throw new NotSupportedException("RP_TARGET_OPTIONS_MISMATCH: Managed IL options must be applied before NativeAOT compilation.");
        var report = new NativeAotBackend().Audit(input, settings, settings.Targets?.NativeAot);
        var rejected = report.Passes.FirstOrDefault(p => p.Status == NativeAotEvidenceStatus.Rejected);
        if (rejected is not null)
            throw new NotSupportedException(rejected.ReasonCode + ": " + rejected.Detail);
        return new(classification, Name,
            report.Passes.Select(p => new PlannedProtection(p.Knob, p.Requested.ToString(), p.Effective.ToString(), p.ReasonCode)).ToArray(),
            report.Passes.Where(p => p.Status is NativeAotEvidenceStatus.Skipped or NativeAotEvidenceStatus.Downgraded)
                .Select(p => p.Knob + ": " + p.ReasonCode).ToArray());
    }

    public BackendProtectionResult Protect(byte[] input, ProtectionSettings settings, byte[]? symbols = null)
    {
        var plan = Plan(input, settings);
        var result = new NativeAotBackend().Protect(input, settings, settings.Targets?.NativeAot);
        var subject = new ProtectionSubject("image");
        return new()
        {
            Output = result.Output,
            Symbols = symbols,
            Plan = plan,
            Evidence = result.Report.Passes.Where(p => p.Requested != ProtectionLevel.Off).Select(p =>
                new ProtectionEvidence(p.Knob, subject, subject, p.Requested.ToString(),
                    p.Status == NativeAotEvidenceStatus.Applied ? EvidenceDisposition.Applied : EvidenceDisposition.Skipped,
                    p.ReasonCode, input.Length, result.Output.Length)).ToArray(),
            PrivateMap = result.Report,
            InputSha256 = result.Report.InputSha256,
            OutputSha256 = result.Report.OutputSha256,
            InputSize = input.Length,
            Seed = settings.Seed,
            Details = result.Report,
        };
    }

    public void Validate(byte[] original, BackendProtectionResult result)
    {
        new NativeAotBackend().Validate(original, result.Output);
        var classification = Inspect(result.Output);
        bool marked = NativeAotMarker.TryInspect(result.Output, out bool markerValid) && markerValid;
        if (!marked && (classification.Target.Kind != Kind || !classification.CanProtect))
            throw new BadImageFormatException("RP_NATIVEAOT_OUTPUT: Output no longer satisfies the NativeAOT structure contract.");
        if (result.Details is not NativeAotReport report || report.Invariants.Any(i => !i.Preserved))
            throw new BadImageFormatException("RP_NATIVEAOT_INVARIANT: A runtime-owned image range changed.");
    }

    public IReadOnlyList<ProtectionEvidence> DescribeEvidence(BackendProtectionResult result) => result.Evidence;
}
