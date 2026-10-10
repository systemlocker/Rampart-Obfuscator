using System.Buffers.Binary;
using Rampart.Config;
using Rampart.Engine;
using Rampart.Engine.Passes;
using Rampart.Pe;
using Rampart.Targets;

namespace Rampart.NativeAot;

/// <summary>Post-publish image-only protection with a separate NativeAOT plan and
/// byte-ownership boundary. Native runtime transforms never enter this pipeline.</summary>
public sealed class NativeAotBackend
{
    /// <summary>Independently checks a finished result against its original image;
    /// callers need not trust serialized pass reports as validation evidence.</summary>
    public void Validate(byte[] original, byte[] output)
    {
        ArgumentNullException.ThrowIfNull(original);
        ArgumentNullException.ThrowIfNull(output);
        if (TargetClassifier.Classify(original).Target.Kind != ProtectionTargetKind.NativeAot)
            throw new NativeAotCompatibilityException("NAOT_TARGET_REQUIRED", "Validation requires the original NativeAOT image.");
        var snapshot = NativeAotInvariantSnapshot.Capture(original);
        if (original.AsSpan().SequenceEqual(output)) { snapshot.ValidateUnchanged(output); return; }
        if (!NativeAotMarker.TryInspect(output, out bool markerValid) || !markerValid)
            throw new NativeAotCompatibilityException("NAOT_INVARIANT_FAILED", "The transformed image has no valid completion marker.");
        var allowed = new List<(int Offset, int Length)>
        {
            (2, 58), (64, snapshot.PeOffset - 64), (snapshot.PeOffset + 8, 4),
            (snapshot.OptionalOffset + 2, 2), (snapshot.OptionalOffset + 64, 4)
        };
        for (int section = 0; section < snapshot.SectionCount; section++)
            allowed.Add((snapshot.SectionTableOffset + section * 40, 8));
        snapshot.Validate(output, allowed);
    }

    public NativeAotReport Audit(byte[] input, ProtectionSettings settings, NativeAotProtectionOptions? options = null) =>
        Execute(input, settings, options, audit: true).Report;

    public NativeAotResult Protect(byte[] input, ProtectionSettings settings, NativeAotProtectionOptions? options = null) =>
        Execute(input, settings, options, audit: options?.AuditOnly ?? settings.Targets?.NativeAot?.AuditOnly ?? false);

    private static NativeAotResult Execute(byte[] input, ProtectionSettings settings, NativeAotProtectionOptions? options, bool audit)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(settings);
        settings.Targets?.Validate();
        if (settings.Targets?.Override is { } target && target != ProtectionTargetKind.NativeAot)
            throw new NativeAotCompatibilityException("NAOT_TARGET_OVERRIDE_MISMATCH", "The target override does not match the NativeAOT backend.");
        if (settings.Targets?.Managed is not null)
            throw new NativeAotCompatibilityException("NAOT_TARGET_OPTIONS_MISMATCH", "Managed IL options must be applied before NativeAOT compilation.");
        options ??= settings.Targets?.NativeAot ?? new();
        var classification = TargetClassifier.Classify(input);
        if (classification.Target.Kind != ProtectionTargetKind.NativeAot || !classification.CanProtect)
            throw new NativeAotCompatibilityException("NAOT_TARGET_REQUIRED", "The input must be a structurally valid Windows x64 NativeAOT executable.");
        var snapshot = NativeAotInvariantSnapshot.Capture(input);
        var plan = NativeAotPassPolicy.Plan(settings, settings.Targets?.Compatibility == CompatibilityPolicy.Strict).ToList();
        PeImage original = PeImage.Load(input);
        bool signed = !original.Directory(DataDir.Security).IsEmpty;
        bool willChange = plan.Any(pass => pass.Effective != ProtectionLevel.Off);
        if (willChange && snapshot.PeOffset < NativeAotMarker.Offset + NativeAotMarker.Length)
            plan.Add(new("marker", ProtectionLevel.Light, ProtectionLevel.Off, NativeAotPassDisposition.Blocked,
                NativeAotEvidenceStatus.Rejected, "NAOT_MARKER_SPACE_REQUIRED", "The image has no DOS-stub space for a transformation marker."));
        if (signed && (willChange || options.PrepareForSigning))
            plan.Add(new("authenticode", ProtectionLevel.Light, ProtectionLevel.Off, NativeAotPassDisposition.Blocked,
                NativeAotEvidenceStatus.Rejected, "NAOT_SIGNING_ORDER", "Protect the unsigned publish output before Authenticode signing."));

        string inputHash = NativeAotInvariantSnapshot.Hash(input);
        if (audit)
            return new((byte[])input.Clone(), new(inputHash, inputHash, settings.Seed, input.Length, input.Length, true, !signed,
                snapshot.OwnedRanges, plan, []));
        var rejected = plan.FirstOrDefault(pass => pass.Status == NativeAotEvidenceStatus.Rejected);
        if (rejected is not null) throw new NativeAotCompatibilityException(rejected.ReasonCode, $"{rejected.Knob}: {rejected.Detail}");

        byte[] current = (byte[])input.Clone();
        var invariants = new List<NativeAotInvariantEvidence>();
        for (int index = 0; index < plan.Count; index++)
        {
            var pass = plan[index];
            if (pass.Effective == ProtectionLevel.Off) continue;
            // Each pass works on an isolated copy. Only after both the byte ownership
            // and PE structural checks pass does it become the next pipeline input.
            var before = NativeAotInvariantSnapshot.Capture(current);
            var ranges = new List<(int Offset, int Length)>();
            byte[] candidate = (byte[])current.Clone();
            if (pass.Knob == "packaging.header-disguise")
            {
                var isolated = new ProtectionSettings { Preset = Presets.Light, Seed = settings.Seed };
                isolated.Knobs[pass.Knob] = ProtectionLevel.Light;
                var context = new BuildContext(PeImage.Load(current), isolated, KnobCatalog.Load());
                new HeaderDisguisePass().Run(context);
                byte[] nativeCandidate = context.Pe.ToBytes();
                ranges.Add((before.PeOffset + 8, 4));
                ranges.Add((before.OptionalOffset + 2, 2));
                foreach (var range in ranges) nativeCandidate.AsSpan(range.Offset, range.Length).CopyTo(candidate.AsSpan(range.Offset));
            }
            else if (pass.Knob == "packaging.symbol-scrub")
            {
                var pe = PeImage.Load(current);
                pe.ScrubDosStubContent();
                foreach (var section in pe.Sections) section.Name = "";
                byte[] nativeCandidate = pe.ToBytes();
                if (before.PeOffset > 64)
                {
                    ranges.Add((2, 58));
                    ranges.Add((64, before.PeOffset - 64));
                }
                for (int section = 0; section < before.SectionCount; section++)
                    ranges.Add((before.SectionTableOffset + section * 40, 8));
                foreach (var range in ranges) nativeCandidate.AsSpan(range.Offset, range.Length).CopyTo(candidate.AsSpan(range.Offset));
            }
            else throw new NativeAotCompatibilityException("NAOT_KNOB_UNSUPPORTED", "The pass is outside the NativeAOT allowlist.");
            before.Validate(candidate, ranges);
            int changed = CountChanged(current, candidate);
            invariants.Add(new(pass.Knob, true, NativeAotInvariantSnapshot.Hash(current), NativeAotInvariantSnapshot.Hash(candidate)));
            current = candidate;
            plan[index] = pass with
            {
                Status = changed == 0 ? NativeAotEvidenceStatus.Skipped : NativeAotEvidenceStatus.Applied,
                ReasonCode = changed == 0 ? "NAOT_NO_ELIGIBLE_BYTES" : pass.ReasonCode,
                ChangedBytes = changed
            };
        }
        // A no-op must remain byte-exact, including its original checksum. For a
        // changed image compute the final PE checksum without touching certificates.
        if (!input.AsSpan().SequenceEqual(current))
        {
            var before = NativeAotInvariantSnapshot.Capture(current);
            byte[] candidate = (byte[])current.Clone();
            NativeAotMarker.Write(candidate);
            before.Validate(candidate, [(NativeAotMarker.Offset, NativeAotMarker.Length)]);
            invariants.Add(new("transformation-marker", true, NativeAotInvariantSnapshot.Hash(current), NativeAotInvariantSnapshot.Hash(candidate)));
            current = candidate;
            before = NativeAotInvariantSnapshot.Capture(current);
            candidate = (byte[])current.Clone();
            BinaryPrimitives.WriteUInt32LittleEndian(candidate.AsSpan(before.OptionalOffset + 64), PeChecksum.Compute(candidate));
            before.Validate(candidate, [(before.OptionalOffset + 64, 4)]);
            invariants.Add(new("pe-checksum", true, NativeAotInvariantSnapshot.Hash(current), NativeAotInvariantSnapshot.Hash(candidate)));
            current = candidate;
        }
        return new(current, new(inputHash, NativeAotInvariantSnapshot.Hash(current), settings.Seed, input.Length, current.Length,
            false, !signed, snapshot.OwnedRanges, plan, invariants));
    }

    private static int CountChanged(byte[] left, byte[] right)
    {
        int count = 0;
        for (int index = 0; index < left.Length; index++) if (left[index] != right[index]) count++;
        return count;
    }
}
