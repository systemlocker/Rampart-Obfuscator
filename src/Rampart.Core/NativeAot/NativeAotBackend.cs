using System.Buffers.Binary;
using Rampart.Config;
using Rampart.Engine;
using Rampart.Engine.Passes;
using Rampart.Pe;
using Rampart.Targets;

namespace Rampart.NativeAot;

/// <summary>Post-publish image-only protection with a separate NativeAOT plan and
/// byte-ownership boundary. Runtime extension is limited to the explicit startup
/// integrity adaptation; original NativeAOT code and runtime data stay immutable
/// except for conservatively extended loader metadata.</summary>
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
        if (output.Length != original.Length)
        {
            ValidateRuntimeExtension(original, output);
            return;
        }
        var allowed = new List<(int Offset, int Length)>
        {
            (2, 58), (64, snapshot.PeOffset - 64), (snapshot.PeOffset + 8, 4),
            (snapshot.OptionalOffset + 2, 2), (snapshot.OptionalOffset + 64, 4)
        };
        for (int section = 0; section < snapshot.SectionCount; section++)
            allowed.Add((snapshot.SectionTableOffset + section * 40, 8));
        snapshot.Validate(output, allowed);
        uint storedChecksum = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(snapshot.OptionalOffset + 64));
        if (storedChecksum != PeChecksum.Compute(output))
            throw new NativeAotCompatibilityException("NAOT_INVARIANT_FAILED", "The transformed image PE checksum is invalid.");
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
        int[] runtimeIndexes = plan.Select((pass, index) => (pass, index))
            .Where(item => item.pass.Effective != ProtectionLevel.Off
                && item.pass.Knob is "integrity.measurement-channels" or "response.tool-response")
            .Select(item => item.index).ToArray();
        for (int index = 0; index < plan.Count; index++)
        {
            var pass = plan[index];
            if (pass.Effective == ProtectionLevel.Off) continue;
            if (pass.Knob is "integrity.measurement-channels" or "response.tool-response")
                continue; // Both settings share one isolated runtime-extension transaction below.
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
        if (runtimeIndexes.Length != 0)
        {
            bool measurement = runtimeIndexes.Any(index => plan[index].Knob == "integrity.measurement-channels");
            bool response = runtimeIndexes.Any(index => plan[index].Knob == "response.tool-response");
            byte[] candidate = ApplyRuntimeIntegrity(current, settings.Seed, measurement, response);
            ValidateRuntimeExtension(current, candidate);
            int changed = CountChanged(current, candidate);
            invariants.Add(new("nativeaot-runtime-integrity", true,
                NativeAotInvariantSnapshot.Hash(current), NativeAotInvariantSnapshot.Hash(candidate)));
            current = candidate;
            foreach (int index in runtimeIndexes)
                plan[index] = plan[index] with { Status = NativeAotEvidenceStatus.Applied, ChangedBytes = changed };
        }
        // A no-op must remain byte-exact, including its original checksum. For a
        // changed image compute the final PE checksum without touching certificates.
        if (!input.AsSpan().SequenceEqual(current))
        {
            byte[] candidate = (byte[])current.Clone();
            NativeAotMarker.Write(candidate);
            if (runtimeIndexes.Length == 0)
                NativeAotInvariantSnapshot.Capture(current).Validate(candidate, [(NativeAotMarker.Offset, NativeAotMarker.Length)]);
            else
                ValidateRuntimeExtension(input, candidate);
            invariants.Add(new("transformation-marker", true, NativeAotInvariantSnapshot.Hash(current), NativeAotInvariantSnapshot.Hash(candidate)));
            current = candidate;
            candidate = (byte[])current.Clone();
            int optionalOffset = BinaryPrimitives.ReadInt32LittleEndian(candidate.AsSpan(0x3c)) + 24;
            BinaryPrimitives.WriteUInt32LittleEndian(candidate.AsSpan(optionalOffset + 64), PeChecksum.Compute(candidate));
            if (runtimeIndexes.Length == 0)
                NativeAotInvariantSnapshot.Capture(current).Validate(candidate, [(optionalOffset + 64, 4)]);
            else
                ValidateRuntimeExtension(input, candidate);
            invariants.Add(new("pe-checksum", true, NativeAotInvariantSnapshot.Hash(current), NativeAotInvariantSnapshot.Hash(candidate)));
            current = candidate;
        }
        return new(current, new(inputHash, NativeAotInvariantSnapshot.Hash(current), settings.Seed, input.Length, current.Length,
            false, !signed, snapshot.OwnedRanges, plan, invariants));
    }

    private static int CountChanged(byte[] left, byte[] right)
    {
        int count = Math.Abs(left.Length - right.Length);
        for (int index = 0; index < Math.Min(left.Length, right.Length); index++)
            if (left[index] != right[index]) count++;
        return count;
    }

    private static byte[] ApplyRuntimeIntegrity(byte[] input, long seed, bool measurement, bool response)
    {
        var catalog = KnobCatalog.Load();
        var isolated = new ProtectionSettings { Preset = Presets.Light, Seed = seed };
        foreach (KnobDef knob in catalog.All)
            isolated.Knobs[knob.Id] = ProtectionLevel.Off;
        isolated.Knobs["packaging.ep-confusion"] = ProtectionLevel.Light;
        if (measurement) isolated.Knobs["integrity.measurement-channels"] = ProtectionLevel.Light;
        if (response) isolated.Knobs["response.tool-response"] = ProtectionLevel.Light;
        ProtectionCapabilities.Validate(isolated, catalog);

        var context = new BuildContext(PeImage.Load(input), isolated, catalog);
        context.Analyze();
        var runtime = new RuntimeHardeningPass();
        runtime.RunBeforeEntryPoint(context);
        new EntryPointPass().Run(context);
        // EntryPointPass owns a one-shot dispatcher. Do not install the recurring
        // per-thread monitor: whole-image measurement is intentionally startup-only.
        RelocBuilder.Rebuild(context);
        return context.Pe.ToBytes();
    }

    private static void ValidateRuntimeExtension(byte[] original, byte[] output)
    {
        NativeAotInvariantSnapshot.ValidateTransformedImage(output);
        PeImage before = PeImage.Load(original);
        PeImage after = PeImage.Load(output);
        DataDirectory loadConfig = before.Directory(DataDir.LoadConfig);
        bool guardCf = PeCompatibility.Inspect(before).GuardCf;
        if (after.Sections.Count != before.Sections.Count + 2)
            throw new NativeAotCompatibilityException("NAOT_INVARIANT_FAILED", "Runtime integrity must add exactly two protector-owned sections.");

        foreach (PeImage.Section originalSection in before.Sections)
        {
            PeImage.Section? emitted = after.Sections.SingleOrDefault(section => section.VirtualAddress == originalSection.VirtualAddress);
            byte[] normalized = emitted?.Data.ToArray() ?? [];
            if (guardCf && emitted is not null && before.SectionFromRva(loadConfig.RelativeVirtualAddress)?.VirtualAddress == originalSection.VirtualAddress)
            {
                int loadConfigOffset = checked((int)(loadConfig.RelativeVirtualAddress - originalSection.VirtualAddress));
                originalSection.Data.AsSpan(loadConfigOffset + 0x80, 20).CopyTo(normalized.AsSpan(loadConfigOffset + 0x80));
            }
            if (emitted is null || emitted.VirtualSize != originalSection.VirtualSize
                || emitted.SizeOfRawData != originalSection.SizeOfRawData
                || emitted.Characteristics != originalSection.Characteristics
                || !normalized.AsSpan().SequenceEqual(originalSection.Data))
            {
                string reason = emitted is null ? "missing"
                    : emitted.VirtualSize != originalSection.VirtualSize ? "virtual-size"
                    : emitted.SizeOfRawData != originalSection.SizeOfRawData ? "raw-size"
                    : emitted.Characteristics != originalSection.Characteristics ? "characteristics"
                    : "content";
                throw new NativeAotCompatibilityException("NAOT_INVARIANT_FAILED",
                    $"Runtime integrity modified original NativeAOT section RVA {originalSection.VirtualAddress:X8} ({reason}).");
            }
        }
        if (guardCf)
            ValidateGuardCfExtension(before, after, loadConfig.RelativeVirtualAddress);
        RelocEntry[] emittedRelocations = Relocations.Enumerate(after).ToArray();
        if (Relocations.Enumerate(before).Any(entry => !emittedRelocations.Contains(entry)))
            throw new NativeAotCompatibilityException("NAOT_INVARIANT_FAILED", "Runtime integrity did not preserve an original relocation entry.");

        PeImage.Section[] added = after.Sections
            .Where(section => before.Sections.All(originalSection => originalSection.VirtualAddress != section.VirtualAddress))
            .ToArray();
        PeImage.Section? code = added.SingleOrDefault(section => section.Name == ".rmpt");
        PeImage.Section? data = added.SingleOrDefault(section => section.Name == ".rmpd");
        if (code is null || data is null || !code.IsExecutable
            || code.Characteristics.HasFlag(SectionCharacteristics.MemWrite)
            || !data.Characteristics.HasFlag(SectionCharacteristics.MemWrite) || data.IsExecutable
            || after.EntryPointRva == before.EntryPointRva || after.SectionFromRva(after.EntryPointRva) != code)
        {
            throw new NativeAotCompatibilityException("NAOT_INVARIANT_FAILED", "Runtime integrity emitted an invalid section or entry-point layout.");
        }

        int overlayOffset = checked((int)Math.Max((ulong)before.SizeOfHeaders,
            before.Sections.Max(section => (ulong)section.PointerToRawData + section.SizeOfRawData)));
        ReadOnlySpan<byte> overlay = original.AsSpan(overlayOffset);
        if (overlay.Length > output.Length || !output.AsSpan(output.Length - overlay.Length).SequenceEqual(overlay))
            throw new NativeAotCompatibilityException("NAOT_INVARIANT_FAILED", "Runtime integrity did not preserve the original overlay.");
    }

    private static void ValidateGuardCfExtension(PeImage before, PeImage after, uint loadConfigRva)
    {
        ulong oldTableVa = BinaryPrimitives.ReadUInt64LittleEndian(before.ReadRva(loadConfigRva + 0x80, 8));
        ulong oldCount = BinaryPrimitives.ReadUInt64LittleEndian(before.ReadRva(loadConfigRva + 0x88, 8));
        uint oldFlags = BinaryPrimitives.ReadUInt32LittleEndian(before.ReadRva(loadConfigRva + 0x90, 4));
        ulong newTableVa = BinaryPrimitives.ReadUInt64LittleEndian(after.ReadRva(loadConfigRva + 0x80, 8));
        ulong newCount = BinaryPrimitives.ReadUInt64LittleEndian(after.ReadRva(loadConfigRva + 0x88, 8));
        uint newFlags = BinaryPrimitives.ReadUInt32LittleEndian(after.ReadRva(loadConfigRva + 0x90, 4));
        int stride = checked(4 + (int)((oldFlags & 0xF0000000u) >> 28));
        if (newCount != oldCount + 1 || (newFlags & oldFlags) != oldFlags || newTableVa == 0)
            throw new NativeAotCompatibilityException("NAOT_INVARIANT_FAILED", "Runtime integrity did not extend Guard CF metadata conservatively.");
        byte[] oldTable = oldCount == 0 ? [] : before.ReadRva(before.VaToRva(oldTableVa), checked((int)oldCount * stride));
        byte[] newTable = after.ReadRva(after.VaToRva(newTableVa), checked((int)newCount * stride));
        for (int index = 0; index < oldTable.Length; index += stride)
        {
            ReadOnlySpan<byte> entry = oldTable.AsSpan(index, stride);
            bool found = false;
            for (int candidate = 0; candidate < newTable.Length; candidate += stride)
                if (newTable.AsSpan(candidate, stride).SequenceEqual(entry)) { found = true; break; }
            if (!found)
                throw new NativeAotCompatibilityException("NAOT_INVARIANT_FAILED", "Runtime integrity dropped an original Guard CF target.");
        }
    }
}
