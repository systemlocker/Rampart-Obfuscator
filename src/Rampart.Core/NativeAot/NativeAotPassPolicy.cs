using Rampart.Config;

namespace Rampart.NativeAot;

/// <summary>Closed NativeAOT allowlist. New native knobs receive no permission implicitly.</summary>
public static class NativeAotPassPolicy
{
    public static NativeAotPassDisposition Disposition(string knob) => knob switch
    {
        "packaging.header-disguise" => NativeAotPassDisposition.Adapt,
        "packaging.symbol-scrub" => NativeAotPassDisposition.Adapt,
        "packaging.import-concealment" or "packaging.ep-confusion" or "packaging.packer"
            or "strings.encryption" or "strings.anti-instrumentation" or "strings.coverage"
            or "code-transformation.junk-insertion" or "code-transformation.mba-constants"
            or "code-transformation.per-build-mutation" or "code-transformation.flattening"
            or "virtualization.per-build-isa" or "virtualization.coverage"
            or "virtualization.extended-isa" or "virtualization.handler-polymorphism"
            or "virtualization.vm-nesting" or "virtualization.runtime-rekey"
            or "integrity.tls-veh-ownership" or "nuclear.nanomites" or "nuclear.exception-flow"
            => NativeAotPassDisposition.RequiresRuntimeMetadataProof,
        _ => NativeAotPassDisposition.Blocked,
    };

    public static IReadOnlyList<NativeAotPassEvidence> Plan(ProtectionSettings settings, bool strict = false)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var catalog = KnobCatalog.Load();
        var result = new List<NativeAotPassEvidence>();
        foreach (var unknown in settings.Knobs.Keys.Where(id => !catalog.TryGet(id, out _)).Order(StringComparer.Ordinal))
            result.Add(new(unknown, settings.Knobs[unknown], ProtectionLevel.Off, NativeAotPassDisposition.Blocked,
                NativeAotEvidenceStatus.Rejected, "NAOT_UNKNOWN_KNOB", "The protection identifier is not recognized."));
        foreach (KnobDef knob in catalog.All)
        {
            ProtectionLevel requested = settings.LevelOf(knob);
            var disposition = Disposition(knob.Id);
            if (!Enum.IsDefined(requested))
            {
                result.Add(new(knob.Id, requested, ProtectionLevel.Off, disposition,
                    NativeAotEvidenceStatus.Rejected, "NAOT_INVALID_LEVEL", "The protection level is invalid."));
                continue;
            }
            if (requested == ProtectionLevel.Off)
            {
                result.Add(new(knob.Id, requested, requested, disposition, NativeAotEvidenceStatus.Disabled,
                    "NAOT_DISABLED", "Disabled by configuration."));
                continue;
            }
            bool explicitRequest = settings.Knobs.ContainsKey(knob.Id);
            if (disposition != NativeAotPassDisposition.Adapt)
            {
                result.Add(new(knob.Id, requested, ProtectionLevel.Off, disposition,
                    explicitRequest || strict ? NativeAotEvidenceStatus.Rejected : NativeAotEvidenceStatus.Skipped,
                    disposition == NativeAotPassDisposition.RequiresRuntimeMetadataProof ? "NAOT_RUNTIME_OWNERSHIP_REQUIRED" : "NAOT_KNOB_UNSUPPORTED",
                    "The NativeAOT backend preserves runtime code, initialization, and runtime-owned data."));
                continue;
            }
            // The native Light header pass changes precisely six identity bytes. Symbol
            // hygiene is deliberately narrower than the native pass at every level.
            bool downgrade = requested > ProtectionLevel.Light;
            result.Add(new(knob.Id, requested, downgrade && (explicitRequest || strict) ? ProtectionLevel.Off : ProtectionLevel.Light,
                disposition, downgrade && (explicitRequest || strict) ? NativeAotEvidenceStatus.Rejected
                    : downgrade ? NativeAotEvidenceStatus.Downgraded : NativeAotEvidenceStatus.Planned,
                downgrade ? "NAOT_LEVEL_UNSUPPORTED" : "NAOT_IMAGE_ONLY",
                knob.Id == "packaging.header-disguise"
                    ? "Only COFF timestamp and linker version are eligible; export and debug timestamps are preserved."
                    : "Only DOS-stub content and section names are eligible; debug records, PDB paths, and COFF tables are preserved."));
        }
        if (settings.Rules.Count != 0 || settings.IncludeSymbols.Count != 0 || settings.ExcludeSymbols.Count != 0 || settings.IncludeRvaRanges.Count != 0)
            result.Add(new("selection", ProtectionLevel.Light, ProtectionLevel.Off, NativeAotPassDisposition.Blocked,
                NativeAotEvidenceStatus.Rejected, "NAOT_FUNCTION_SELECTION_UNSUPPORTED", "NativeAOT image operations do not accept function selection rules."));
        if (settings.Watermark is not null || settings.CustomMessage is not null)
            result.Add(new("response", ProtectionLevel.Light, ProtectionLevel.Off, NativeAotPassDisposition.Blocked,
                NativeAotEvidenceStatus.Rejected, "NAOT_RESPONSE_UNSUPPORTED", "NativeAOT image operations do not inject runtime messages or watermarks."));
        if (settings.SymbolSources.Count != 0 || settings.PdbTool is not null || settings.ThreatFocus.Count != 0)
            result.Add(new("native-options", ProtectionLevel.Light, ProtectionLevel.Off, NativeAotPassDisposition.Blocked,
                NativeAotEvidenceStatus.Rejected, "NAOT_NATIVE_OPTIONS_UNSUPPORTED", "Native function symbol inputs and threat dials do not apply to NativeAOT image operations."));
        return result;
    }
}
