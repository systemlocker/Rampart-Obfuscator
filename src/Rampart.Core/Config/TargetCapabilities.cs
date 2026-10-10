using Rampart.Targets;

namespace Rampart.Config;

/// <summary>Planning ceilings for a particular backend. Image admission and
/// method eligibility are independently required before a protection is applied.</summary>
public static class TargetCapabilities
{
    public static ProtectionLevel MaximumLevel(string id, ProtectionTargetKind target) => target switch
    {
        ProtectionTargetKind.NativePe => ProtectionCapabilities.MaxReadyLevel(id),
        ProtectionTargetKind.NativeAot when id is "packaging.header-disguise" or "packaging.symbol-scrub" => ProtectionLevel.Light,
        ProtectionTargetKind.ManagedIl when id is "strings.encryption" or "code-transformation.mba-constants"
            or "code-transformation.flattening" or "packaging.symbol-scrub"
            or "virtualization.per-build-isa" or "virtualization.coverage" => ProtectionLevel.Light,
        _ => ProtectionLevel.Off,
    };

    public static void ApplyOnly(ProtectionSettings settings, KnobCatalog catalog, IEnumerable<string> ids, ProtectionTargetKind target)
    {
        if (target == ProtectionTargetKind.NativePe) { ProtectionSelection.ApplyOnly(settings, catalog, ids); return; }
        foreach (var knob in catalog.All) settings.Knobs[knob.Id] = ProtectionLevel.Off;
        foreach (string id in ids.Distinct(StringComparer.Ordinal))
        {
            _ = catalog.Get(id);
            var level = MaximumLevel(id, target);
            if (level == ProtectionLevel.Off)
                throw new NotSupportedException($"RP_TARGET_KNOB_UNSUPPORTED: '{id}' does not apply to this target.");
            settings.Knobs[id] = level;
        }
    }

    public static void ApplyGroup(ProtectionSettings settings, KnobCatalog catalog, string group, ProtectionLevel level, ProtectionTargetKind target)
    {
        if (target == ProtectionTargetKind.NativePe) { ProtectionSelection.ApplyGroupLevel(settings, catalog, group, level); return; }
        if (!KnobGroups.All.Contains(group, StringComparer.Ordinal)) throw new ArgumentException("RP_GROUP: Unknown protection group.");
        var knobs = catalog.InGroup(group).Where(k => MaximumLevel(k.Id, target) != ProtectionLevel.Off).ToArray();
        if (knobs.Length == 0) throw new NotSupportedException("RP_TARGET_GROUP_UNSUPPORTED: This group has no protections for the selected target.");
        foreach (var knob in knobs) settings.Knobs[knob.Id] = (ProtectionLevel)Math.Min((int)level, (int)MaximumLevel(knob.Id, target));
    }

    public static void ValidateSettings(ProtectionSettings settings, KnobCatalog catalog, ProtectionTargetKind target)
    {
        settings.Targets?.Validate();
        if (target == ProtectionTargetKind.NativePe) { ProtectionCapabilities.Validate(settings, catalog); return; }
        _ = Presets.DefaultLevel(settings.Preset, catalog.All[0]);
        foreach (var knob in settings.Knobs)
        {
            _ = catalog.Get(knob.Key);
            if (!Enum.IsDefined(knob.Value)) throw new ArgumentException("RP_KNOB_LEVEL: Invalid protection level.");
            if (knob.Value > MaximumLevel(knob.Key, target))
                throw new NotSupportedException($"RP_TARGET_KNOB_UNSUPPORTED: '{knob.Key}' is unavailable at {knob.Value} for this target.");
        }
        foreach (var rule in settings.Rules)
        {
            if (!Enum.IsDefined(rule.Scope) || string.IsNullOrWhiteSpace(rule.Match))
                throw new ArgumentException("RP_RULE_SELECTOR: Invalid rule scope or pattern.");
            if (rule.Preset is not null && !rule.Preset.Equals("off", StringComparison.OrdinalIgnoreCase)
                && !Presets.All.Contains(rule.Preset, StringComparer.OrdinalIgnoreCase))
                throw new ArgumentException("RP_RULE_PRESET: Unknown rule preset.");
            foreach (var knob in rule.Knobs)
            {
                _ = catalog.Get(knob.Key);
                if (!Enum.IsDefined(knob.Value) || knob.Value > MaximumLevel(knob.Key, target))
                    throw new NotSupportedException("RP_TARGET_RULE_UNSUPPORTED: A per-method protection is unavailable at its requested level.");
            }
        }
    }
}
