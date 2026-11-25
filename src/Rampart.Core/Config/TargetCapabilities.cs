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
        if (target == ProtectionTargetKind.ManagedIl && settings.Targets?.Managed is { } managed)
        {
            // Clear prior managed transform flags while keeping non-transform
            // policy settings (Watermark, StrictCompatibility, PreserveDebugSymbols).
            managed.Strings = false;
            managed.Constants = false;
            managed.MetadataHygiene = false;
            managed.Integrity = false;
            managed.RenamePrivateMembers = false;
            managed.ControlFlow = false;
            managed.Virtualize = false;
            managed.HardenedRuntime = false;
            managed.RequireVirtualization = false;
            managed.RemoveWatermark = false;
        }
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
        if (!Enum.IsDefined(level)) throw new ArgumentOutOfRangeException(nameof(level), level, $"Invalid protection level {(int)level}.");
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
        if (!(target == ProtectionTargetKind.NativeAot && settings.Preset.Equals("off", StringComparison.OrdinalIgnoreCase)))
            _ = Presets.DefaultLevel(settings.Preset, catalog.All[0]);
        foreach (var tag in settings.ThreatFocus)
            if (!ThreatTags.All.Contains(tag, StringComparer.OrdinalIgnoreCase))
                throw new ArgumentException($"RP_CONFIG_VALUE: Unknown threat-focus tag '{tag}'.");
        foreach (var knob in settings.Knobs)
        {
            _ = catalog.Get(knob.Key);
            if (!Enum.IsDefined(knob.Value)) throw new ArgumentException("RP_KNOB_LEVEL: Invalid protection level.");
            if (knob.Value > MaximumLevel(knob.Key, target))
                throw new NotSupportedException($"RP_TARGET_KNOB_UNSUPPORTED: '{knob.Key}' is unavailable at {knob.Value} for this target.");
        }
        foreach (var rule in settings.Rules)
        {
            if (!Enum.IsDefined(rule.Scope))
                throw new ArgumentException("RP_RULE_SELECTOR: Invalid rule scope.");
            if (string.IsNullOrWhiteSpace(rule.Match) && rule.Scope != ProtectionRuleScope.Rva)
                throw new ArgumentException("RP_RULE_SELECTOR: Invalid rule scope or pattern.");
            if (rule.Scope == ProtectionRuleScope.Rva && (rule.StartRva is null || rule.EndRva is null || rule.EndRva <= rule.StartRva))
                throw new ArgumentException("RP_RULE_SELECTOR: RVA protection rules require StartRva < EndRva.");
            if (rule.Scope != ProtectionRuleScope.Rva && (rule.StartRva is not null || rule.EndRva is not null))
                throw new ArgumentException("RP_RULE_SELECTOR: StartRva and EndRva may only be set on RVA protection rules.");
            if (rule.Preset is not null && !rule.Preset.Equals("off", StringComparison.OrdinalIgnoreCase)
                && !Presets.All.Contains(rule.Preset, StringComparer.OrdinalIgnoreCase))
                throw new ArgumentException("RP_RULE_PRESET: Unknown rule preset.");
            foreach (var knob in rule.Knobs)
            {
                _ = catalog.Get(knob.Key);
                if (!Enum.IsDefined(knob.Value) || knob.Value > MaximumLevel(knob.Key, target))
                    throw new NotSupportedException("RP_TARGET_RULE_UNSUPPORTED: A per-method protection is unavailable at its requested level.");
                if (target == ProtectionTargetKind.ManagedIl && knob.Key == "packaging.symbol-scrub" && knob.Value != ProtectionLevel.Off)
                    throw new NotSupportedException("RP_TARGET_RULE_UNSUPPORTED: 'packaging.symbol-scrub' applies module-wide and cannot be configured per method.");
            }
        }
    }
}
