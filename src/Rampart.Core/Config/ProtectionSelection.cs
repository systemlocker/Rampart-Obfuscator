namespace Rampart.Config;

/// <summary>
/// Applies ergonomic, bulk protection selections while preserving the same
/// capability ceilings and dependency validation used by explicit settings.
/// </summary>
public static class ProtectionSelection
{
    private static readonly Dictionary<string, string[]> Dependencies = new(StringComparer.Ordinal)
    {
        ["packaging.import-concealment"] = ["packaging.ep-confusion"],
        ["strings.encryption"] = ["packaging.ep-confusion"],
        ["strings.anti-instrumentation"] = ["strings.encryption"],
        ["strings.coverage"] = ["strings.encryption"],
    };

    /// <summary>
    /// Turns every catalog knob off, then enables only the named ready knobs and
    /// their runtime dependencies. Preset defaults choose each enabled level.
    /// </summary>
    public static void ApplyOnly(
        ProtectionSettings settings,
        KnobCatalog catalog,
        IEnumerable<string> knobIds)
    {
        string[] requested = knobIds.Distinct(StringComparer.Ordinal).ToArray();
        if (requested.Length == 0)
            throw new ArgumentException("At least one knob id is required for an only-selection.");

        // Planned knobs already resolve to Off through the capability ceiling;
        // avoid bloating payload previews with redundant roadmap entries.
        foreach (var knob in catalog.All.Where(knob => ProtectionCapabilities.IsReady(knob.Id)))
            settings.Knobs[knob.Id] = ProtectionLevel.Off;

        foreach (string id in requested)
            EnableWithDependencies(settings, catalog, id);
    }

    /// <summary>
    /// Sets every ready knob in a group to the requested level, clamped to each
    /// emitter's verified ceiling. Planned knobs remain off.
    /// </summary>
    public static void ApplyGroupLevel(
        ProtectionSettings settings,
        KnobCatalog catalog,
        string group,
        ProtectionLevel level)
    {
        if (!KnobGroups.All.Contains(group, StringComparer.Ordinal))
        {
            throw new ArgumentException(
                $"Unknown group '{group}'. Valid: {string.Join(", ", KnobGroups.All)}.");
        }

        var ready = catalog.InGroup(group)
            .Where(knob => ProtectionCapabilities.IsReady(knob.Id))
            .ToArray();
        if (ready.Length == 0)
            throw new NotSupportedException($"Group '{group}' does not contain any ready protections yet.");

        foreach (var knob in ready)
            settings.Knobs[knob.Id] = ProtectionCapabilities.ClampToReady(knob.Id, level);
    }

    public static void Disable(
        ProtectionSettings settings,
        KnobCatalog catalog,
        IEnumerable<string> knobIds)
    {
        foreach (string id in knobIds.Distinct(StringComparer.Ordinal))
        {
            _ = catalog.Get(id);
            settings.Knobs[id] = ProtectionLevel.Off;
        }
    }

    private static void EnableWithDependencies(
        ProtectionSettings settings,
        KnobCatalog catalog,
        string id)
    {
        var knob = catalog.Get(id);
        var ceiling = ProtectionCapabilities.MaxReadyLevel(id);
        if (ceiling == ProtectionLevel.Off)
        {
            throw new NotSupportedException(
                $"Protection knob '{id}' is planned but does not have a ready emitter yet.");
        }

        var selectedLevel = ProtectionCapabilities.ClampToReady(
            id,
            Presets.DefaultLevel(settings.Preset, knob));
        if (selectedLevel == ProtectionLevel.Off)
            selectedLevel = ProtectionLevel.Light;
        settings.Knobs[id] = selectedLevel;

        if (!Dependencies.TryGetValue(id, out string[]? dependencies))
            return;

        foreach (string dependency in dependencies)
            EnableWithDependencies(settings, catalog, dependency);
    }
}
