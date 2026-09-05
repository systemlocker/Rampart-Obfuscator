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
        ["packaging.packer"] = ["packaging.ep-confusion"],
        ["virtualization.per-build-isa"] = ["virtualization.coverage"],
        ["virtualization.coverage"] = ["virtualization.per-build-isa"],
        ["virtualization.extended-isa"] = ["virtualization.coverage"],
        ["virtualization.handler-polymorphism"] = ["virtualization.coverage"],
        ["virtualization.vm-nesting"] = ["virtualization.coverage"],
        ["virtualization.runtime-rekey"] = ["virtualization.coverage"],
        ["nuclear.nanomites"] = ["packaging.ep-confusion"],
        ["nuclear.exception-flow"] = ["packaging.ep-confusion"],
        ["strings.encryption"] = ["packaging.ep-confusion"],
        ["strings.anti-instrumentation"] = ["strings.encryption"],
        ["strings.coverage"] = ["strings.encryption"],
        ["anti-debug.channel-sweep"] = ["packaging.ep-confusion"],
        ["anti-debug.inline-hook-check"] = ["packaging.ep-confusion"],
        ["anti-debug.veh-tamper"] = ["packaging.ep-confusion"],
        ["anti-debug.dll-notify"] = ["packaging.ep-confusion"],
        ["anti-sandbox.virtualisation-detect"] = ["packaging.ep-confusion"],
        ["anti-sandbox.fingerprint-suite"] = ["packaging.ep-confusion"],
        ["anti-sandbox.human-gate"] = ["packaging.ep-confusion"],
        ["analysis.runtime-header-corruption"] = ["packaging.ep-confusion"],
        ["memory.anti-dump"] = ["packaging.ep-confusion"],
        ["integrity.header-scrub"] = ["packaging.ep-confusion"],
        ["anti-inject.dacl-hardening"] = ["packaging.ep-confusion"],
        ["anti-inject.dynamic-code-policy"] = ["packaging.ep-confusion"],
        ["anti-inject.iat-hash-check"] = ["packaging.ep-confusion"],
        ["integrity.kernel-wall"] = ["packaging.ep-confusion"],
        ["integrity.measurement-channels"] = ["packaging.ep-confusion"],
        ["integrity.tls-veh-ownership"] = ["packaging.ep-confusion"],
        ["integrity.hidden-threads"] = ["packaging.ep-confusion"],
        ["response.silent-taint"] = ["integrity.kernel-wall"],
        ["response.tool-response"] = ["anti-debug.channel-sweep"],
        ["response.custom-messages"] = ["integrity.kernel-wall"],
        ["nuclear.injection-hunter"] = ["packaging.ep-confusion"],
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

        // Unsupported compatibility identifiers already resolve to Off; omit
        // redundant entries from newly generated configuration payloads.
        foreach (var knob in catalog.All.Where(knob => ProtectionCapabilities.IsReady(knob.Id)))
            settings.Knobs[knob.Id] = ProtectionLevel.Off;

        var visited = new HashSet<string>(StringComparer.Ordinal);
        foreach (string id in requested)
            EnableWithDependencies(settings, catalog, id, visited);
    }

    /// <summary>
    /// Sets every ready knob in a group to the requested level, clamped to each
    /// emitter's verified ceiling. Unsupported options remain off.
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
        string id,
        HashSet<string> visited)
    {
        // Some capabilities form a required pair (the VM and its coverage
        // selector). Visit each once so either name can enable the whole pair.
        if (!visited.Add(id))
            return;
        var knob = catalog.Get(id);
        var ceiling = ProtectionCapabilities.MaxReadyLevel(id);
        if (ceiling == ProtectionLevel.Off)
        {
            throw new NotSupportedException(
                $"Protection knob '{id}' is not supported. Run `rampart knobs` to see supported protections.");
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
            EnableWithDependencies(settings, catalog, dependency, visited);
    }
}
