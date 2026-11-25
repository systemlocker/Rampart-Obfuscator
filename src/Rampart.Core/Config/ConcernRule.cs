namespace Rampart.Config;

public enum ConcernSeverity
{
    Info,
    Warning,
    Risky,
}

/// <summary>A pre-build finding about a configuration: a risky combination, an
/// overlapping defence, or an EDR-notable option. Surfaced by `rampart check`
/// and before every build unless suppressed.</summary>
public sealed record Concern(
    ConcernSeverity Severity,
    string Code,
    string Message,
    string? Suggestion = null);

/// <summary>Evaluates a configuration for concerns before any bytes are touched —
/// the local equivalent of the dashboard's "concerns + overlap detection" pane.</summary>
public static class ConcernRules
{
    /// <summary>Rules are expressed over resolved knob levels. Each entry receives
    /// the full settings and catalog so it can express cross-group interactions.</summary>
    private static readonly List<Func<ProtectionSettings, KnobCatalog, IEnumerable<Concern>>> Rules =
    [
        (s, c) => R(s, c, "packaging.symbol-scrub", "nuclear.nanomites", ProtectionLevel.Light,
            ConcernSeverity.Risky, "RP01",
            "Nanomites rely on first-chance exception dispatch at protected sites; combining them with " +
            "symbol scrubbing makes crash triage and exception diagnostics significantly harder without " +
            "the private symbol map.",
            "Retain the private .rmap.json sidecar for crash triage, or disable nanomites on paths that require standard crash dumps."),

        (s, c) => R(s, c, "anti-inject.cet-shadow-stack", ProtectionLevel.Light,
            ConcernSeverity.Info, "RP04",
            "CET shadow stack enforcement requires Windows 10 2004+ with hardware CET for full " +
            "effect; older systems silently run without hardware shadow stacks."),

        (s, c) => R(s, c, "anti-sandbox.human-gate", ProtectionLevel.Light,
            ConcernSeverity.Warning, "RP06",
            "The human-activity gate flags executions when no recent keyboard or mouse input is observed. " +
            "Services, headless workers, and scheduled tasks see no interactive input by design.",
            "Exclude unattended service binaries from anti-sandbox.human-gate."),

        (s, c) => R(s, c, "response.tool-response", ProtectionLevel.Light,
            ConcernSeverity.Warning, "RP10",
            "Tool response turns shared detection state into an application response. At Light the " +
            "response is a clean process exit, so a false positive can end a legitimate session.",
            "Exercise detection-only settings in QA before enabling the response in a release profile."),
    ];

    public static List<Concern> Evaluate(ProtectionSettings settings, KnobCatalog catalog)
    {
        var found = new List<Concern>();
        foreach (var rule in Rules)
            found.AddRange(rule(settings, catalog));
        return found;
    }

    private static IEnumerable<Concern> R(
        ProtectionSettings s, KnobCatalog c, string idA, ProtectionLevel minA,
        ConcernSeverity sev, string code, string msg, string? suggestion = null)
    {
        if (c.TryGet(idA, out var knobA) && s.LevelOf(knobA) >= minA)
            yield return new Concern(sev, code, msg, suggestion);
    }

    private static IEnumerable<Concern> R(
        ProtectionSettings s, KnobCatalog c, string idA, string idB, ProtectionLevel minB,
        ConcernSeverity sev, string code, string msg, string? suggestion = null)
    {
        if (!c.TryGet(idA, out var knobA) || !c.TryGet(idB, out var knobB))
            yield break;
        if (s.LevelOf(knobA) != ProtectionLevel.Off && s.LevelOf(knobB) >= minB)
            yield return new Concern(sev, code, msg, suggestion);
    }
}
