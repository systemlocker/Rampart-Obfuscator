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
            "Relocation stripping forces a fixed image base; nanomites rely on VEH dispatch that " +
            "ASLR-off builds make easier to spot and patch.",
            "Keep symbol scrub at Balanced or lower, or drop nanomites."),

        (s, c) => R(s, c, "anti-inject.dynamic-code-policy", "virtualization.jit-handlers", ProtectionLevel.Light,
            ConcernSeverity.Warning, "RP02",
            "Dynamic code policy forbids new executable pages, but JIT-decrypted VM handlers copy " +
            "handler bodies to a scratch page before executing them.",
            "The engine falls back to in-place handler decryption for this build; expect slightly " +
            "weaker handler isolation, or lower one of the two knobs."),

        (s, c) => R(s, c, "memory.page-mode-decrypt", "memory.sleep-mask", ProtectionLevel.Heavy,
            ConcernSeverity.Info, "RP03",
            "Page-mode decryption and the sleep mask overlap: both re-encrypt non-executing code. " +
            "The engine de-duplicates this; the second knob mostly adds cost."),

        (s, c) => R(s, c, "anti-inject.cet-shadow-stack", ProtectionLevel.Balanced,
            ConcernSeverity.Info, "RP04",
            "CET shadow stack enforcement requires Windows 10 2004+ with hardware CET for full " +
            "effect; older systems silently run the policy off."),

        (s, c) => R(s, c, "integrity.self-debug-port", ProtectionLevel.Light,
            ConcernSeverity.Risky, "RP05",
            "Self-debug port ownership holds the process debug object. Crash dumps from this process " +
            "become harder to collect, and some AV heuristics flag self-debugging.",
            "Acceptable for release builds; skip for binaries you need to debug or that must collect WER dumps."),

        (s, c) => R(s, c, "anti-sandbox.human-gate", ProtectionLevel.Balanced,
            ConcernSeverity.Warning, "RP06",
            "The human-activity gate refuses sensitive paths when no recent input activity exists. " +
            "Services and scheduled tasks see no keyboard/mouse input by design.",
            "Keep at Light for unattended binaries, or exclude service binaries from this knob."),

        (s, c) => R(s, c, "packaging.packer", "memory.at-rest-encryption", ProtectionLevel.Balanced,
            ConcernSeverity.Info, "RP07",
            "Packing already makes on-disk content ciphertext; at-rest encryption adds value only " +
            "against mid-run memory scanners."),

        (s, c) => R(s, c, "analysis.ida-bomb", ProtectionLevel.Heavy,
            ConcernSeverity.Warning, "RP08",
            "The autoanalysis bomb emits tens of thousands of synthetic prologues. Some AV/EDR " +
            "engines count suspicious-looking density and may raise a score for the file."),

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
