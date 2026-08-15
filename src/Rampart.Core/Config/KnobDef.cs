namespace Rampart.Config;

/// <summary>One tunable protection option. The catalog doubles as the public
/// roadmap; <see cref="ProtectionCapabilities"/> distinguishes ready emitters
/// from planned entries.</summary>
/// <param name="Id">Stable CLI identifier, e.g. "strings.encryption".</param>
/// <param name="Group">One of the ten dashboard sections in <see cref="KnobGroups"/>.</param>
/// <param name="Name">Human-readable name shown in `rampart knobs`.</param>
/// <param name="Summary">One-line description of the mechanism.</param>
/// <param name="Points">Protection-budget points for Light..Maximum (index = level-1).</param>
/// <param name="LevelTexts">What each level adds over the previous one, Light..Maximum.
/// Written so `rampart explain` can show a step-by-step level diff.</param>
/// <param name="Tags">Threat-focus tags used by the dials, e.g. "static", "debug".</param>
public sealed record KnobDef(
    string Id,
    string Group,
    string Name,
    string Summary,
    int[] Points,
    string[] LevelTexts,
    string[] Tags)
{
    public int PointsAt(ProtectionLevel level) =>
        level == ProtectionLevel.Off ? 0 : Points[(int)level - 1];

    public string LevelText(ProtectionLevel level) =>
        level == ProtectionLevel.Off ? "Off — no bytes change." : LevelTexts[(int)level - 1];

    public bool HasTag(string tag) => Tags.Contains(tag, StringComparer.Ordinal);
}

/// <summary>The ten dashboard sections, ordered the way an attacker would approach
/// the binary: static reading first, live analysis last.</summary>
public static class KnobGroups
{
    public const string Packaging = "packaging";
    public const string StringProtection = "string-protection";
    public const string CodeTransformation = "code-transformation";
    public const string AntiDebug = "anti-debug";
    public const string AntiInject = "anti-inject";
    public const string AntiSandbox = "anti-sandbox";
    public const string AnalysisCrashers = "analysis-crashers";
    public const string MemoryProtection = "memory-protection";
    public const string Virtualization = "virtualization";
    public const string IntegrityBinding = "integrity-binding";
    public const string Response = "response";

    public static readonly string[] All =
    [
        Packaging,
        StringProtection,
        CodeTransformation,
        AntiDebug,
        AntiInject,
        AntiSandbox,
        AnalysisCrashers,
        MemoryProtection,
        Virtualization,
        IntegrityBinding,
        Response,
    ];

    public static string Title(string group) => group switch
    {
        Packaging => "Packaging",
        StringProtection => "String protection",
        CodeTransformation => "Code transformation",
        AntiDebug => "Anti-debug",
        AntiInject => "Anti-inject",
        AntiSandbox => "Anti-sandbox",
        AnalysisCrashers => "Analysis crashers",
        MemoryProtection => "Memory protection",
        Virtualization => "Virtualization",
        IntegrityBinding => "Integrity binding",
        Response => "Response & branding",
        _ => group,
    };
}

/// <summary>Threat-focus dial identifiers: the seven attacker types the dials
/// intensify protections against.</summary>
public static class ThreatTags
{
    public const string Static = "static";        // static analysis / disassembly
    public const string Debug = "debug";          // live debugging
    public const string Dump = "dump";            // memory acquisition
    public const string Sandbox = "sandbox";      // VM / sandbox execution
    public const string Inject = "inject";        // process injection
    public const string Tools = "tools";          // RE tooling (IDA et al.)
    public const string Kernel = "kernel";        // kernel-mode adversaries

    public static readonly string[] All = [Static, Debug, Dump, Sandbox, Inject, Tools, Kernel];
}
