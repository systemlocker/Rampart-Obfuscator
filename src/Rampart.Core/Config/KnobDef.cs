namespace Rampart.Config;

/// <summary>Configuration metadata for one protection identifier.
/// <see cref="ProtectionCapabilities"/> defines its supported levels.</summary>
/// <param name="Id">Stable CLI identifier, e.g. "strings.encryption".</param>
/// <param name="Group">A protection group in <see cref="KnobGroups"/>.</param>
/// <param name="Name">Human-readable name shown in `rampart knobs`.</param>
/// <param name="Summary">One-line description of the mechanism.</param>
/// <param name="Points">Protection-budget points for Light..Maximum (index = level-1).</param>
/// <param name="LevelTexts">Descriptions for Light..Maximum. Unsupported levels
/// contain an availability notice, not a behavioral specification.</param>
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

/// <summary>Protection groups, from file transformations to runtime checks.</summary>
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
        AnalysisCrashers => "Analysis resistance",
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
