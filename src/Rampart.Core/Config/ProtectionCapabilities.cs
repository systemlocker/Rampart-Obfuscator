namespace Rampart.Config;

/// <summary>
/// Tracks the knobs whose emitters are complete enough to use in a build. The
/// catalog is also Rampart's public roadmap, so catalog membership alone must
/// never be treated as proof that a protection is already implemented.
/// </summary>
public static class ProtectionCapabilities
{
    private static readonly Dictionary<string, ProtectionLevel> ReadyLevels = new(StringComparer.Ordinal)
    {
        ["packaging.symbol-scrub"] = ProtectionLevel.Heavy,
        ["packaging.import-concealment"] = ProtectionLevel.Light,
        ["packaging.header-disguise"] = ProtectionLevel.Balanced,
        ["packaging.ep-confusion"] = ProtectionLevel.Light,
        ["code-transformation.junk-insertion"] = ProtectionLevel.Maximum,
        ["code-transformation.mba-constants"] = ProtectionLevel.Light,
        ["code-transformation.per-build-mutation"] = ProtectionLevel.Light,
        ["strings.encryption"] = ProtectionLevel.Balanced,
        ["strings.anti-instrumentation"] = ProtectionLevel.Light,
        ["strings.coverage"] = ProtectionLevel.Maximum,
    };

    public static bool IsReady(string knobId) => ReadyLevels.ContainsKey(knobId);

    public static ProtectionLevel MaxReadyLevel(string knobId) =>
        ReadyLevels.TryGetValue(knobId, out var level) ? level : ProtectionLevel.Off;

    public static ProtectionLevel ClampToReady(string knobId, ProtectionLevel requested) =>
        (ProtectionLevel)Math.Min((int)requested, (int)MaxReadyLevel(knobId));

    /// <summary>Knobs whose work can be selected at individual function scope.</summary>
    public static readonly HashSet<string> FunctionScopedKnobs = new(StringComparer.Ordinal)
    {
        "packaging.import-concealment",
        "code-transformation.junk-insertion",
        "strings.encryption",
        "strings.anti-instrumentation",
        "strings.coverage",
    };

    /// <summary>
    /// Rejects misspelled and planned-only explicit overrides. Presets resolve
    /// planned knobs to Off, but an explicit opt-in must fail loudly instead of
    /// producing a binary that only claims to contain the requested protection.
    /// </summary>
    public static void Validate(ProtectionSettings settings, KnobCatalog catalog)
    {
        _ = Presets.DefaultLevel(settings.Preset, catalog.All[0]);

        foreach (var (id, level) in settings.Knobs)
        {
            _ = catalog.Get(id);
            if (!Enum.IsDefined(level))
                throw new ArgumentException($"Protection knob '{id}' has invalid numeric level {(int)level}.");
            var maxReady = MaxReadyLevel(id);
            if (level > maxReady)
            {
                throw new NotSupportedException(
                    maxReady == ProtectionLevel.Off
                        ? $"Protection knob '{id}' is planned but does not have a ready emitter yet. " +
                          "Run `rampart knobs` to see ready protections."
                        : $"Protection knob '{id}' is ready through {maxReady}, but {level} was requested. " +
                          "Run `rampart explain` to see which levels are available.");
            }
        }

        foreach (var range in settings.IncludeRvaRanges)
        {
            if (range.End <= range.Start)
                throw new ArgumentException($"Invalid RVA range 0x{range.Start:X}-0x{range.End:X}; end must exceed start.");
        }

        foreach (var rule in settings.Rules)
        {
            if (string.IsNullOrWhiteSpace(rule.Match) && rule.Scope != ProtectionRuleScope.Rva)
                throw new ArgumentException("Protection rules require a non-empty Match value.");
            if (rule.Scope == ProtectionRuleScope.Rva
                && (rule.StartRva is null || rule.EndRva is null || rule.EndRva <= rule.StartRva))
            {
                throw new ArgumentException("RVA protection rules require StartRva < EndRva.");
            }
            if (rule.Preset is not null
                && !string.Equals(rule.Preset, "off", StringComparison.OrdinalIgnoreCase)
                && !Presets.All.Contains(rule.Preset, StringComparer.OrdinalIgnoreCase))
            {
                throw new ArgumentException(
                    $"Unknown rule preset '{rule.Preset}'. Valid: off, {string.Join(", ", Presets.All)}.");
            }
            foreach (var (id, level) in rule.Knobs)
            {
                _ = catalog.Get(id);
                if (!FunctionScopedKnobs.Contains(id))
                    throw new ArgumentException($"Protection knob '{id}' cannot currently be applied per function.");
                if (!Enum.IsDefined(level) || level > MaxReadyLevel(id))
                    throw new NotSupportedException($"Per-function knob '{id}' is not ready at {level}.");
            }

            ProtectionLevel RuleLevel(string id)
            {
                if (rule.Knobs.TryGetValue(id, out ProtectionLevel exact))
                    return exact;
                if (rule.Preset is null)
                    return settings.LevelOf(catalog.Get(id));
                return string.Equals(rule.Preset, "off", StringComparison.OrdinalIgnoreCase)
                    ? ProtectionLevel.Off
                    : ClampToReady(id, Presets.DefaultLevel(rule.Preset.ToLowerInvariant(), catalog.Get(id)));
            }

            ProtectionLevel ruleImports = RuleLevel("packaging.import-concealment");
            ProtectionLevel ruleStrings = RuleLevel("strings.encryption");
            ProtectionLevel ruleStringInstrumentation = RuleLevel("strings.anti-instrumentation");
            ProtectionLevel ruleStringCoverage = RuleLevel("strings.coverage");
            if (settings.LevelOf(catalog.Get("packaging.ep-confusion")) == ProtectionLevel.Off
                && (ruleImports != ProtectionLevel.Off || ruleStrings != ProtectionLevel.Off))
            {
                throw new ArgumentException(
                    "packaging.ep-confusion must be enabled when a function rule enables imports or strings.");
            }
            if (ruleStrings == ProtectionLevel.Off
                && (ruleStringInstrumentation != ProtectionLevel.Off || ruleStringCoverage != ProtectionLevel.Off))
            {
                throw new ArgumentException(
                    "A function rule cannot enable string coverage or anti-instrumentation while strings.encryption is off.");
            }
        }

        var entryPoint = settings.LevelOf(catalog.Get("packaging.ep-confusion"));
        var imports = settings.LevelOf(catalog.Get("packaging.import-concealment"));
        var strings = settings.LevelOf(catalog.Get("strings.encryption"));
        var stringInstrumentation = settings.LevelOf(catalog.Get("strings.anti-instrumentation"));
        var stringCoverage = settings.LevelOf(catalog.Get("strings.coverage"));

        if (entryPoint == ProtectionLevel.Off
            && (imports != ProtectionLevel.Off || strings != ProtectionLevel.Off))
        {
            throw new ArgumentException(
                "packaging.ep-confusion must be enabled when import concealment or string encryption " +
                "registers a startup routine.");
        }

        if (strings == ProtectionLevel.Off
            && (stringInstrumentation != ProtectionLevel.Off || stringCoverage != ProtectionLevel.Off))
        {
            throw new ArgumentException(
                "strings.encryption must be enabled when string coverage or anti-instrumentation is enabled.");
        }
    }
}
