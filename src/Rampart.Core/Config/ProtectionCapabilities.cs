namespace Rampart.Config;

/// <summary>
/// Defines the supported level ceiling for each protection. Catalog membership
/// alone does not establish support: disabled identifiers can remain recognized
/// for compatibility with existing configuration files.
/// </summary>
public static class ProtectionCapabilities
{
    private static readonly Dictionary<string, ProtectionLevel> ReadyLevels = new(StringComparer.Ordinal)
    {
        ["packaging.symbol-scrub"] = ProtectionLevel.Maximum,
        ["packaging.import-concealment"] = ProtectionLevel.Light,
        ["packaging.header-disguise"] = ProtectionLevel.Maximum,
        ["packaging.ep-confusion"] = ProtectionLevel.Light,
        ["packaging.packer"] = ProtectionLevel.Light,
        ["code-transformation.flattening"] = ProtectionLevel.Light,
        ["virtualization.per-build-isa"] = ProtectionLevel.Light,
        ["virtualization.coverage"] = ProtectionLevel.Light,
        ["virtualization.extended-isa"] = ProtectionLevel.Light,
        ["virtualization.handler-polymorphism"] = ProtectionLevel.Light,
        ["virtualization.vm-nesting"] = ProtectionLevel.Light,
        ["virtualization.runtime-rekey"] = ProtectionLevel.Light,
        ["nuclear.nanomites"] = ProtectionLevel.Light,
        ["nuclear.exception-flow"] = ProtectionLevel.Light,
        ["code-transformation.junk-insertion"] = ProtectionLevel.Maximum,
        ["code-transformation.mba-constants"] = ProtectionLevel.Maximum,
        ["code-transformation.per-build-mutation"] = ProtectionLevel.Light,
        ["strings.encryption"] = ProtectionLevel.Balanced,
        ["strings.anti-instrumentation"] = ProtectionLevel.Light,
        ["strings.coverage"] = ProtectionLevel.Maximum,
        ["anti-debug.channel-sweep"] = ProtectionLevel.Light,
        ["anti-debug.inline-hook-check"] = ProtectionLevel.Light,
        ["anti-debug.veh-tamper"] = ProtectionLevel.Light,
        ["anti-debug.dll-notify"] = ProtectionLevel.Light,
        ["anti-sandbox.virtualisation-detect"] = ProtectionLevel.Light,
        ["anti-sandbox.fingerprint-suite"] = ProtectionLevel.Light,
        ["anti-sandbox.human-gate"] = ProtectionLevel.Light,
        ["anti-inject.dacl-hardening"] = ProtectionLevel.Light,
        ["anti-inject.cet-shadow-stack"] = ProtectionLevel.Light,
        ["anti-inject.dynamic-code-policy"] = ProtectionLevel.Light,
        ["anti-inject.iat-hash-check"] = ProtectionLevel.Light,
        ["analysis.ida-bomb"] = ProtectionLevel.Light,
        ["analysis.hexrays-denial"] = ProtectionLevel.Light,
        ["analysis.symbolic-denial"] = ProtectionLevel.Light,
        ["analysis.static-decode-denial"] = ProtectionLevel.Light,
        ["analysis.runtime-header-corruption"] = ProtectionLevel.Light,
        ["memory.anti-dump"] = ProtectionLevel.Light,
        ["memory.api-concealment"] = ProtectionLevel.Light,
        ["integrity.header-scrub"] = ProtectionLevel.Light,
        ["integrity.kernel-wall"] = ProtectionLevel.Light,
        ["integrity.measurement-channels"] = ProtectionLevel.Light,
        ["integrity.tls-veh-ownership"] = ProtectionLevel.Light,
        ["integrity.mitigation-stack"] = ProtectionLevel.Light,
        ["integrity.hidden-threads"] = ProtectionLevel.Light,
        ["response.silent-taint"] = ProtectionLevel.Light,
        ["response.tool-response"] = ProtectionLevel.Light,
        ["response.brand-overlay"] = ProtectionLevel.Light,
        ["response.custom-messages"] = ProtectionLevel.Light,
        ["nuclear.injection-hunter"] = ProtectionLevel.Light,
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
        "code-transformation.flattening",
        "code-transformation.mba-constants",
        "virtualization.per-build-isa",
        "virtualization.coverage",
        "virtualization.extended-isa",
        "virtualization.handler-polymorphism",
        "virtualization.vm-nesting",
        "virtualization.runtime-rekey",
        "nuclear.nanomites",
        "nuclear.exception-flow",
    };

    /// <summary>
    /// Rejects misspelled and unsupported explicit overrides. Presets resolve
    /// unavailable options to Off, but an explicit opt-in must fail instead of
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
                        ? $"Protection knob '{id}' is not supported. " +
                          "Run `rampart knobs` to see supported protections."
                        : $"Protection knob '{id}' is supported through {maxReady}, but {level} was requested. " +
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
        }

        // Rules compose in document order, and matching depends on functions
        // discovered from the input image. Validate their final dependency state
        // in ValidateEffectiveFunctionPolicies instead of judging each partial
        // rule against the global defaults.
        var entryPoint = settings.LevelOf(catalog.Get("packaging.ep-confusion"));
        var imports = settings.LevelOf(catalog.Get("packaging.import-concealment"));
        var strings = settings.LevelOf(catalog.Get("strings.encryption"));
        var stringInstrumentation = settings.LevelOf(catalog.Get("strings.anti-instrumentation"));
        var stringCoverage = settings.LevelOf(catalog.Get("strings.coverage"));
        var packer = settings.LevelOf(catalog.Get("packaging.packer"));
        if ((settings.LevelOf(catalog.Get("virtualization.per-build-isa")) == ProtectionLevel.Off)
            != (settings.LevelOf(catalog.Get("virtualization.coverage")) == ProtectionLevel.Off))
        {
            throw new ArgumentException(
                "virtualization.per-build-isa and virtualization.coverage must be enabled together.");
        }
        if (VmModifierIds.Any(id => settings.LevelOf(catalog.Get(id)) != ProtectionLevel.Off)
            && (settings.LevelOf(catalog.Get("virtualization.per-build-isa")) == ProtectionLevel.Off
                || settings.LevelOf(catalog.Get("virtualization.coverage")) == ProtectionLevel.Off))
        {
            throw new ArgumentException(
                "Virtualization modifiers require virtualization.per-build-isa and virtualization.coverage.");
        }
        string[] startupKnobs =
        [
            "anti-debug.channel-sweep",
            "anti-debug.inline-hook-check",
            "anti-debug.veh-tamper",
            "anti-debug.dll-notify",
            "anti-sandbox.virtualisation-detect",
            "anti-sandbox.fingerprint-suite",
            "anti-sandbox.human-gate",
            "analysis.runtime-header-corruption",
            "memory.anti-dump",
            "integrity.header-scrub",
            "anti-inject.dacl-hardening",
            "anti-inject.dynamic-code-policy",
            "anti-inject.iat-hash-check",
            "integrity.kernel-wall",
            "integrity.measurement-channels",
            "integrity.tls-veh-ownership",
            "integrity.hidden-threads",
            "response.silent-taint",
            "response.tool-response",
            "response.custom-messages",
            "nuclear.injection-hunter",
            "nuclear.nanomites",
            "nuclear.exception-flow",
        ];
        bool runtimeGuardEnabled = startupKnobs.Any(id =>
            settings.LevelOf(catalog.Get(id)) != ProtectionLevel.Off);

        if (entryPoint == ProtectionLevel.Off
            && (imports != ProtectionLevel.Off || strings != ProtectionLevel.Off
                || packer != ProtectionLevel.Off || runtimeGuardEnabled))
        {
            throw new ArgumentException(
                "packaging.ep-confusion must be enabled when a selected protection registers a startup routine.");
        }

        if (strings == ProtectionLevel.Off
            && (stringInstrumentation != ProtectionLevel.Off || stringCoverage != ProtectionLevel.Off))
        {
            throw new ArgumentException(
                "strings.encryption must be enabled when string coverage or anti-instrumentation is enabled.");
        }
    }

    private static readonly string[] VmModifierIds =
    [
        "virtualization.extended-isa",
        "virtualization.handler-polymorphism",
        "virtualization.vm-nesting",
        "virtualization.runtime-rekey",
    ];

    /// <summary>
    /// Validates dependency relationships after ordered rules have been resolved
    /// against the functions discovered in the input image.
    /// </summary>
    public static void ValidateEffectiveFunctionPolicies(
        ProtectionSettings settings,
        KnobCatalog catalog,
        IEnumerable<Rampart.Engine.FunctionDescriptor> functions)
    {
        var policy = new Rampart.Engine.FunctionPolicy(settings, catalog);
        ProtectionLevel entryPoint = settings.LevelOf(catalog.Get("packaging.ep-confusion"));
        foreach (Rampart.Engine.FunctionDescriptor function in functions.Where(policy.IsSelected))
        {
            ProtectionLevel vmIsa = policy.Level("virtualization.per-build-isa", function);
            ProtectionLevel vmCoverage = policy.Level("virtualization.coverage", function);
            if ((vmIsa == ProtectionLevel.Off) != (vmCoverage == ProtectionLevel.Off))
            {
                throw new ArgumentException(
                    $"Function '{function.Name}' must enable virtualization.per-build-isa and " +
                    "virtualization.coverage together after ordered rules are applied.");
            }

            if (VmModifierIds.Any(id => policy.Level(id, function) != ProtectionLevel.Off)
                && (vmIsa == ProtectionLevel.Off || vmCoverage == ProtectionLevel.Off))
            {
                throw new ArgumentException(
                    $"Function '{function.Name}' enables a virtualization modifier without " +
                    "virtualization.per-build-isa and virtualization.coverage after ordered rules are applied.");
            }

            ProtectionLevel imports = policy.Level("packaging.import-concealment", function);
            ProtectionLevel strings = policy.Level("strings.encryption", function);
            if (entryPoint == ProtectionLevel.Off
                && (imports != ProtectionLevel.Off || strings != ProtectionLevel.Off
                    || policy.Level("nuclear.nanomites", function) != ProtectionLevel.Off
                    || policy.Level("nuclear.exception-flow", function) != ProtectionLevel.Off))
            {
                throw new ArgumentException(
                    $"packaging.ep-confusion must be enabled because function '{function.Name}' enables " +
                    "a startup-dependent protection after ordered rules are applied.");
            }

            ProtectionLevel stringInstrumentation =
                policy.Level("strings.anti-instrumentation", function);
            ProtectionLevel stringCoverage = policy.Level("strings.coverage", function);
            if (strings == ProtectionLevel.Off
                && (stringInstrumentation != ProtectionLevel.Off || stringCoverage != ProtectionLevel.Off))
            {
                throw new ArgumentException(
                    $"Function '{function.Name}' must enable strings.encryption because string coverage " +
                    "or anti-instrumentation remains enabled after ordered rules are applied.");
            }
        }
    }
}
