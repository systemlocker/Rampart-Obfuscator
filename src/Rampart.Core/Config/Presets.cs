namespace Rampart.Config;

/// <summary>Named starting points. A preset sets a sane default level for every
/// knob; explicit per-knob settings still win.</summary>
public static class Presets
{
    public const string Light = "light";
    public const string Balanced = "balanced";
    public const string Heavy = "heavy";
    public const string Maximum = "maximum";
    public const string Nuclear = "nuclear";

    public static readonly string[] All = [Light, Balanced, Heavy, Maximum, Nuclear];

    /// <summary>Default level a preset assigns to a knob when the user has not
    /// overridden it. Everything earns its level: cheap static transforms ride
    /// high everywhere, expensive transforms (VM, nanomites) only turn up late.</summary>
    public static ProtectionLevel DefaultLevel(string preset, KnobDef knob) => preset switch
    {
        Light => PresetMap(knob.Group, knob.Id, 1),
        Balanced => PresetMap(knob.Group, knob.Id, 2),
        Heavy => PresetMap(knob.Group, knob.Id, 3),
        Maximum => PresetMap(knob.Group, knob.Id, 4),
        // Nuclear is Maximum plus the "deliberate use only" options the site
        // gates behind a second confirmation — here gated by the preset choice.
        Nuclear => NuclearMap(knob.Id),
        _ => throw new ArgumentException($"Unknown preset '{preset}'. Valid: {string.Join(", ", All)}"),
    };

    private static ProtectionLevel PresetMap(string group, string id, int tier)
    {
        // Presets scale each group by tier, but individual knobs clamp the tier:
        // knobs whose cost is compatibility (not just speed) stay low until asked for.
        var clamp = id switch
        {
            // Nanomites and friends are "deliberate use only" even on Maximum —
            // some tools flag their patterns, exactly as the reference feature
            // list warns. They only light up on the nuclear preset or by name.
            "nuclear.nanomites" or "nuclear.exception-flow" or "nuclear.memory-ambush"
                or "nuclear.injection-hunter" => ProtectionLevel.Off,
            // Self-debugging holds the debug port; too surprising for a default.
            "integrity.self-debug-port" => tier >= 4 ? ProtectionLevel.Light : ProtectionLevel.Off,
            // Loader interposition can refuse legitimate plug-ins in DLL-heavy apps.
            "integrity.loader-hijack" => tier >= 4 ? ProtectionLevel.Light : ProtectionLevel.Off,
            // Runtime environment probes and process-policy changes need an
            // explicit compatibility decision. `--only` still enables their
            // Light emitters together with required startup infrastructure.
            "anti-debug.channel-sweep" or "anti-debug.inline-hook-check"
                or "anti-debug.veh-tamper" or "anti-debug.dll-notify"
                or "anti-sandbox.virtualisation-detect"
                or "anti-sandbox.fingerprint-suite" or "anti-sandbox.human-gate"
                or "analysis.runtime-header-corruption" or "memory.anti-dump"
                or "integrity.header-scrub"
                or "anti-inject.dacl-hardening" or "anti-inject.cet-shadow-stack"
                or "anti-inject.dynamic-code-policy" or "anti-inject.iat-hash-check"
                or "integrity.kernel-wall" or "integrity.measurement-channels"
                or "integrity.tls-veh-ownership" or "integrity.mitigation-stack"
                or "integrity.hidden-threads"
                or "response.silent-taint" or "response.tool-response"
                or "response.brand-overlay" or "response.custom-messages"
                => ProtectionLevel.Off,
            _ => (ProtectionLevel)tier,
        };
        return clamp;
    }

    private static ProtectionLevel NuclearMap(string id) => ProtectionLevel.Maximum;
}
