using System.Text.Json;
using System.Text.Json.Serialization;

namespace Rampart.Config;

/// <summary>A concrete configuration: knob levels plus build inputs. This is the
/// exact object serialized by `rampart protect --dry-run --json` (payload preview)
/// and persisted by templates.</summary>
public sealed class ProtectionSettings
{
    /// <summary>Knob id → level. Omitted knobs default to the preset level.</summary>
    public Dictionary<string, ProtectionLevel> Knobs { get; init; } = new();

    /// <summary>Base preset applied before per-knob overrides.</summary>
    public string Preset { get; set; } = Presets.Balanced;

    /// <summary>Per-build seed. Same seed ⇒ identical output bytes (reproducible
    /// builds); different seeds ⇒ no shared bytes across builds (polymorphism).</summary>
    public long Seed { get; set; }

    /// <summary>Threat-focus dial tags intensified this build.</summary>
    public List<string> ThreatFocus { get; init; } = [];

    /// <summary>Owner watermark embedded in the build (visible to you, noise to an analyst).</summary>
    public string? Watermark { get; set; }

    /// <summary>Custom tamper/detection response message body.</summary>
    public string? CustomMessage { get; set; }

    /// <summary>MSVC/GNU MAP, JSON, or PDB files used only while building.</summary>
    public List<string> SymbolSources { get; init; } = [];

    /// <summary>Optional llvm-pdbutil path for native PDB public-symbol ingestion.</summary>
    public string? PdbTool { get; set; }

    /// <summary>When non-empty, only matching symbols or RVA ranges receive
    /// function-scoped transforms.</summary>
    public List<string> IncludeSymbols { get; init; } = [];

    /// <summary>Symbol globs that always opt matching functions out.</summary>
    public List<string> ExcludeSymbols { get; init; } = [];

    public List<RvaRange> IncludeRvaRanges { get; init; } = [];

    /// <summary>Ordered module/section/symbol/namespace/source/RVA overrides.</summary>
    public List<ProtectionRule> Rules { get; init; } = [];

    /// <summary>Optional, versioned settings for target-specific backends.
    /// Omitting this object preserves the native configuration contract.</summary>
    public TargetProtectionOptions? Targets { get; set; }

    public static ProtectionSettings FromPreset(string preset) => new()
    {
        Preset = preset,
        Seed = Random.Shared.NextInt64(),
    };

    public ProtectionLevel LevelOf(KnobDef knob)
    {
        if (Knobs.TryGetValue(knob.Id, out var level))
            return level;
        return ProtectionCapabilities.ClampToReady(
            knob.Id,
            Presets.DefaultLevel(Preset, knob));
    }
}

public static class ProtectionSettingsJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static string Serialize(ProtectionSettings settings)
    {
        // Balanced is the legacy model's default, not a managed preset request.
        // Omit that placeholder so SDK-produced managed configurations can be
        // reused by the CLI/build integration, which rejects explicit presets.
        if ((settings.Targets?.Managed is not null || settings.Targets?.Override == Targets.ProtectionTargetKind.ManagedIl)
            && settings.Preset == Presets.Balanced)
        {
            var payload = JsonSerializer.SerializeToNode(settings, Options)!.AsObject();
            payload.Remove(nameof(ProtectionSettings.Preset));
            return payload.ToJsonString(Options);
        }
        return JsonSerializer.Serialize(settings, Options);
    }

    public static ProtectionSettings Deserialize(string json)
    {
        using var document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new FormatException("Protection settings must be a JSON object.");

        JsonElement? nested = null;
        foreach (JsonProperty property in root.EnumerateObject())
        {
            if (!string.Equals(property.Name, "Settings", StringComparison.OrdinalIgnoreCase))
                continue;
            if (nested is not null)
                throw new FormatException("Protection settings wrapper contains more than one Settings property.");
            nested = property.Value;
        }
        if (nested is { } wrapped)
            root = wrapped.ValueKind == JsonValueKind.Object
                ? wrapped
                : throw new FormatException("Protection settings wrapper property 'Settings' must be an object.");

        ProtectionSettings settings = root.Deserialize<ProtectionSettings>(Options)
            ?? throw new FormatException("Empty protection settings document.");
        ValidateRequiredValues(settings);
        return settings;
    }

    private static void ValidateRequiredValues(ProtectionSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.Preset))
            throw new FormatException("Protection settings property 'Preset' must be a non-empty string.");
        settings.Targets?.Validate();
        if (settings.Knobs is null || settings.ThreatFocus is null || settings.SymbolSources is null
            || settings.IncludeSymbols is null || settings.ExcludeSymbols is null
            || settings.IncludeRvaRanges is null || settings.Rules is null)
        {
            throw new FormatException("Protection settings collection properties cannot be null.");
        }
        if (settings.IncludeRvaRanges.Any(range => range is null))
            throw new FormatException("Protection settings RVA ranges cannot contain null entries.");
        if (settings.Rules.Any(rule => rule is null || rule.Knobs is null))
            throw new FormatException("Protection settings rules and their Knobs collections cannot be null.");
        if (settings.ThreatFocus.Any(value => value is null)
            || settings.SymbolSources.Any(value => value is null)
            || settings.IncludeSymbols.Any(value => value is null)
            || settings.ExcludeSymbols.Any(value => value is null))
        {
            throw new FormatException("Protection settings string collections cannot contain null entries.");
        }
    }
}
