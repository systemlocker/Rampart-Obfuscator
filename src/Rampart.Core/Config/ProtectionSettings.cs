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
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static string Serialize(ProtectionSettings settings) =>
        JsonSerializer.Serialize(settings, Options);

    public static ProtectionSettings Deserialize(string json)
    {
        using var document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;
        if (root.ValueKind == JsonValueKind.Object
            && root.TryGetProperty("Settings", out JsonElement nested))
        {
            root = nested;
        }

        return root.Deserialize<ProtectionSettings>(Options)
            ?? throw new FormatException("Empty protection settings document.");
    }
}
