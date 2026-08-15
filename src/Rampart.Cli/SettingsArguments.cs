using Rampart.Config;
using System.Globalization;

namespace Rampart.Cli;

/// <summary>Shared configuration arguments for protect and check. Parsing lives
/// in one place so payload previews and real builds resolve settings identically.</summary>
internal sealed class SettingsArguments
{
    private string? _configPath;
    private string? _preset;
    private long? _seed;
    private readonly List<(string Id, ProtectionLevel Level)> _sets = [];
    private readonly List<string> _only = [];
    private readonly List<string> _disabled = [];
    private readonly List<(string Group, ProtectionLevel Level)> _groupLevels = [];
    private readonly List<string> _focus = [];
    private readonly List<string> _symbolSources = [];
    private readonly List<string> _includeSymbols = [];
    private readonly List<string> _excludeSymbols = [];
    private readonly List<RvaRange> _rvaRanges = [];
    private readonly List<ProtectionRule> _functionProfiles = [];
    private string? _pdbTool;
    private string? _watermark;
    private string? _customMessage;

    public bool Json { get; private set; }

    public bool TryConsume(string[] args, ref int index)
    {
        string arg = args[index];
        switch (arg)
        {
            case "--config":
                _configPath = RequireValue(args, ref index, arg);
                return true;
            case "--preset":
                _preset = RequireValue(args, ref index, arg).ToLowerInvariant();
                return true;
            case "--seed":
                string rawSeed = RequireValue(args, ref index, arg);
                if (!long.TryParse(rawSeed, out long seed))
                    throw new ArgumentException($"Invalid seed '{rawSeed}'. Expected a signed 64-bit integer.");
                _seed = seed;
                return true;
            case "--set":
                ParseSet(RequireValue(args, ref index, arg));
                return true;
            case "--only":
                ParseIds(RequireValue(args, ref index, arg), _only, arg);
                return true;
            case "--disable":
                ParseIds(RequireValue(args, ref index, arg), _disabled, arg);
                return true;
            case "--group-level":
                ParseGroupLevel(RequireValue(args, ref index, arg));
                return true;
            case "--focus":
                _focus.AddRange(RequireValue(args, ref index, arg)
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
                return true;
            case "--symbols" or "--map" or "--pdb":
                _symbolSources.Add(RequireValue(args, ref index, arg));
                return true;
            case "--pdb-tool":
                _pdbTool = RequireValue(args, ref index, arg);
                return true;
            case "--include-symbol":
                _includeSymbols.Add(RequireValue(args, ref index, arg));
                return true;
            case "--exclude-symbol":
                _excludeSymbols.Add(RequireValue(args, ref index, arg));
                return true;
            case "--rva-range":
                _rvaRanges.Add(ParseRvaRange(RequireValue(args, ref index, arg)));
                return true;
            case "--function-profile":
                _functionProfiles.Add(ParseFunctionProfile(RequireValue(args, ref index, arg)));
                return true;
            case "--watermark":
                _watermark = RequireValue(args, ref index, arg);
                return true;
            case "--custom-message":
                _customMessage = RequireValue(args, ref index, arg);
                return true;
            case "--json":
                Json = true;
                return true;
            default:
                return false;
        }
    }

    public ProtectionSettings Build(KnobCatalog catalog)
    {
        ProtectionSettings settings;
        if (_configPath is not null)
        {
            string path = Path.GetFullPath(_configPath);
            settings = ProtectionSettingsJson.Deserialize(File.ReadAllText(path));
            ResolveConfigPaths(settings, Path.GetDirectoryName(path)!);
        }
        else
        {
            settings = ProtectionSettings.FromPreset(_preset ?? Presets.Balanced);
        }

        if (_preset is not null)
            settings.Preset = _preset;
        if (_seed is not null)
            settings.Seed = _seed.Value;
        if (_watermark is not null)
            settings.Watermark = _watermark;
        if (_customMessage is not null)
            settings.CustomMessage = _customMessage;
        if (_pdbTool is not null)
            settings.PdbTool = Path.GetFullPath(_pdbTool);

        settings.SymbolSources.AddRange(_symbolSources.Select(Path.GetFullPath));
        settings.IncludeSymbols.AddRange(_includeSymbols);
        settings.ExcludeSymbols.AddRange(_excludeSymbols);
        settings.IncludeRvaRanges.AddRange(_rvaRanges);
        settings.Rules.AddRange(_functionProfiles);

        // Bulk selectors establish a profile first. Exact --set overrides then
        // win, while --disable is deliberately final and may expose an invalid
        // dependency combination for the normal validator to explain.
        if (_only.Count > 0)
            ProtectionSelection.ApplyOnly(settings, catalog, _only);
        foreach (var (group, level) in _groupLevels)
            ProtectionSelection.ApplyGroupLevel(settings, catalog, group, level);
        foreach (var (id, level) in _sets)
            settings.Knobs[id] = level;
        ProtectionSelection.Disable(settings, catalog, _disabled);
        foreach (string tag in _focus)
        {
            if (!settings.ThreatFocus.Contains(tag, StringComparer.Ordinal))
                settings.ThreatFocus.Add(tag);
        }

        ProtectionCapabilities.Validate(settings, catalog);
        return settings;
    }

    private void ParseSet(string assignment)
    {
        int equals = assignment.IndexOf('=');
        if (equals <= 0 || equals == assignment.Length - 1)
            throw new ArgumentException($"Invalid override '{assignment}'. Expected <knob>=<level>.");

        string id = assignment[..equals];
        string rawLevel = assignment[(equals + 1)..];
        ProtectionLevel level = ParseLevel(rawLevel);
        _sets.Add((id, level));
    }

    private void ParseGroupLevel(string assignment)
    {
        int equals = assignment.IndexOf('=');
        if (equals <= 0 || equals == assignment.Length - 1)
            throw new ArgumentException($"Invalid group level '{assignment}'. Expected <group>=<level>.");

        _groupLevels.Add((assignment[..equals], ParseLevel(assignment[(equals + 1)..])));
    }

    private static ProtectionLevel ParseLevel(string rawLevel)
    {
        if (!Enum.TryParse(rawLevel, ignoreCase: true, out ProtectionLevel level)
            || !Enum.IsDefined(level))
        {
            throw new ArgumentException(
                $"Invalid protection level '{rawLevel}'. Valid: {string.Join(", ", Enum.GetNames<ProtectionLevel>())}.");
        }
        return level;
    }

    private static void ParseIds(string value, List<string> destination, string option)
    {
        string[] ids = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (ids.Length == 0)
            throw new ArgumentException($"Option '{option}' requires at least one knob id.");
        destination.AddRange(ids);
    }

    private static RvaRange ParseRvaRange(string value)
    {
        string[] parts = value.Split(['-', ':'], 2, StringSplitOptions.TrimEntries);
        if (parts.Length != 2)
            throw new ArgumentException($"Invalid RVA range '{value}'. Expected <start>-<end>.");
        uint start = ParseRva(parts[0]);
        uint end = ParseRva(parts[1]);
        if (end <= start)
            throw new ArgumentException($"Invalid RVA range '{value}'; end must exceed start.");
        return new RvaRange { Start = start, End = end };
    }

    private static uint ParseRva(string value)
    {
        string hex = value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? value[2..] : value;
        if (!uint.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out uint result))
            throw new ArgumentException($"Invalid hexadecimal RVA '{value}'.");
        return result;
    }

    private static ProtectionRule ParseFunctionProfile(string value)
    {
        int equals = value.LastIndexOf('=');
        if (equals <= 0 || equals == value.Length - 1)
            throw new ArgumentException($"Invalid function profile '{value}'. Expected <symbol-glob>=<preset>.");
        return new ProtectionRule
        {
            Match = value[..equals],
            Scope = ProtectionRuleScope.Symbol,
            Preset = value[(equals + 1)..].ToLowerInvariant(),
        };
    }

    private static void ResolveConfigPaths(ProtectionSettings settings, string configDirectory)
    {
        for (int i = 0; i < settings.SymbolSources.Count; i++)
        {
            if (!Path.IsPathRooted(settings.SymbolSources[i]))
                settings.SymbolSources[i] = Path.GetFullPath(Path.Combine(configDirectory, settings.SymbolSources[i]));
        }
        if (settings.PdbTool is not null && !Path.IsPathRooted(settings.PdbTool))
            settings.PdbTool = Path.GetFullPath(Path.Combine(configDirectory, settings.PdbTool));
    }

    internal static string RequireValue(string[] args, ref int index, string option)
    {
        if (index + 1 >= args.Length)
            throw new ArgumentException($"Option '{option}' requires a value.");
        index++;
        return args[index];
    }
}
