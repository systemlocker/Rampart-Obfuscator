using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Rampart.Config;
using Rampart.Pe;
using Rampart.Symbols;

namespace Rampart.Engine;

/// <summary>A `.pdata` function enriched with optional build-only symbol data.</summary>
public sealed record FunctionDescriptor(
    uint BeginRva,
    uint EndRva,
    uint UnwindRva,
    string Name,
    string Namespace,
    string? Module,
    string Section,
    string? Source)
{
    public uint Size => EndRva >= BeginRva ? EndRva - BeginRva : 0u;

    public static List<FunctionDescriptor> Attach(
        PeImage pe,
        IEnumerable<RuntimeFunction> functions,
        IEnumerable<SymbolRecord> symbols)
    {
        SymbolRecord[] orderedSymbols = symbols.OrderBy(symbol => symbol.StartRva).ToArray();
        var result = new List<FunctionDescriptor>();
        foreach (RuntimeFunction function in functions)
        {
            if (function.EndRva < function.BeginRva)
                continue;
            SymbolRecord? symbol = FindBestSymbol(orderedSymbols, function.BeginRva, function.EndRva);
            string name = symbol?.Name ?? $"sub_{function.BeginRva:X8}";
            int separator = name.LastIndexOf("::", StringComparison.Ordinal);
            string symbolNamespace = separator > 0 ? name[..separator] : "";
            result.Add(new FunctionDescriptor(
                function.BeginRva,
                function.EndRva,
                function.UnwindRva,
                name,
                symbolNamespace,
                symbol?.Module,
                pe.SectionFromRva(function.BeginRva)?.Name ?? "",
                symbol?.Source));
        }
        return result;
    }

    private static SymbolRecord? FindBestSymbol(SymbolRecord[] orderedSymbols, uint beginRva, uint endRva)
    {
        if (orderedSymbols.Length == 0)
            return null;
        // Binary search for the first symbol with StartRva >= beginRva (O(log S)).
        int low = 0, high = orderedSymbols.Length;
        while (low < high)
        {
            int mid = low + (high - low) / 2;
            if (orderedSymbols[mid].StartRva < beginRva)
                low = mid + 1;
            else
                high = mid;
        }
        if (low >= orderedSymbols.Length || orderedSymbols[low].StartRva >= endRva)
            return null;
        // Because symbols are sorted by StartRva, the first entry at/after
        // beginRva automatically prefers an exact BeginRva match, then lowest RVA.
        return orderedSymbols[low];
    }
}

/// <summary>Resolves global settings and ordered region rules for one function.</summary>
public sealed class FunctionPolicy
{
    private static readonly ConcurrentDictionary<string, Regex> GlobCache = new(StringComparer.Ordinal);
    private readonly ProtectionSettings _settings;
    private readonly KnobCatalog _catalog;

    public FunctionPolicy(ProtectionSettings settings, KnobCatalog catalog)
    {
        _settings = settings;
        _catalog = catalog;
    }

    public bool IsSelected(FunctionDescriptor function)
    {
        bool hasIncludes = _settings.IncludeSymbols.Count > 0 || _settings.IncludeRvaRanges.Count > 0;
        bool included = !hasIncludes
            || _settings.IncludeSymbols.Any(pattern => Glob(pattern, function.Name))
            || _settings.IncludeRvaRanges.Any(range => Overlaps(function, range.Start, range.End));
        if (!included)
            return false;

        return !_settings.ExcludeSymbols.Any(pattern => Glob(pattern, function.Name));
    }

    public ProtectionLevel Level(string knobId, FunctionDescriptor function)
    {
        if (!ProtectionCapabilities.FunctionScopedKnobs.Contains(knobId))
            return _settings.LevelOf(_catalog.Get(knobId));
        if (!IsSelected(function))
            return ProtectionLevel.Off;

        KnobDef knob = _catalog.Get(knobId);
        ProtectionLevel level = _settings.LevelOf(knob);
        foreach (ProtectionRule rule in _settings.Rules.Where(rule => Matches(rule, function)))
        {
            if (rule.Preset is not null)
            {
                level = string.Equals(rule.Preset, "off", StringComparison.OrdinalIgnoreCase)
                    ? ProtectionLevel.Off
                    : ProtectionCapabilities.ClampToReady(
                        knobId,
                        Presets.DefaultLevel(rule.Preset.ToLowerInvariant(), knob));
            }
            if (rule.Knobs.TryGetValue(knobId, out ProtectionLevel overrideLevel))
                level = overrideLevel;
        }
        return level;
    }

    public ProtectionLevel MaximumLevel(string knobId, IEnumerable<FunctionDescriptor> functions)
    {
        if (!ProtectionCapabilities.FunctionScopedKnobs.Contains(knobId))
            return _settings.LevelOf(_catalog.Get(knobId));
        return functions.Select(function => Level(knobId, function)).DefaultIfEmpty(ProtectionLevel.Off).Max();
    }

    /// <summary>Native body replacement requires an explicit function boundary
    /// selection in addition to an enabled knob. Merely increasing a global
    /// profile must not opt every discoverable leaf function into rewriting.</summary>
    public bool HasExplicitSelection(string knobId, FunctionDescriptor function)
    {
        if (!IsSelected(function) || Level(knobId, function) == ProtectionLevel.Off)
            return false;
        if (_settings.IncludeSymbols.Count > 0 || _settings.IncludeRvaRanges.Count > 0)
            return true;

        bool explicitlyEnabled = false;
        foreach (ProtectionRule rule in _settings.Rules.Where(rule => Matches(rule, function)))
        {
            // A later preset replaces the earlier per-knob choice. Native body
            // replacement stays opt-in in every preset, including Nuclear.
            if (rule.Preset is not null)
                explicitlyEnabled = false;
            if (rule.Knobs.TryGetValue(knobId, out ProtectionLevel level))
                explicitlyEnabled = level != ProtectionLevel.Off;
        }
        return explicitlyEnabled;
    }

    public IReadOnlyDictionary<string, ProtectionLevel> EffectiveLevels(FunctionDescriptor function) =>
        ProtectionCapabilities.FunctionScopedKnobs
            .Select(id => (Id: id, Level: Level(id, function)))
            .Where(item => item.Level != ProtectionLevel.Off)
            .ToDictionary(item => item.Id, item => item.Level, StringComparer.Ordinal);

    public static bool Matches(ProtectionRule rule, FunctionDescriptor function)
    {
        if (rule.StartRva is uint start && rule.EndRva is uint end && !Overlaps(function, start, end))
            return false;

        return rule.Scope switch
        {
            ProtectionRuleScope.Symbol => Glob(rule.Match, function.Name),
            ProtectionRuleScope.Namespace => Glob(rule.Match, function.Namespace),
            ProtectionRuleScope.Module => Glob(rule.Match, function.Module),
            ProtectionRuleScope.Section => Glob(rule.Match, function.Section),
            ProtectionRuleScope.Source => Glob(rule.Match, function.Source),
            ProtectionRuleScope.Rva => rule.StartRva is uint rvaStart
                && rule.EndRva is uint rvaEnd
                && Overlaps(function, rvaStart, rvaEnd),
            _ => Glob(rule.Match, function.Name)
                || Glob(rule.Match, function.Namespace)
                || Glob(rule.Match, function.Module)
                || Glob(rule.Match, function.Section)
                || Glob(rule.Match, function.Source),
        };
    }

    private static bool Overlaps(FunctionDescriptor function, uint start, uint end) =>
        function.BeginRva < end && function.EndRva > start;

    internal static bool Glob(string pattern, string? value)
    {
        if (value is null)
            return false;
        // Normalize build paths so one policy works with MSVC backslashes,
        // GNU MAP forward slashes, and JSON produced on either host OS.
        string normalizedPattern = pattern.Replace('\\', '/');
        string normalizedValue = value.Replace('\\', '/');
        Regex compiled = GlobCache.GetOrAdd(normalizedPattern, static p =>
        {
            string regex = "^" + Regex.Escape(p)
                .Replace("\\*", ".*", StringComparison.Ordinal)
                .Replace("\\?", ".", StringComparison.Ordinal) + "$";
            return new Regex(regex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled,
                TimeSpan.FromMilliseconds(250));
        });
        return compiled.IsMatch(normalizedValue);
    }
}
