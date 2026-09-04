namespace Rampart.Config;

/// <summary>Configuration metadata, including disabled compatibility identifiers.
/// Use <see cref="ProtectionCapabilities"/> to determine supported options.</summary>
public sealed class KnobCatalog
{
    private readonly Dictionary<string, KnobDef> _byId;
    private readonly List<KnobDef> _ordered;

    public KnobCatalog(IEnumerable<KnobDef> knobs)
    {
        _ordered = knobs.ToList();
        _byId = _ordered.ToDictionary(k => k.Id, StringComparer.Ordinal);
        foreach (var group in _ordered.Select(k => k.Group).Distinct())
        {
            if (!KnobGroups.All.Contains(group))
                throw new ArgumentException($"Knob group '{group}' is not one of KnobGroups.All.");
        }
    }

    public static KnobCatalog Load() => new(KnobCatalogData.Entries);

    public IReadOnlyList<KnobDef> All => _ordered;

    public KnobDef Get(string id) =>
        _byId.TryGetValue(id, out var knob) ? knob
            : throw new KeyNotFoundException($"Unknown knob '{id}'. Run `rampart knobs` for the catalog.");

    public bool TryGet(string id, out KnobDef knob) => _byId.TryGetValue(id, out knob!);

    public IEnumerable<KnobDef> InGroup(string group) =>
        _ordered.Where(k => k.Group == group);

    public int Count => _ordered.Count;

    /// <summary>Total protection-budget points a configuration spends. Rampart
    /// does not gate on budget. The relative total helps compare configurations;
    /// it is not a measurement of runtime cost or protection strength.</summary>
    public static int BudgetFor(ProtectionSettings settings, KnobCatalog catalog) =>
        catalog.All.Sum(k => k.PointsAt(settings.LevelOf(k)));
}
