using System.Text.Json;
using Rampart.Config;
using Rampart.Targets;

namespace Rampart.Cli;

internal static class CheckCommand
{
    public static int Run(string[] args)
    {
        if (args.Contains("--help", StringComparer.Ordinal))
        {
            Console.WriteLine("usage: rampart check [--config <file>] [--preset <name>] [--set <id>=<level>] [--only <ids>] [--disable <ids>] [--group-level <group>=<level>] [--focus <tags>] [--symbols <file>] [--include-symbol <glob>] [--exclude-symbol <glob>] [--rva-range <start-end>] [--function-profile <glob>=<preset>] [--json]");
            return 0;
        }

        var catalog = KnobCatalog.Load();
        var settingsArgs = new SettingsArguments();
        for (int i = 0; i < args.Length; i++)
        {
            if (!settingsArgs.TryConsume(args, ref i))
                throw new ArgumentException($"Unknown option '{args[i]}'.");
        }

        var settings = settingsArgs.Build(catalog);
        bool native = (settings.Targets?.Override ?? ProtectionTargetKind.NativePe) == ProtectionTargetKind.NativePe;
        if (native) ThreatDials.Apply(settings, catalog);
        if (settings.Targets?.Override == ProtectionTargetKind.ManagedIl) _ = ManagedProtectionBackend.ResolveOptions(settings);
        var concerns = native ? ConcernRules.Evaluate(settings, catalog) : new List<Concern>();
        int budget = native ? KnobCatalog.BudgetFor(settings, catalog) : 0;

        if (settingsArgs.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                Valid = true,
                Settings = SettingsArguments.SettingsPayload(settings, settings.Targets?.Override ?? ProtectionTargetKind.NativePe),
                BudgetPoints = budget,
                Concerns = concerns,
            }, ProtectionSettingsJson.Options));
        }
        else
        {
            Console.WriteLine($"configuration valid: {budget} points, {concerns.Count} concern(s)");
            ProtectCommand.PrintConcerns(concerns);
        }
        return concerns.Any(c => c.Severity == ConcernSeverity.Risky) ? 3 : 0;
    }
}

internal static class KnobsCommand
{
    public static int Run(string[] args)
    {
        if (args.Contains("--help", StringComparer.Ordinal))
        {
            Console.WriteLine("usage: rampart knobs [--group <name>] [--json]");
            return 0;
        }

        string? group = null;
        bool json = false;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--group":
                    group = SettingsArguments.RequireValue(args, ref i, args[i]);
                    break;
                case "--ready":
                    // Retain the earlier filter flag as an alias for the default.
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown option '{args[i]}'.");
            }
        }

        var catalog = KnobCatalog.Load();
        if (group is not null && !KnobGroups.All.Contains(group, StringComparer.Ordinal))
            throw new ArgumentException($"Unknown group '{group}'. Valid: {string.Join(", ", KnobGroups.All)}.");
        IEnumerable<KnobDef> query = group is null ? catalog.All : catalog.InGroup(group);
        query = query.Where(k => ProtectionCapabilities.IsReady(k.Id));
        var knobs = query.Select(k => new
        {
            k.Id,
            k.Group,
            k.Name,
            k.Summary,
            Status = $"supported through {ProtectionCapabilities.MaxReadyLevel(k.Id).DisplayName()}",
            k.Tags,
            k.Points,
        }).ToList();

        if (json)
        {
            Console.WriteLine(JsonSerializer.Serialize(knobs, ProtectionSettingsJson.Options));
            return 0;
        }

        foreach (var grouped in knobs.GroupBy(k => k.Group))
        {
            Console.WriteLine(KnobGroups.Title(grouped.Key));
            foreach (var knob in grouped)
                Console.WriteLine($"  [{knob.Status,-22}] {knob.Id,-42} {knob.Name}");
        }
        return 0;
    }
}

internal static class ExplainCommand
{
    public static int Run(string[] args)
    {
        if (args.Length != 1 || args[0] == "--help")
        {
            Console.WriteLine("usage: rampart explain <knob-id>");
            return args.Length == 1 ? 0 : 2;
        }

        var knob = KnobCatalog.Load().Get(args[0]);
        var maxReady = ProtectionCapabilities.MaxReadyLevel(knob.Id);
        if (maxReady == ProtectionLevel.Off)
            throw new NotSupportedException($"Protection option '{knob.Id}' is not supported. Run `rampart knobs` for supported options.");
        string status = $"supported through {maxReady.DisplayName()}";
        Console.WriteLine($"{knob.Name} ({knob.Id})");
        Console.WriteLine($"status: {status}");
        Console.WriteLine(knob.Summary);
        Console.WriteLine();
        for (var level = ProtectionLevel.Light; level <= maxReady; level++)
        {
            Console.WriteLine($"{level.DisplayName(),-9} {knob.PointsAt(level),2} point(s)  {knob.LevelText(level)}");
        }
        return 0;
    }
}
