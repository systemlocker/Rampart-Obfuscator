using System.Security.Cryptography;
using Rampart.Config;
using Rampart.Pe;
using Rampart.Engine.Passes;
using Rampart.Symbols;

namespace Rampart.Engine;

public sealed class ProtectionResult
{
    public required byte[] Output { get; init; }
    public required List<BuildLogEntry> Log { get; init; }
    public required Dictionary<string, ProtectionLevel> Applied { get; init; }
    public required int BudgetPoints { get; init; }
    public required List<Concern> Concerns { get; init; }
    public required long Seed { get; init; }
    public required int InputSize { get; init; }
    public required int OutputSize { get; init; }
    public required string InputSha256 { get; init; }
    public required string OutputSha256 { get; init; }
    public required ProtectedSymbolMap SymbolMap { get; init; }
}

/// <summary>The build pipeline. Pass order is deliberate: code transforms run on
/// the original layout first, data transforms (strings, imports) patch references
/// after, runtime pieces register init routines, the entry-point pass wires the
/// dispatcher last, and relocations are rebuilt once every pointer slot exists.</summary>
public sealed class Protector
{
    public ProtectionResult Protect(
        byte[] input,
        ProtectionSettings settings,
        KnobCatalog? catalog = null,
        IReadOnlyList<SymbolRecord>? symbols = null)
    {
        catalog ??= KnobCatalog.Load();

        ProtectionCapabilities.Validate(settings, catalog);

        // Threat dials bump knobs before anything reads levels.
        ThreatDials.Apply(settings, catalog);
        var concerns = ConcernRules.Evaluate(settings, catalog);

        var pe = PeImage.Load(input);
        PeCompatibility.Validate(pe);

        var ctx = new BuildContext(pe, settings, catalog, symbols);
        ctx.Analyze();

        var certificateDirectory = pe.Directory(DataDir.Security);
        if (!certificateDirectory.IsEmpty)
        {
            // Authenticode covers the file bytes and is invalid after any
            // transform. Keep overlay data, but remove the stale directory so
            // callers can sign the completed output normally.
            pe.SetDirectory(DataDir.Security, 0, 0);
            ctx.Log.Add(new("authenticode",
                "cleared the invalidated certificate directory; sign the protected output after Rampart"));
        }

        // --- passes, in order ---------------------------------------------------
        new VirtualizationPass().Run(ctx);        // lift before any code rewriting
        new CodeTransformPass().Run(ctx);         // junk / MBA / flattening / nanomites
        new StringProtectionPass().Run(ctx);      // encrypt strings, register decryptor init
        new ImportConcealmentPass().Run(ctx);     // hash-resolved IAT, register resolver init
        new GuardStubsPass().Run(ctx);            // anti-debug/anti-inject/sandbox, mitigations
        new SymbolScrubPass().Run(ctx);
        new HeaderDisguisePass().Run(ctx);             // disguise after scrub so decoys survive
        new EntryPointPass().Run(ctx);            // dispatcher + gem + TLS wiring

        RelocBuilder.Rebuild(ctx);

        byte[] output = pe.ToBytes();
        string inputSha256 = Convert.ToHexString(SHA256.HashData(input));
        string outputSha256 = Convert.ToHexString(SHA256.HashData(output));
        int budget = KnobCatalog.BudgetFor(settings, catalog);

        var applied = catalog.All
            .Select(knob => new
            {
                Knob = knob,
                Level = ProtectionCapabilities.FunctionScopedKnobs.Contains(knob.Id)
                    ? ctx.MaximumFunctionLevel(knob.Id)
                    : settings.LevelOf(knob),
            })
            .Where(item => item.Level != ProtectionLevel.Off)
            .ToDictionary(item => item.Knob.Id, item => item.Level);

        ctx.Log.Add(new("done",
            $"{input.Length} → {output.Length} bytes, {applied.Count} knobs active, budget {budget}"));

        return new ProtectionResult
        {
            Output = output,
            Log = ctx.Log,
            Applied = applied,
            BudgetPoints = budget,
            Concerns = concerns,
            Seed = settings.Seed,
            InputSize = input.Length,
            OutputSize = output.Length,
            InputSha256 = inputSha256,
            OutputSha256 = outputSha256,
            SymbolMap = new ProtectedSymbolMap
            {
                Seed = settings.Seed,
                ImageBase = pe.ImageBase,
                InputSha256 = inputSha256,
                OutputSha256 = outputSha256,
                Functions = ctx.Functions.Select(function => new ProtectedSymbolMapEntry
                {
                    Name = function.Name,
                    Namespace = string.IsNullOrEmpty(function.Namespace) ? null : function.Namespace,
                    Module = function.Module,
                    Section = function.Section,
                    Source = function.Source,
                    OriginalRva = function.BeginRva,
                    // Current ready transforms preserve original function RVAs.
                    // Separate fields keep this sidecar compatible with later
                    // relocation and virtualization emitters.
                    ProtectedRva = function.BeginRva,
                    Size = function.Size,
                    Applied = ctx.FunctionPolicy.EffectiveLevels(function),
                }).ToList(),
            },
        };
    }
}
