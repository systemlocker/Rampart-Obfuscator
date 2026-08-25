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

        void RunAndRecord(Action action, params string[] knobs)
        {
            byte[] before = pe.ToBytes();
            action();
            if (before.AsSpan().SequenceEqual(pe.ToBytes()))
                return;
            foreach (string knob in knobs)
                ctx.MarkApplied(knob);
        }

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
        RunAndRecord(() => new VirtualizationPass().Run(ctx), "virtualization.per-build-isa");
        new CodeTransformPass().Run(ctx);         // junk / MBA / flattening / nanomites
        RunAndRecord(() => new IdaBombPass().Run(ctx), "analysis.ida-bomb");
        RunAndRecord(() => new HexRaysDenialPass().Run(ctx), "analysis.hexrays-denial");
        RunAndRecord(() => new SymbolicDenialPass().Run(ctx), "analysis.symbolic-denial");
        RunAndRecord(() => new StaticDecodeDenialPass().Run(ctx), "analysis.static-decode-denial");
        new StringProtectionPass().Run(ctx);      // encrypt strings, register decryptor init
        RunAndRecord(() => new ApiConcealmentPass().Run(ctx), "memory.api-concealment");
        new ImportConcealmentPass().Run(ctx);     // hash-resolved IAT, register resolver init
        RunAndRecord(() => new AntiDebugPass().Run(ctx),
            "anti-debug.channel-sweep", "anti-debug.inline-hook-check",
            "anti-debug.veh-tamper", "anti-debug.dll-notify");
        RunAndRecord(() => new AntiSandboxPass().Run(ctx),
            "anti-sandbox.virtualisation-detect", "anti-sandbox.fingerprint-suite",
            "anti-sandbox.human-gate");
        RunAndRecord(() => new InjectionHunterPass().Run(ctx), "nuclear.injection-hunter");
        RunAndRecord(() => new HiddenThreadsPass().Run(ctx), "integrity.hidden-threads");
        RunAndRecord(() => new SymbolScrubPass().Run(ctx), "packaging.symbol-scrub");
        RunAndRecord(() => new HeaderDisguisePass().Run(ctx), "packaging.header-disguise");
        var runtimeHardening = new RuntimeHardeningPass();
        RunAndRecord(() => runtimeHardening.RunBeforeEntryPoint(ctx),
            "anti-inject.dacl-hardening", "anti-inject.cet-shadow-stack",
            "anti-inject.dynamic-code-policy", "anti-inject.iat-hash-check",
            "integrity.kernel-wall", "integrity.measurement-channels",
            "integrity.tls-veh-ownership", "integrity.mitigation-stack",
            "response.silent-taint", "response.tool-response",
            "response.brand-overlay", "response.custom-messages");
        RunAndRecord(() => new RuntimeHeaderProtectionPass().Run(ctx),
            "analysis.runtime-header-corruption", "memory.anti-dump", "integrity.header-scrub");
        RunAndRecord(() => new EntryPointPass().Run(ctx), "packaging.ep-confusion");
        runtimeHardening.RunAfterEntryPoint(ctx);      // outer TLS monitor after dispatcher exists

        RelocBuilder.Rebuild(ctx);

        byte[] output = pe.ToBytes();
        string inputSha256 = Convert.ToHexString(SHA256.HashData(input));
        string outputSha256 = Convert.ToHexString(SHA256.HashData(output));
        if (!input.AsSpan().SequenceEqual(output)
            && ctx.MaximumFunctionLevel("code-transformation.per-build-mutation") != ProtectionLevel.Off)
            ctx.MarkApplied("code-transformation.per-build-mutation");

        var applied = ctx.Applied
            .OrderBy(item => item.Key, StringComparer.Ordinal)
            .ToDictionary(item => item.Key, item => item.Value, StringComparer.Ordinal);
        int budget = applied.Sum(item => catalog.Get(item.Key).PointsAt(item.Value));

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
