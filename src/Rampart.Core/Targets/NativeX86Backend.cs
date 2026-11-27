using System.Security.Cryptography;
using Rampart.Config;
using Rampart.Engine;
using Rampart.Engine.Passes;
using Rampart.Pe;

namespace Rampart.Targets;

/// <summary>
/// Native PE32/I386 backend. It deliberately runs only transforms with a Win32
/// implementation; x64 ABI stubs never enter this pipeline.
/// </summary>
internal sealed class NativeX86Backend : IProtectionBackend
{
    public string Name => "native-pe-x86";
    public ProtectionTargetKind Kind => ProtectionTargetKind.NativePeX86;
    public TargetClassification Inspect(byte[] input) => TargetClassifier.Classify(input);

    public ProtectionPlan Plan(byte[] input, ProtectionSettings settings)
    {
        TargetClassification classification = Inspect(input);
        ProtectionPipeline.RequireTarget(classification, settings, Kind);
        ValidateOptions(settings);

        KnobCatalog catalog = KnobCatalog.Load();
        TargetCapabilities.ValidateSettings(settings, catalog, Kind);
        PeCompatibility.ValidateX86(PeImage.Load(input));

        var protections = new List<PlannedProtection>();
        var diagnostics = new List<string>();
        foreach (KnobDef knob in catalog.All)
        {
            ProtectionLevel requested = RequestedLevel(settings, knob);
            ProtectionLevel maximum = TargetCapabilities.MaximumLevel(knob.Id, Kind);
            ProtectionLevel effective = (ProtectionLevel)Math.Min((int)requested, (int)maximum);
            string reason = requested == effective ? "RP_X86_POLICY" : "RP_X86_CAPABILITY";
            protections.Add(new(knob.Id, requested.ToString(), effective.ToString(), reason));
            if (requested != ProtectionLevel.Off && effective == ProtectionLevel.Off)
                diagnostics.Add($"{knob.Id}: RP_X86_CAPABILITY");
        }
        return new(classification, Name, protections, diagnostics);
    }

    public BackendProtectionResult Protect(byte[] input, ProtectionSettings settings, byte[]? symbols = null)
    {
        ProtectionPlan plan = Plan(input, settings);
        KnobCatalog catalog = KnobCatalog.Load();
        ProtectionSettings effective = ResolveSettings(settings, catalog);
        PeImage pe = PeImage.Load(input);
        PeCompatibility.ValidateX86(pe);
        var context = new BuildContext(pe, effective, catalog);
        PeCompatibilityFeatures features = PeCompatibility.Inspect(pe);
        context.Log.Add(new("analyze", $"admitted native PE32/I386 executable; {features.Summary}"));

        void RunAndRecord(Action action, params string[] knobs)
        {
            byte[] before = pe.ToBytes();
            action();
            if (before.AsSpan().SequenceEqual(pe.ToBytes()))
                return;
            foreach (string knob in knobs)
                context.MarkApplied(knob);
        }

        DataDirectory certificate = pe.Directory(DataDir.Security);
        if (!certificate.IsEmpty)
        {
            pe.SetDirectory(DataDir.Security, 0, 0);
            context.Log.Add(new("authenticode",
                "cleared the invalidated certificate directory; sign the protected output after Rampart"));
        }

        RunAndRecord(() => new IdaBombPass().Run(context), "analysis.ida-bomb");
        RunAndRecord(() => new HexRaysDenialPass().Run(context), "analysis.hexrays-denial");
        RunAndRecord(() => new SymbolicDenialPass().Run(context), "analysis.symbolic-denial");
        RunAndRecord(() => new StaticDecodeDenialPass().Run(context), "analysis.static-decode-denial");
        RunAndRecord(() => new SymbolScrubPass().Run(context), "packaging.symbol-scrub");
        RunAndRecord(() => new HeaderDisguisePass().Run(context), "packaging.header-disguise");
        RunAndRecord(() => new X86EntryPointPass().Run(context), "packaging.ep-confusion");

        byte[] output = pe.ToBytes();
        if (context.Level("packaging.header-disguise") == ProtectionLevel.Maximum)
        {
            pe.Checksum = PeChecksum.Compute(output);
            output = pe.ToBytes();
            context.Log.Add(new("header-disguise", $"computed final PE checksum {pe.Checksum:X8}"));
        }

        string inputSha256 = Convert.ToHexString(SHA256.HashData(input));
        string outputSha256 = Convert.ToHexString(SHA256.HashData(output));
        var applied = context.Applied.OrderBy(item => item.Key, StringComparer.Ordinal)
            .ToDictionary(item => item.Key, item => item.Value, StringComparer.Ordinal);
        int budget = applied.Sum(item => catalog.Get(item.Key).PointsAt(item.Value));
        context.Log.Add(new("done", $"{input.Length} -> {output.Length} bytes, {applied.Count} x86 knobs active, budget {budget}"));

        var evidence = new List<ProtectionEvidence>();
        var subject = new ProtectionSubject("image");
        foreach (PlannedProtection protection in plan.Protections.Where(item => item.Effective != nameof(ProtectionLevel.Off)))
        {
            bool changed = applied.TryGetValue(protection.Id, out ProtectionLevel level) && level != ProtectionLevel.Off;
            evidence.Add(new(protection.Id, subject, subject, protection.Requested,
                changed ? EvidenceDisposition.Applied : EvidenceDisposition.Skipped,
                changed ? "RP_APPLIED" : "RP_X86_NO_ELIGIBLE_DATA", input.Length, output.Length));
        }

        var privateMap = new ProtectedSymbolMap
        {
            Seed = settings.Seed,
            ImageBase = pe.ImageBase,
            InputSha256 = inputSha256,
            OutputSha256 = outputSha256,
            Functions = [],
        };
        return new BackendProtectionResult
        {
            Output = output,
            Symbols = symbols,
            Plan = plan,
            Evidence = evidence,
            PrivateMap = privateMap,
            InputSha256 = inputSha256,
            OutputSha256 = outputSha256,
            Seed = settings.Seed,
            InputSize = input.Length,
            Details = new NativeX86ProtectionDetails(applied, context.Log, budget),
        };
    }

    public void Validate(byte[] original, BackendProtectionResult result)
    {
        PeImage output = PeImage.Load(result.Output);
        if (output.Machine != MachineType.I386 || output.OptionalMagic != PeImage.MagicPe32
            || (output.Characteristics & 0x2000) != 0 || !output.Directory(DataDir.ComDescriptor).IsEmpty)
        {
            throw new BadImageFormatException("RP_X86_OUTPUT: Output no longer satisfies the native PE32/I386 contract.");
        }
        _ = PeCompatibility.Inspect(output);
        if (output.EntryPointRva == 0 || output.SectionFromRva(output.EntryPointRva) is not { IsExecutable: true })
            throw new BadImageFormatException("RP_X86_OUTPUT: Protected entry point is not executable.");
    }

    public IReadOnlyList<ProtectionEvidence> DescribeEvidence(BackendProtectionResult result) => result.Evidence;

    private static ProtectionSettings ResolveSettings(ProtectionSettings settings, KnobCatalog catalog)
    {
        ProtectionSettings copy = ProtectionSettingsJson.Deserialize(ProtectionSettingsJson.Serialize(settings));
        foreach (KnobDef knob in catalog.All)
        {
            ProtectionLevel requested = RequestedLevel(settings, knob);
            ProtectionLevel maximum = TargetCapabilities.MaximumLevel(knob.Id, ProtectionTargetKind.NativePeX86);
            copy.Knobs[knob.Id] = (ProtectionLevel)Math.Min((int)requested, (int)maximum);
        }
        return copy;
    }

    private static ProtectionLevel RequestedLevel(ProtectionSettings settings, KnobDef knob) =>
        settings.Knobs.TryGetValue(knob.Id, out ProtectionLevel explicitLevel)
            ? explicitLevel
            : Presets.DefaultLevel(settings.Preset, knob);

    private static void ValidateOptions(ProtectionSettings settings)
    {
        if (settings.Targets?.Managed is not null || settings.Targets?.NativeAot is not null)
            throw new NotSupportedException("RP_TARGET_OPTIONS_MISMATCH: Managed or NativeAOT options do not apply to native x86.");
        if (settings.SymbolSources.Count != 0 || settings.PdbTool is not null
            || settings.IncludeSymbols.Count != 0 || settings.ExcludeSymbols.Count != 0
            || settings.IncludeRvaRanges.Count != 0 || settings.Rules.Count != 0)
        {
            throw new NotSupportedException("RP_X86_SELECTORS_UNSUPPORTED: Native x86 currently accepts image-level protections only.");
        }
        if (settings.ThreatFocus.Count != 0 || settings.Watermark is not null || settings.CustomMessage is not null)
            throw new NotSupportedException("RP_X86_OPTIONS_UNSUPPORTED: Threat dials, watermarks, and custom runtime messages require runtime stubs unavailable on x86.");
    }

    private sealed record NativeX86ProtectionDetails(
        IReadOnlyDictionary<string, ProtectionLevel> Applied,
        IReadOnlyList<BuildLogEntry> Log,
        int BudgetPoints);
}
