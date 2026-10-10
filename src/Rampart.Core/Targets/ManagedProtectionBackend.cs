using System.Text.Json;
using Rampart.Config;
using Rampart.Managed;

namespace Rampart.Targets;

public sealed class ManagedProtectionBackend : IProtectionBackend
{
    public string Name => "managed-il";
    public ProtectionTargetKind Kind => ProtectionTargetKind.ManagedIl;
    public TargetClassification Inspect(byte[] input) => TargetClassifier.Classify(input);

    public ProtectionPlan Plan(byte[] input, ProtectionSettings settings)
    {
        var classification = Inspect(input);
        ProtectionPipeline.RequireTarget(classification, settings, Kind);
        ManagedProtectionOptions options = ResolveOptions(settings);
        ManagedBackend.ValidateInput(input, options);
        var protections = new List<PlannedProtection>();
        void Add(string name, bool value) => protections.Add(new("managed." + name, value ? "Light" : "Off", value ? "Light" : "Off", "RP_MANAGED_POLICY"));
        Add("strings", options.Strings); Add("constants", options.Constants);
        Add("metadata-hygiene", options.MetadataHygiene); Add("integrity", options.Integrity);
        Add("rename", options.RenamePrivateMembers); Add("control-flow", options.ControlFlow);
        Add("virtualize", options.Virtualize); Add("watermark", options.Watermark is not null);
        if (options.HardenedRuntime) Add("hardened-runtime", true);
        return new(classification, Name, protections, []);
    }

    public BackendProtectionResult Protect(byte[] input, ProtectionSettings settings, byte[]? symbols = null)
    {
        var plan = Plan(input, settings);
        var result = new ManagedBackend().Protect(input, ResolveOptions(settings), settings.Seed, symbols);
        return Adapt(input, settings, plan, result);
    }

    public static BackendProtectionResult Adapt(byte[] input, ProtectionSettings settings, ProtectionPlan plan, ManagedProtectionResult result)
    {
        var evidence = new List<ProtectionEvidence>();
        foreach (var method in result.Evidence)
        {
            var original = new ProtectionSubject(method.Original.StableId, method.Original.Assembly,
                method.Original.Module, method.Original.Type, method.Original.Signature, method.Original.MetadataToken);
            var updated = original with { Signature = method.ProtectedName, MetadataToken = method.ProtectedToken };
            foreach (string applied in method.Applied)
                evidence.Add(new(applied, original, updated, "Light", EvidenceDisposition.Applied, "RP_APPLIED",
                    OriginalSize: method.OriginalIlSize, ProtectedSize: method.ProtectedIlSize,
                    OriginalHash: method.OriginalHash, ProtectedHash: method.ProtectedHash, VerificationStatus: method.VerificationStatus));
            foreach (string skipped in method.Skipped.Except(method.Rejected, StringComparer.Ordinal))
                evidence.Add(new(skipped.Split(':')[0], original, updated, "Light", EvidenceDisposition.Skipped, skipped,
                    OriginalSize: method.OriginalIlSize, ProtectedSize: method.ProtectedIlSize,
                    OriginalHash: method.OriginalHash, ProtectedHash: method.ProtectedHash, VerificationStatus: method.VerificationStatus));
            foreach (string rejected in method.Rejected)
                evidence.Add(new(rejected.Split(':')[0], original, updated, "Light", EvidenceDisposition.Rejected, rejected,
                    OriginalSize: method.OriginalIlSize, ProtectedSize: method.ProtectedIlSize,
                    OriginalHash: method.OriginalHash, ProtectedHash: method.ProtectedHash, VerificationStatus: method.VerificationStatus));
        }
        return new()
        {
            Output = result.Output,
            Symbols = result.PdbOutput,
            Plan = plan with { Diagnostics = result.Diagnostics },
            Evidence = evidence,
            PrivateMap = new
            {
                SchemaVersion = 1,
                settings.Seed,
                result.InputSha256,
                result.OutputSha256,
                result.TokenMap,
                Methods = result.Evidence,
                result.IdentifierRenames,
                result.Diagnostics,
                result.Verification,
                result.Coverage
            },
            InputSha256 = result.InputSha256,
            OutputSha256 = result.OutputSha256,
            InputSize = input.Length,
            Seed = settings.Seed,
        };
    }

    public static ManagedProtectionOptions ResolveOptions(ProtectionSettings settings)
    {
        settings.Targets?.Validate();
        // The default value comes from the legacy settings model and does not
        // enable managed work. CLI/build callers also reject its explicit use.
        if (!string.Equals(settings.Preset, Presets.Balanced, StringComparison.Ordinal))
            throw new NotSupportedException("RP_MANAGED_PRESET_UNSUPPORTED: Native presets do not apply to managed IL. Select managed protections explicitly.");
        if (settings.Targets?.NativeAot is not null)
            throw new NotSupportedException("RP_TARGET_OPTIONS_MISMATCH: NativeAOT options require a published native executable.");
        if (settings.IncludeRvaRanges.Count != 0 || settings.Rules.Any(r => r.Scope is ProtectionRuleScope.Rva or ProtectionRuleScope.Section))
            throw new NotSupportedException("RP_MANAGED_NATIVE_SELECTOR: RVA and section selectors apply only to native code.");
        if (settings.SymbolSources.Count != 0 || settings.PdbTool is not null || settings.ThreatFocus.Count != 0)
            throw new NotSupportedException("RP_MANAGED_NATIVE_OPTIONS: Native symbol sources and threat dials do not apply to managed IL.");
        var options = settings.Targets?.Managed is { } source
            ? JsonSerializer.Deserialize<ManagedProtectionOptions>(JsonSerializer.Serialize(source, ProtectionSettingsJson.Options), ProtectionSettingsJson.Options)!
            : new ManagedProtectionOptions();
        options.StrictCompatibility |= settings.Targets?.Compatibility == CompatibilityPolicy.Strict;
        options.Watermark ??= settings.Watermark;
        foreach (var knob in settings.Knobs.Where(k => k.Value != ProtectionLevel.Off))
        {
            if (knob.Value != ProtectionLevel.Light)
                throw new NotSupportedException("RP_MANAGED_LEVEL: Managed protections currently accept Light only.");
            switch (knob.Key)
            {
                case "strings.encryption": options.Strings = true; break;
                case "code-transformation.mba-constants": options.Constants = true; break;
                case "code-transformation.flattening": options.ControlFlow = true; break;
                case "packaging.symbol-scrub": options.MetadataHygiene = true; break;
                case "virtualization.coverage" or "virtualization.per-build-isa": options.Virtualize = true; break;
                default: throw new NotSupportedException($"RP_TARGET_KNOB_UNSUPPORTED: '{knob.Key}' does not apply to managed IL.");
            }
        }

        var rules = new List<ManagedMethodRule>();
        if (settings.IncludeSymbols.Count != 0)
        {
            rules.Add(new() { Include = false });
            rules.AddRange(settings.IncludeSymbols.Select(pattern => new ManagedMethodRule { Method = pattern, Include = true }));
        }
        rules.AddRange(options.Rules);
        foreach (var rule in settings.Rules)
        {
            var managed = new ManagedMethodRule();
            switch (rule.Scope)
            {
                case ProtectionRuleScope.Any or ProtectionRuleScope.Symbol: managed.Method = rule.Match; break;
                case ProtectionRuleScope.Namespace: managed.Namespace = rule.Match; break;
                case ProtectionRuleScope.Module: managed.Module = rule.Match; break;
                case ProtectionRuleScope.Source: managed.SourceDocument = rule.Match; break;
                default: throw new NotSupportedException("RP_MANAGED_SELECTOR: Unsupported managed selector.");
            }
            if (rule.Preset is not null)
            {
                if (!string.Equals(rule.Preset, "off", StringComparison.OrdinalIgnoreCase))
                    throw new NotSupportedException("RP_MANAGED_PRESET_UNSUPPORTED: Native method presets do not apply to managed IL. Use explicit managed rules or off.");
                managed.Strings = false; managed.Constants = false; managed.ControlFlow = false;
                managed.RenamePrivateMembers = false; managed.Virtualize = false;
            }
            foreach (var knob in rule.Knobs)
            {
                if (knob.Value > ProtectionLevel.Light)
                    throw new NotSupportedException("RP_MANAGED_LEVEL: Managed rules currently accept Light or Off only.");
                bool enabled = knob.Value != ProtectionLevel.Off;
                switch (knob.Key)
                {
                    case "strings.encryption": managed.Strings = enabled; break;
                    case "code-transformation.mba-constants": managed.Constants = enabled; break;
                    case "code-transformation.flattening": managed.ControlFlow = enabled; break;
                    case "virtualization.coverage" or "virtualization.per-build-isa": managed.Virtualize = enabled; break;
                    default: throw new NotSupportedException($"RP_TARGET_KNOB_UNSUPPORTED: '{knob.Key}' does not apply to a managed method.");
                }
            }
            rules.Add(managed);
        }
        rules.AddRange(settings.ExcludeSymbols.Select(pattern => new ManagedMethodRule { Method = pattern, Include = false }));
        options.Rules = rules;
        return options;
    }

    public void Validate(byte[] original, BackendProtectionResult result)
    {
        ManagedBackend.ValidateInput(result.Output, new ManagedProtectionOptions { MaximumInputBytes = 268435456 });
        var classification = Inspect(result.Output);
        if (classification.Target.Kind is not (ProtectionTargetKind.ManagedIl or ProtectionTargetKind.AlreadyProtected))
            throw new BadImageFormatException("RP_MANAGED_OUTPUT: Output is no longer a pure-IL assembly.");
    }

    public IReadOnlyList<ProtectionEvidence> DescribeEvidence(BackendProtectionResult result) => result.Evidence;
}
