using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Rampart.Config;
using MethodDefinition = Mono.Cecil.MethodDefinition;
using TypeDefinition = Mono.Cecil.TypeDefinition;
using ModuleDefinition = Mono.Cecil.ModuleDefinition;

namespace Rampart.Managed;

/// <summary>Pure-IL protection with in-memory validation before the caller promotes output.</summary>
public sealed class ManagedBackend
{
    public static void ValidateInput(byte[] input, ManagedProtectionOptions options) => ManagedPreflight.Validate(input, options);

    public ManagedProtectionResult Protect(byte[] input, ManagedProtectionOptions options, long seed, byte[]? portablePdb = null)
    {
        ArgumentNullException.ThrowIfNull(input); ArgumentNullException.ThrowIfNull(options);
        var timer = Stopwatch.StartNew();
        ManagedPreflight.Validate(input, options);
        if (options.RequireVirtualization && !options.Rules.Any(rule => rule.Virtualize == true))
            ManagedPreflight.Fail("MANAGED_VM_SELECTION_REQUIRED", "Required virtualization needs explicit method selection rules.");
        if (options.MaximumProtectionMilliseconds is < 100 or > 600000 || options.MaximumVmInstructionCount is < 1 or > 65536)
            ManagedPreflight.Fail("MANAGED_LIMITS", "The managed execution budget is outside the supported bounds.");
        var changes = options.Strings || options.Constants || options.MetadataHygiene || options.Integrity
            || options.RenamePrivateMembers || options.ControlFlow || options.Virtualize || options.Watermark is not null || options.RemoveWatermark
            || options.Rules.Any(r => r.Strings == true || r.Constants == true || r.ControlFlow == true || r.RenamePrivateMembers == true || r.Virtualize == true);
        if (portablePdb is not null && portablePdb.Length > options.MaximumInputBytes)
            ManagedPreflight.Fail("MANAGED_SYMBOL_LIMIT", "The symbol file exceeds the configured input limit.");
        if (options.PreserveDebugSymbols && portablePdb is not null && changes && (!portablePdb.AsSpan().StartsWith("BSJB"u8)))
            ManagedPreflight.Fail("MANAGED_WINDOWS_PDB", "Supply portable symbols or explicitly disable symbol preservation.");
        var inputHash = Hash(input);
        using var inputStream = new MemoryStream(input, false);
        using var symbolInput = portablePdb is null ? null : new MemoryStream(portablePdb, false);
        var parameters = new ReaderParameters { ReadingMode = ReadingMode.Deferred, InMemory = true };
        if (options.PreserveDebugSymbols && portablePdb is not null && portablePdb.AsSpan().StartsWith("BSJB"u8))
        { parameters.ReadSymbols = true; parameters.SymbolStream = symbolInput; parameters.SymbolReaderProvider = new PortablePdbReaderProvider(); }
        else if (options.PreserveDebugSymbols && HasEmbeddedPdb(input))
        { parameters.ReadSymbols = true; parameters.SymbolReaderProvider = new ManagedEmbeddedReader(); }
        try
        {
            using var module = ModuleDefinition.ReadModule(inputStream, parameters);
            var watermarkOnly = options.RemoveWatermark && options.Watermark is null && !options.Strings && !options.Constants && !options.MetadataHygiene
                && !options.Integrity && !options.RenamePrivateMembers && !options.ControlFlow && !options.Virtualize && options.Rules.Count == 0;
            if (changes && !watermarkOnly && (module.Types.Any(t => t.Name.StartsWith("<Rampart_", StringComparison.Ordinal))
                || module.Resources.Any(r => r.Name.StartsWith("Rampart.Managed.", StringComparison.Ordinal))))
                ManagedPreflight.Fail("MANAGED_ALREADY_PROTECTED", "This assembly already contains managed protection output.");
            var allMethods = Types(module.Types).SelectMany(t => t.Methods).ToArray();
            var identities = allMethods.ToDictionary(m => m, ManagedPolicy.Identity);
            var originalHashes = allMethods.ToDictionary(m => m, MethodHash);
            var originalSizes = allMethods.ToDictionary(m => m, m => m.HasBody ? m.Body.CodeSize : 0);
            var debugMaps = allMethods.ToDictionary(m => m, m => new ManagedDebugMap(m));
            var originalSites = allMethods.ToDictionary(m => m, m => m.HasBody ? m.Body.Instructions
                .Where(i => i.OpCode.Code == Code.Ldstr || ManagedTransforms.Integer(i, out _))
                .Select(i => (i.Offset, Instruction: i, Protection: i.OpCode.Code == Code.Ldstr ? "strings" : "constants")).ToArray() : []);
            var diagnostics = new List<string>();
            if (allMethods.Any(method => ManagedIlVerifier.VerificationStatus(method).Contains("nominal-verification-required", StringComparison.Ordinal)))
                diagnostics.Add("MANAGED_NOMINAL_VERIFICATION_REQUIRED: Stack-category checks do not resolve complete nominal type contracts. Use an independent verifier with matching reference assemblies.");
            var inputTokens = ManagedTokenMap.OriginalTokens(input);
            var tokenMap = changes ? new ManagedTokenMap(input, module) : null;
            foreach (var method in allMethods) ManagedIlVerifier.Validate(method);
            if (!changes)
                return ManagedVerification.VerifyResult(new ManagedProtectionResult(input.ToArray(), portablePdb?.ToArray(), allMethods.Select(m =>
                    new ManagedMethodEvidence(identities[m], m.MetadataToken.ToInt32(), m.FullName, originalHashes[m], originalHashes[m], null, [], [])
                    {
                        OriginalIlSize = originalSizes[m],
                        ProtectedIlSize = originalSizes[m],
                        SequencePoints = debugMaps[m].Identity(),
                        VerificationStatus = ManagedIlVerifier.VerificationStatus(m),
                        Sites = originalSites[m].Select(site => new ManagedSiteEvidence(identities[m].StableId + ":" + site.Offset,
                            site.Offset, site.Protection, "skipped", "disabled")).ToArray()
                    }).ToArray(),
                    inputTokens.Select(t => new ManagedTokenMapping(t, t)).ToArray(), inputHash, inputHash, diagnostics), options);
            var originalPublicKey = module.Assembly.Name.PublicKey.ToArray();
            var key = ReadSigningKey(module, options);
            var preservedTypes = module.GetTypes().Select(t => t.FullName).ToHashSet(StringComparer.Ordinal);
            var api = PublicApi(module, preservedTypes);
            var references = module.AssemblyReferences.Select(a => a.FullName).Order().ToArray();
            var keeps = ReadKeeps(options);
            var contracts = ManagedContractAnalysis.Analyze(module);
            var constantContracts = ManagedIntrinsicContracts.Constants(allMethods);
            string? SiteReason(Instruction instruction, string protection) => protection == "strings"
                ? contracts.StringReason(instruction) : constantContracts.GetValueOrDefault(instruction);
            if (contracts.Unresolved.Count != 0 && (options.RenamePrivateMembers || options.Rules.Any(rule => rule.RenamePrivateMembers == true)))
            {
                if (options.StrictCompatibility) ManagedPreflight.Fail("MANAGED_REFLECTION_UNRESOLVED", "Renaming cannot prove a dynamic name contract: " + contracts.Unresolved[0]);
                foreach (var reason in contracts.Unresolved) diagnostics.Add("MANAGED_REFLECTION_PRESERVED: " + reason);
            }
            var suffix = Hash(Encoding.UTF8.GetBytes(inputHash + "|" + seed))[..16];
            var renaming = new ManagedRenaming(module, contracts, keeps);
            if (options.RenamePrivateMembers) renaming.Apply(seed);
            var resourceName = "Rampart.Managed.Payload." + suffix;
            TypeDefinition? helper = null;
            if (options.Strings || options.Integrity || options.Virtualize || options.Rules.Any(r => r.Strings == true || r.Virtualize == true))
            {
                var framework = RequireHelperRuntime(module);
                if (framework && options.HardenedRuntime)
                    ManagedPreflight.Fail("MANAGED_HARDENED_RUNTIME_UNSUPPORTED", "Hardened runtime protection requires modern .NET.");
                helper = ManagedHelperInjector.Inject(module, suffix, framework, options.HardenedRuntime);
                if (options.HardenedRuntime)
                    diagnostics.Add("MANAGED_HARDENED_RUNTIME: Payloads use AES-256-CBC with HMAC-SHA256; selected VM methods use independent dispatch layouts. Decoding keys ship with the application.");
            }
            using var payload = new MemoryStream();
            var counts = new int[options.Rules.Count];
            var generatedRuleHits = new bool[options.Rules.Count]; var boundaryRuleHits = new bool[options.Rules.Count];
            var work = new List<(MethodDefinition Method, List<string> Applied, List<string> Skipped, string? Owner, string[] Requested)>();
            foreach (var method in allMethods)
            {
                var applied = new List<string>(); var skipped = new List<string>(); string? owner = null;
                var identity = identities[method];
                var beforeCounts = counts.ToArray();
                var selection = ManagedPolicy.Select(identity, options, counts);
                for (var rule = 0; rule < counts.Length; rule++)
                    if (counts[rule] != beforeCounts[rule])
                    {
                        generatedRuleHits[rule] |= identity.GeneratedCode && options.Rules[rule].GeneratedCode is null;
                        boundaryRuleHits[rule] |= method.IsPublic || method.IsFamily || method.IsFamilyOrAssembly;
                    }
                if (!selection.Included) skipped.Add("policy:excluded");
                else if (!method.HasBody) skipped.Add("body:absent");
                else
                {
                    if (selection.Vm)
                    {
                        bool transformed = method.Body.Instructions.Count <= options.MaximumVmInstructionCount
                            && (options.HardenedRuntime
                                ? ManagedHardenedTransforms.Virtualize(method, helper!.Methods.Single(m => m.Name == "Interpret"),
                                    helper.Methods.Single(m => m.Name == "Decode"), payload, resourceName, seed, identity.StableId)
                                : ManagedTransforms.Virtualize(method, helper!.Methods.Single(m => m.Name == "Interpret"), seed, identity.StableId));
                        if (transformed)
                        { applied.Add("virtualize"); owner = options.HardenedRuntime ? "managed-hardened-vm" : "managed-vm"; }
                        else skipped.Add("virtualize:outside-int32-subset");
                    }
                    else if (options.Virtualize) skipped.Add("virtualize:explicit-selection-required");
                    // The VM owns its complete body; the IL pipeline composes string and integer
                    // substitutions before CFG permutation, all with unchanged edge stack types.
                    if (owner is null)
                    {
                        if (selection.Constants)
                        {
                            var reasons = originalSites[method].Where(site => site.Protection == "constants")
                                .Select(site => constantContracts.GetValueOrDefault(site.Instruction)).OfType<string>().Distinct(StringComparer.Ordinal).ToArray();
                            skipped.AddRange(reasons);
                            var count = ManagedTransforms.Constants(method, seed, identity.StableId, instruction => !constantContracts.ContainsKey(instruction));
                            if (count > 0) applied.Add("constants:" + count); else if (reasons.Length == 0) skipped.Add("constants:no-sites");
                        }
                        if (selection.Strings)
                        {
                            var reasons = originalSites[method].Where(site => site.Protection == "strings")
                                .Select(site => contracts.StringReason(site.Instruction)).OfType<string>().Distinct(StringComparer.Ordinal).ToArray();
                            skipped.AddRange(reasons);
                            var decoder = helper!.Methods.Single(candidate => candidate.Name == "Decode");
                            var count = options.HardenedRuntime
                                ? ManagedHardenedTransforms.Strings(method, decoder, payload, resourceName, seed, identity.StableId,
                                    instruction => contracts.StringReason(instruction) is null)
                                : ManagedTransforms.Strings(method, decoder, payload, resourceName, seed, identity.StableId,
                                    instruction => contracts.StringReason(instruction) is null);
                            if (count > 0) applied.Add("strings:" + count); else if (reasons.Length == 0) skipped.Add("strings:no-sites");
                        }
                        if (selection.ControlFlow)
                        { if (ManagedTransforms.ControlFlow(method, seed, identity.StableId)) applied.Add("control-flow"); else skipped.Add("control-flow:outside-stack-neutral-subset"); }
                        if (applied.Count > 0) owner = "managed-il";
                    }
                    if (selection.Rename)
                    {
                        if (renaming.MethodReason(method, identity) is not { } reason)
                        { renaming.RenameMethod(method, identity, seed); applied.Add(method.IsPrivate ? "rename-private-method" : "rename-internal-method"); }
                        else skipped.Add("rename:" + reason);
                    }
                    if (applied.Any(protection => protection.StartsWith("constants:", StringComparison.Ordinal)
                        || protection.StartsWith("strings:", StringComparison.Ordinal) || protection is "control-flow" or "virtualize"))
                        ManagedTransforms.ExpandBranches(method);
                    ManagedIlVerifier.Validate(method);
                }
                if (options.RequireVirtualization && selection.Included && selection.Vm && !applied.Contains("virtualize"))
                    ManagedPreflight.Fail("MANAGED_VM_REQUIRED", "A method selected for required virtualization is outside the supported subset: " + identity.Signature);
                work.Add((method, applied, skipped, owner, Requested(selection, options.Virtualize)));
                if (timer.ElapsedMilliseconds > options.MaximumProtectionMilliseconds)
                    ManagedPreflight.Fail("MANAGED_TIME_BUDGET", "Managed protection exceeded its configured time budget.");
            }
            if (options.RequireVirtualization && !work.Any(item => item.Applied.Contains("virtualize")))
                ManagedPreflight.Fail("MANAGED_VM_SELECTION_EMPTY", "No included method matched the required virtualization selection.");
            for (var i = 0; i < counts.Length; i++)
            {
                if (options.RequireVirtualization && counts[i] == 0 && options.Rules[i].Virtualize == true && options.Rules[i].Include != false)
                    ManagedPreflight.Fail("MANAGED_VM_RULE_NO_MATCH", "A required virtualization rule matched no methods: " + i);
                if (counts[i] == 0) diagnostics.Add($"MANAGED_RULE_NO_MATCH: Rule {i} matched no methods.");
                if (generatedRuleHits[i]) diagnostics.Add($"MANAGED_RULE_GENERATED_CODE: Rule {i} implicitly matched compiler-generated methods.");
                if (boundaryRuleHits[i]) diagnostics.Add($"MANAGED_RULE_PUBLIC_BOUNDARY: Rule {i} matched public or protected methods; contractual names remain preserved.");
            }
            foreach (var method in allMethods) debugMaps[method].Rebind(method);
            if (options.MetadataHygiene)
            {
                foreach (var method in allMethods)
                    foreach (var point in method.DebugInformation.SequencePoints) point.Document.Url = Path.GetFileName(point.Document.Url.Replace('\\', '/'));
                diagnostics.Add("MANAGED_METADATA_HYGIENE: Portable sequence-point document paths were reduced to file names.");
            }
            if (options.RemoveWatermark || options.Watermark is not null)
            {
                foreach (var resource in module.Resources.Where(r => r.Name == "Rampart.Managed.Watermark").ToArray()) module.Resources.Remove(resource);
                if (options.Watermark is { } watermark)
                {
                    var bytes = Encoding.UTF8.GetBytes(watermark);
                    if (bytes.Length > 4096) ManagedPreflight.Fail("MANAGED_WATERMARK_LIMIT", "The watermark may contain at most 4096 UTF-8 bytes.");
                    module.Resources.Add(new EmbeddedResource("Rampart.Managed.Watermark", ManifestResourceAttributes.Private, bytes));
                }
            }
            if (helper is not null)
            {
                var bytes = payload.ToArray();
                module.Resources.Add(new EmbeddedResource(resourceName, ManifestResourceAttributes.Private, bytes));
                if (options.Integrity) AddInitializer(module, helper.Methods.Single(m => m.Name == "Verify"), resourceName, Hash(bytes));
                foreach (var method in helper.Methods) ManagedIlVerifier.Validate(method);
            }
            if (!module.Resources.Any(r => r.Name == "Rampart.Managed.Manifest"))
                module.Resources.Add(new EmbeddedResource("Rampart.Managed.Manifest", ManifestResourceAttributes.Private, Encoding.UTF8.GetBytes("Rampart.Managed/1\n" + inputHash)));
            using var output = new MemoryStream(); using var symbols = new MemoryStream();
            var writer = new WriterParameters { Timestamp = 0, DeterministicMvid = true, StrongNameKeyBlob = key };
            if (module.HasSymbols && options.PreserveDebugSymbols)
            {
                writer.WriteSymbols = true;
                if (HasEmbeddedPdb(input)) writer.SymbolWriterProvider = new ManagedEmbeddedWriter();
                else { writer.SymbolWriterProvider = new PortablePdbWriterProvider(); writer.SymbolStream = symbols; }
            }
            try { module.Write(output, writer); }
            finally { if (key is not null) CryptographicOperations.ZeroMemory(key); }
            var result = output.ToArray();
            if (result.LongLength > (long)input.Length * (100 + options.MaximumOutputGrowthPercent) / 100 + 65536)
                ManagedPreflight.Fail("MANAGED_OUTPUT_LIMIT", "The rewritten assembly exceeds its output growth budget.");
            ManagedPreflight.Validate(result, options);
            if (!originalPublicKey.AsSpan().SequenceEqual(module.Assembly.Name.PublicKey))
                ManagedPreflight.Fail("MANAGED_SIGNING_IDENTITY", "The signing key does not preserve the assembly public key.");
            if (originalPublicKey.Length != 0) ManagedStrongNameValidator.Validate(result, originalPublicKey);
            using var checkSymbols = new MemoryStream(symbols.ToArray(), false);
            var checkParameters = new ReaderParameters();
            if (writer.WriteSymbols)
            {
                checkParameters.ReadSymbols = true;
                if (HasEmbeddedPdb(result)) checkParameters.SymbolReaderProvider = new ManagedEmbeddedReader();
                else { checkParameters.SymbolReaderProvider = new PortablePdbReaderProvider(); checkParameters.SymbolStream = checkSymbols; }
            }
            using var check = ModuleDefinition.ReadModule(new MemoryStream(result, false), checkParameters);
            if (!api.SequenceEqual(PublicApi(check, preservedTypes, renaming.Normalize))) ManagedPreflight.Fail("MANAGED_PUBLIC_API_CHANGED", "Public API validation failed.");
            if (references.Except(check.AssemblyReferences.Select(a => a.FullName)).Any())
                ManagedPreflight.Fail("MANAGED_REFERENCE_CHANGED", "Assembly reference preservation failed.");
            foreach (var method in Types(check.Types).SelectMany(t => t.Methods)) ManagedIlVerifier.Validate(method);
            if (!diagnostics.Any(message => message.StartsWith("MANAGED_NOMINAL_VERIFICATION_REQUIRED", StringComparison.Ordinal))
                && Types(check.Types).SelectMany(type => type.Methods).Any(method => ManagedIlVerifier.VerificationStatus(method).Contains("nominal-verification-required", StringComparison.Ordinal)))
                diagnostics.Add("MANAGED_NOMINAL_VERIFICATION_REQUIRED: Stack-category checks do not resolve complete nominal type contracts. Use an independent verifier with matching reference assemblies.");
            var mappings = tokenMap!.Build(result, check, renaming.Normalize);
            if (mappings.Any(m => m.ProtectedToken == 0)) diagnostics.Add("MANAGED_TOKEN_REMOVED: Unreferenced metadata or an explicitly removed watermark has no output token; its map entry uses token zero.");
            var evidence = work.Select(item => new ManagedMethodEvidence(identities[item.Method], item.Method.MetadataToken.ToInt32(), item.Method.FullName,
                originalHashes[item.Method], MethodHash(item.Method), item.Owner, item.Applied, item.Skipped)
            {
                Requested = item.Requested,
                Rejected = item.Skipped.Where(reason => reason.Contains(":outside-", StringComparison.Ordinal)).ToArray(),
                VerificationStatus = ManagedIlVerifier.VerificationStatus((MethodDefinition)check.LookupToken(item.Method.MetadataToken)),
                OriginalIlSize = originalSizes[item.Method],
                ProtectedIlSize = ((MethodDefinition)check.LookupToken(item.Method.MetadataToken)).HasBody
                        ? ((MethodDefinition)check.LookupToken(item.Method.MetadataToken)).Body.CodeSize : 0,
                SequencePoints = debugMaps[item.Method].Emitted(item.Method, (MethodDefinition)check.LookupToken(item.Method.MetadataToken), writer.WriteSymbols, item.Owner),
                Sites = originalSites[item.Method].Select(site => new ManagedSiteEvidence(identities[item.Method].StableId + ":" + site.Offset,
                site.Offset, site.Protection, item.Applied.Any(a => a.StartsWith(site.Protection + ":", StringComparison.Ordinal))
                    && SiteReason(site.Instruction, site.Protection) is null ? "applied" : "skipped",
                item.Requested.Contains(site.Protection) && SiteReason(site.Instruction, site.Protection) is { } reason ? reason
                    : item.Applied.Any(a => a.StartsWith(site.Protection + ":", StringComparison.Ordinal)) ? null : item.Skipped.FirstOrDefault(s => s.StartsWith(site.Protection + ":", StringComparison.Ordinal)) ?? "disabled-or-owned-by-another-pass")).ToArray()
            }).ToArray();
            return ManagedVerification.VerifyResult(new ManagedProtectionResult(result, writer.WriteSymbols && symbols.Length != 0 ? symbols.ToArray() : null,
                evidence, mappings, inputHash, Hash(result), diagnostics)
            { IdentifierRenames = renaming.Evidence() }, options);
        }
        catch (ManagedProtectionException) { throw; }
        catch (Exception error) when (error is BadImageFormatException or ArgumentException or IndexOutOfRangeException
            or NotSupportedException or NotImplementedException or EndOfStreamException or NullReferenceException)
        { throw new ManagedProtectionException("MANAGED_REWRITE_FAILED", "The assembly could not be safely read or rewritten."); }
    }

    public static string? ReadWatermark(byte[] input)
    {
        ManagedPreflight.Validate(input, new ManagedProtectionOptions());
        using var module = ModuleDefinition.ReadModule(new MemoryStream(input, false));
        var resource = module.Resources.OfType<EmbeddedResource>().SingleOrDefault(r => r.Name == "Rampart.Managed.Watermark");
        if (resource is null) return null;
        var data = resource.GetResourceData();
        if (data.Length > 4096) ManagedPreflight.Fail("MANAGED_WATERMARK_LIMIT", "The watermark exceeds its permitted size.");
        return Encoding.UTF8.GetString(data);
    }

    private static IEnumerable<TypeDefinition> Types(IEnumerable<TypeDefinition> types)
    { foreach (var type in types) { yield return type; foreach (var nested in Types(type.NestedTypes)) yield return nested; } }
    private static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));
    private static string[] Requested(ManagedPolicy.Selection selection, bool vm) => new[]
    {
        selection.Strings ? "strings" : null, selection.Constants ? "constants" : null,
        selection.ControlFlow ? "control-flow" : null, selection.Rename ? "rename" : null,
        selection.Vm || vm ? "virtualize" : null
    }.OfType<string>().ToArray();
    private static string MethodHash(MethodDefinition method) => !method.HasBody ? Hash([]) : Hash(Encoding.UTF8.GetBytes(string.Join("\n", method.Body.Instructions.Select(i => i.ToString()))));
    private static string[] PublicApi(ModuleDefinition module, HashSet<string> preservedTypes, Func<string, string>? normalize = null)
    {
        normalize ??= value => value;
        var snapshot = new List<string> { "assembly:" + module.Assembly.Name.FullName, "kind:" + module.Kind,
            "assembly-attributes:" + Attributes(module.Assembly), "module-attributes:" + Attributes(module) };
        foreach (var type in module.GetTypes().Where(t => preservedTypes.Contains(normalize(t.FullName))))
        {
            snapshot.Add($"type:{type.FullName}|{type.Attributes}|{type.BaseType?.FullName}|{type.PackingSize}|{type.ClassSize}|{Attributes(type)}");
            foreach (var implementation in type.Interfaces) snapshot.Add($"interface:{type.FullName}|{implementation.InterfaceType.FullName}|{Attributes(implementation)}");
            foreach (var generic in type.GenericParameters) snapshot.Add(Generic(type.FullName, generic));
            foreach (var field in type.Fields) snapshot.Add($"field:{field.FullName}|{field.Attributes}|{field.Offset}|{Attributes(field)}");
            foreach (var property in type.Properties) snapshot.Add($"property:{property.FullName}|{property.Attributes}|{Attributes(property)}");
            foreach (var item in type.Events) snapshot.Add($"event:{item.FullName}|{item.Attributes}|{Attributes(item)}");
            foreach (var method in type.Methods.Where(m => !m.IsPrivate))
            {
                // FullName retains return/parameter custom modifiers and generic arity;
                // constraints and attributes need separate entries to detect contract loss.
                snapshot.Add($"method:{method.FullName}|{method.Attributes}|{method.ImplAttributes}|{Attributes(method)}|{Attributes(method.MethodReturnType)}");
                foreach (var parameter in method.Parameters) snapshot.Add($"parameter:{method.FullName}|{parameter.Index}|{parameter.Name}|{parameter.Attributes}|{Attributes(parameter)}");
                foreach (var generic in method.GenericParameters) snapshot.Add(Generic(method.FullName, generic));
                foreach (var implementation in method.Overrides) snapshot.Add($"override:{method.FullName}|{implementation.FullName}");
            }
        }
        return snapshot.Select(normalize).Order(StringComparer.Ordinal).ToArray();
        static string Attributes(ICustomAttributeProvider provider) => string.Join(";", provider.CustomAttributes.Select(a => a.Constructor.FullName + ":" + Convert.ToHexString(a.GetBlob())).Order(StringComparer.Ordinal));
        static string Generic(string owner, GenericParameter generic) => $"generic:{owner}|{generic.Position}|{generic.Name}|{generic.Attributes}|{Attributes(generic)}|"
            + string.Join(";", generic.Constraints.Select(c => c.ConstraintType.FullName + ":" + Attributes(c)).Order(StringComparer.Ordinal));
    }
    private static string[] ReadKeeps(ManagedProtectionOptions options)
    {
        var keeps = options.KeepPatterns.ToList();
        if (options.KeepFileEnvironmentVariable is { } variable)
        {
            var path = Environment.GetEnvironmentVariable(variable);
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) ManagedPreflight.Fail("MANAGED_KEEP_FILE", "The configured keep file is unavailable.");
            if (new FileInfo(path!).Length > 65536) ManagedPreflight.Fail("MANAGED_KEEP_FILE", "The keep file exceeds its size limit.");
            keeps.AddRange(File.ReadLines(path!).Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith('#')));
        }
        if (keeps.Count > 4096 || keeps.Any(k => k.Length > 4096)) ManagedPreflight.Fail("MANAGED_KEEP_LIMIT", "The keep policy exceeds its limits.");
        return keeps.ToArray();
    }
    private static byte[]? ReadSigningKey(ModuleDefinition module, ManagedProtectionOptions options)
    {
        if (!module.Assembly.Name.HasPublicKey && options.StrongNameKeyEnvironmentVariable is null) return null;
        if (options.StrongNameKeyEnvironmentVariable is not { } variable) ManagedPreflight.Fail("MANAGED_SIGNING_KEY_REQUIRED", "A strong-named assembly requires an explicit re-signing key for mutation.");
        var path = Environment.GetEnvironmentVariable(options.StrongNameKeyEnvironmentVariable!);
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) ManagedPreflight.Fail("MANAGED_SIGNING_KEY_REQUIRED", "The configured signing key is unavailable.");
        if (new FileInfo(path!).Length > 16384) ManagedPreflight.Fail("MANAGED_SIGNING_KEY_FORMAT", "The signing key exceeds its supported size.");
        return File.ReadAllBytes(path!);
    }
    private static bool RequireHelperRuntime(ModuleDefinition module)
    {
        var target = module.Assembly.CustomAttributes.FirstOrDefault(a => a.AttributeType.FullName == "System.Runtime.Versioning.TargetFrameworkAttribute");
        var name = target?.ConstructorArguments.FirstOrDefault().Value as string;
        if (name is not null && name.StartsWith(".NETFramework,Version=v", StringComparison.Ordinal)
            && Version.TryParse(name[23..], out var frameworkVersion) && frameworkVersion >= new Version(4, 8) && frameworkVersion <= new Version(4, 8, 1)
            && module.TypeSystem.CoreLibrary.Name == "mscorlib") return true;
        if (name is not null && name.StartsWith(".NETCoreApp,Version=v", StringComparison.Ordinal)
            && Version.TryParse(name[21..], out var version) && version.Major >= 8) return false;
        ManagedPreflight.Fail("MANAGED_HELPER_RUNTIME", "Runtime helpers require .NET 8 or later, or .NET Framework 4.8 or 4.8.1.");
        return false;
    }
    private static bool HasEmbeddedPdb(byte[] input)
    {
        try { using var pe = new PEReader(new MemoryStream(input, false)); return pe.ReadDebugDirectory().Any(d => d.Type == DebugDirectoryEntryType.EmbeddedPortablePdb); }
        catch (BadImageFormatException) { throw new ManagedProtectionException("MANAGED_INVALID_SYMBOLS", "The image debug directory is malformed."); }
    }
    private static void AddInitializer(ModuleDefinition module, MethodDefinition helper, string resource, string digest)
    {
        var type = module.Types.Single(t => t.Name == "<Module>");
        var initializer = type.Methods.SingleOrDefault(m => m.Name == ".cctor");
        if (initializer is null)
        {
            initializer = new MethodDefinition(".cctor", MethodAttributes.Static | MethodAttributes.Private | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, module.TypeSystem.Void);
            type.Methods.Add(initializer); initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        }
        var il = initializer.Body.GetILProcessor(); var first = initializer.Body.Instructions[0];
        il.InsertBefore(first, Instruction.Create(OpCodes.Ldstr, resource)); il.InsertBefore(first, Instruction.Create(OpCodes.Ldstr, digest));
        il.InsertBefore(first, Instruction.Create(OpCodes.Call, helper));
    }
}
