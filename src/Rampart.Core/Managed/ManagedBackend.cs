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
        var readExternalSymbols = options.PreserveDebugSymbols && portablePdb is not null && portablePdb.AsSpan().StartsWith("BSJB"u8);
        if (readExternalSymbols) ManagedPreflight.ValidatePortablePdb(portablePdb, options);
        var readEmbeddedSymbols = !readExternalSymbols && options.PreserveDebugSymbols && HasEmbeddedPdb(input);
        var inputHash = Hash(input);
        using var inputStream = new MemoryStream(input, false);
        using var symbolInput = portablePdb is null ? null : new MemoryStream(portablePdb, false);
        var parameters = new ReaderParameters { ReadingMode = ReadingMode.Deferred, InMemory = true };
        if (readExternalSymbols)
        { parameters.ReadSymbols = true; parameters.SymbolStream = symbolInput; parameters.SymbolReaderProvider = new PortablePdbReaderProvider(); }
        else if (readEmbeddedSymbols)
        { parameters.ReadSymbols = true; parameters.SymbolReaderProvider = new ManagedEmbeddedReader(); }
        byte[]? key = null;
        try
        {
            using var module = ModuleDefinition.ReadModule(inputStream, parameters);
            var hasActiveProtection = module.Types.Any(t => t.Name.StartsWith("<Rampart_", StringComparison.Ordinal))
                || module.Resources.Any(r => r.Name.StartsWith("Rampart.Managed.", StringComparison.Ordinal)
                    && r.Name is not ("Rampart.Managed.Watermark" or "Rampart.Managed.Manifest"));
            var watermarkOnly = (options.RemoveWatermark || options.Watermark is not null)
                && !options.Strings && !options.Constants && !options.MetadataHygiene
                && !options.Integrity && !options.RenamePrivateMembers && !options.ControlFlow
                && !options.Virtualize && options.Rules.Count == 0;
            if (changes && !watermarkOnly && hasActiveProtection)
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
            key = ReadSigningKey(module, options);
            var signingUnsignedAssembly = originalPublicKey.Length == 0 && key is not null;
            var preservedTypes = module.GetTypes().Select(t => t.FullName).ToHashSet(StringComparer.Ordinal);
            var api = PublicApi(module, preservedTypes, ignoreAssemblyPublicKey: signingUnsignedAssembly);
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
            if (options.RenamePrivateMembers || options.Rules.Any(r => r.RenamePrivateMembers == true)) renaming.Apply(seed, options);
            var resourceName = "Rampart.Managed.Payload." + suffix;
            TypeDefinition? helper = null;
            var needDecode = options.Strings || options.Rules.Any(r => r.Strings == true)
                || options.HardenedRuntime && (options.Virtualize || options.Rules.Any(r => r.Virtualize == true));
            var needVerify = options.Integrity;
            var needInterpret = options.Virtualize || options.Rules.Any(r => r.Virtualize == true);
            if (needDecode || needVerify || needInterpret)
            {
                var framework = RequireHelperRuntime(module);
                if (framework && options.HardenedRuntime)
                    ManagedPreflight.Fail("MANAGED_HARDENED_RUNTIME_UNSUPPORTED", "Hardened runtime protection requires modern .NET.");
                helper = ManagedHelperInjector.Inject(module, suffix, framework, options.HardenedRuntime, needDecode, needVerify, needInterpret);
                if (options.HardenedRuntime)
                    diagnostics.Add(options.EphemeralVmPrograms
                        ? "MANAGED_HARDENED_RUNTIME: Payloads use AES-256-CBC with HMAC-SHA256; selected VM programs are decrypted per invocation and cleared with the interpreter stack. Decoding keys ship with the application."
                        : "MANAGED_HARDENED_RUNTIME: Payloads use AES-256-CBC with HMAC-SHA256; selected VM methods use independent dispatch layouts. Decoding keys ship with the application.");
            }
            using var payload = new MemoryStream();
            var decisionGuards = new ManagedDecisionGuards(module, seed);
            var decisionGuardCount = 0;
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
                                    helper.Methods.Single(m => m.Name == (options.EphemeralVmPrograms ? "DecodeProgram" : "Decode")),
                                    helper.Methods.Single(m => m.Name == "ClearScratch"), payload, resourceName, seed, identity.StableId,
                                    options.EphemeralVmPrograms)
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
                        {
                            bool permuted = ManagedTransforms.ControlFlow(method, seed, identity.StableId);
                            int guarded = decisionGuards.Apply(method, identity.StableId);
                            decisionGuardCount += guarded;
                            if (guarded > 0) applied.Add("decision-guards:" + guarded);
                            if (permuted) applied.Add("control-flow");
                            else if (guarded == 0) skipped.Add("control-flow:outside-stack-neutral-subset");
                            else skipped.Add("control-flow:permutation-outside-stack-neutral-subset");
                        }
                        if (applied.Count > 0) owner = "managed-il";
                    }
                    if (selection.Rename)
                    {
                        if (renaming.MethodReason(method, identity) is not { } reason)
                        { renaming.RenameMethod(method, identity, seed); applied.Add(method.IsPrivate ? "rename-private-method" : "rename-internal-method"); }
                        else skipped.Add("rename:" + reason);
                    }
                    if (applied.Any(protection => protection.StartsWith("constants:", StringComparison.Ordinal)
                        || protection.StartsWith("strings:", StringComparison.Ordinal)
                        || protection.StartsWith("decision-guards:", StringComparison.Ordinal)
                        || protection is "control-flow" or "virtualize"))
                        ManagedTransforms.ExpandBranches(method);
                    ManagedIlVerifier.Validate(method);
                }
                if ((options.RequireVirtualization || options.EphemeralVmPrograms) && selection.Included && selection.Vm && !applied.Contains("virtualize"))
                    ManagedPreflight.Fail("MANAGED_VM_REQUIRED", "A method selected for required virtualization is outside the supported subset: " + identity.Signature);
                work.Add((method, applied, skipped, owner, Requested(selection, options.Virtualize)));
                if (timer.ElapsedMilliseconds > options.MaximumProtectionMilliseconds)
                    ManagedPreflight.Fail("MANAGED_TIME_BUDGET", "Managed protection exceeded its configured time budget.");
            }
            if ((options.RequireVirtualization || options.EphemeralVmPrograms) && !work.Any(item => item.Applied.Contains("virtualize")))
                ManagedPreflight.Fail("MANAGED_VM_SELECTION_EMPTY", "No included method matched the required virtualization selection.");
            if (decisionGuardCount > 0)
                diagnostics.Add($"MANAGED_DECISION_GUARDS: Replaced {decisionGuardCount} Boolean/int32 branch sites with per-site seeded dispatch.");
            for (var i = 0; i < counts.Length; i++)
            {
                if ((options.RequireVirtualization || options.EphemeralVmPrograms) && counts[i] == 0 && options.Rules[i].Virtualize == true && options.Rules[i].Include != false)
                    ManagedPreflight.Fail("MANAGED_VM_RULE_NO_MATCH", "A required virtualization rule matched no methods: " + i);
                if (counts[i] == 0) diagnostics.Add($"MANAGED_RULE_NO_MATCH: Rule {i} matched no methods.");
                if (generatedRuleHits[i]) diagnostics.Add($"MANAGED_RULE_GENERATED_CODE: Rule {i} implicitly matched compiler-generated methods.");
                if (boundaryRuleHits[i]) diagnostics.Add($"MANAGED_RULE_PUBLIC_BOUNDARY: Rule {i} matched public or protected methods; contractual names remain preserved.");
            }
            foreach (var method in allMethods) debugMaps[method].Rebind(method);
            if (options.MetadataHygiene)
            {
                var scrubbed = 0;
                foreach (var method in allMethods)
                    foreach (var point in method.DebugInformation.SequencePoints)
                    {
                        point.Document.Url = Path.GetFileName(point.Document.Url.Replace('\\', '/'));
                        scrubbed++;
                    }
                diagnostics.Add(scrubbed > 0
                    ? "MANAGED_METADATA_HYGIENE: Portable sequence-point document paths were reduced to file names."
                    : "MANAGED_METADATA_HYGIENE_NO_SYMBOLS: No portable sequence points were present to scrub.");
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
                if (options.Integrity)
                {
                    var (initializer, created) = AddInitializer(module, helper.Methods.Single(m => m.Name == "Verify"), resourceName, Hash(bytes));
                    if (created)
                    {
                        diagnostics.Add("MANAGED_INTEGRITY_INITIALIZER: Added a module initializer to verify the embedded payload resource.");
                    }
                    else
                    {
                        var existingIndex = work.FindIndex(item => ReferenceEquals(item.Method, initializer));
                        if (existingIndex >= 0)
                        {
                            var existing = work[existingIndex];
                            existing.Applied.Add("integrity");
                            work[existingIndex] = (existing.Method, existing.Applied, existing.Skipped, existing.Owner ?? "managed-il", existing.Requested);
                        }
                    }
                }
                foreach (var method in helper.Methods) ManagedIlVerifier.Validate(method);
            }
            if (!module.Resources.Any(r => r.Name == "Rampart.Managed.Manifest"))
                module.Resources.Add(new EmbeddedResource("Rampart.Managed.Manifest", ManifestResourceAttributes.Private, Encoding.UTF8.GetBytes("Rampart.Managed/1\n" + inputHash)));
            using var output = new MemoryStream(); using var symbols = new MemoryStream();
            var writer = new WriterParameters { Timestamp = 0, DeterministicMvid = true, StrongNameKeyBlob = key };
            var writeEmbeddedSymbols = false;
            if (module.HasSymbols && options.PreserveDebugSymbols)
            {
                writer.WriteSymbols = true;
                if (readEmbeddedSymbols) { writeEmbeddedSymbols = true; writer.SymbolWriterProvider = new ManagedEmbeddedWriter(); }
                else { writer.SymbolWriterProvider = new PortablePdbWriterProvider(); writer.SymbolStream = symbols; }
            }
            module.Write(output, writer);
            var result = output.ToArray();
            if (result.LongLength > (long)input.Length * (100 + options.MaximumOutputGrowthPercent) / 100 + 65536)
                ManagedPreflight.Fail("MANAGED_OUTPUT_LIMIT", "The rewritten assembly exceeds its output growth budget.");
            ManagedPreflight.Validate(result, options);
            var emittedPublicKey = module.Assembly.Name.PublicKey.ToArray();
            if (originalPublicKey.Length != 0 && !originalPublicKey.AsSpan().SequenceEqual(emittedPublicKey))
                ManagedPreflight.Fail("MANAGED_SIGNING_IDENTITY", "The signing key does not preserve the assembly public key.");
            if (emittedPublicKey.Length != 0) ManagedStrongNameValidator.Validate(result, emittedPublicKey);
            using var checkSymbols = new MemoryStream(symbols.ToArray(), false);
            var checkParameters = new ReaderParameters();
            if (writer.WriteSymbols)
            {
                checkParameters.ReadSymbols = true;
                if (writeEmbeddedSymbols) checkParameters.SymbolReaderProvider = new ManagedEmbeddedReader();
                else { checkParameters.SymbolReaderProvider = new PortablePdbReaderProvider(); checkParameters.SymbolStream = checkSymbols; }
            }
            using var check = ModuleDefinition.ReadModule(new MemoryStream(result, false), checkParameters);
            if (!api.SequenceEqual(PublicApi(check, preservedTypes, renaming.Normalize, signingUnsignedAssembly))) ManagedPreflight.Fail("MANAGED_PUBLIC_API_CHANGED", "Public API validation failed.");
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
                Sites = originalSites[item.Method].Select(site =>
                {
                    bool appliedSite = item.Applied.Any(a => a.StartsWith(site.Protection + ":", StringComparison.Ordinal))
                        && SiteReason(site.Instruction, site.Protection) is null;
                    string? reason = appliedSite ? null
                        : item.Skipped.Contains("policy:excluded", StringComparer.Ordinal) ? "policy:excluded"
                        : item.Requested.Contains(site.Protection) && SiteReason(site.Instruction, site.Protection) is { } siteReason ? siteReason
                        : item.Skipped.FirstOrDefault(s => s.StartsWith(site.Protection + ":", StringComparison.Ordinal)) ?? "disabled-or-owned-by-another-pass";
                    return new ManagedSiteEvidence(identities[item.Method].StableId + ":" + site.Offset,
                        site.Offset, site.Protection, appliedSite ? "applied" : "skipped", reason);
                }).ToArray()
            }).ToArray();
            return ManagedVerification.VerifyResult(new ManagedProtectionResult(result, writer.WriteSymbols && symbols.Length != 0 ? symbols.ToArray() : null,
                evidence, mappings, inputHash, Hash(result), diagnostics)
            { IdentifierRenames = renaming.Evidence() }, options);
        }
        catch (ManagedProtectionException) { throw; }
        catch (Exception error) when (error is BadImageFormatException or InvalidOperationException or ArgumentException or IndexOutOfRangeException
            or NotSupportedException or NotImplementedException or EndOfStreamException)
        { throw new ManagedProtectionException("MANAGED_REWRITE_FAILED", "The assembly could not be safely read or rewritten.", error); }
        finally { if (key is not null) CryptographicOperations.ZeroMemory(key); }
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
    private static string[] PublicApi(ModuleDefinition module, HashSet<string> preservedTypes,
        Func<string, string>? normalize = null, bool ignoreAssemblyPublicKey = false)
    {
        normalize ??= value => value;
        var assemblyName = ignoreAssemblyPublicKey
            ? $"{module.Assembly.Name.Name}, Version={module.Assembly.Name.Version}, Culture={(string.IsNullOrEmpty(module.Assembly.Name.Culture) ? "neutral" : module.Assembly.Name.Culture)}"
            : module.Assembly.Name.FullName;
        var snapshot = new List<string> { "assembly:" + assemblyName, "kind:" + module.Kind,
            "assembly-attributes:" + normalize(Attributes(module.Assembly)), "module-attributes:" + normalize(Attributes(module)) };
        foreach (var type in module.GetTypes().Where(t => preservedTypes.Contains(IsExternallyVisibleType(t) ? t.FullName : normalize(t.FullName))))
        {
            // Never normalize declaration names of externally visible types or their
            // public/protected members so an unintended rename cannot be hidden.
            var externalType = IsExternallyVisibleType(type);
            string MaybeNormalize(string value, bool keepRaw) => keepRaw ? value : normalize(value);
            string NormalizeExceptMemberName(string fullName, string memberName)
            {
                var separator = fullName.LastIndexOf("::", StringComparison.Ordinal);
                if (separator < 0) return normalize(fullName);
                var afterSeparator = fullName[(separator + 2)..];
                if (!afterSeparator.StartsWith(memberName, StringComparison.Ordinal)) return normalize(fullName);
                return normalize(fullName[..separator]) + "::" + memberName + normalize(afterSeparator[memberName.Length..]);
            }

            snapshot.Add(MaybeNormalize($"type:{type.FullName}|{type.Attributes}|{type.BaseType?.FullName}|{type.PackingSize}|{type.ClassSize}|{Attributes(type)}", externalType));
            foreach (var implementation in type.Interfaces)
                snapshot.Add(MaybeNormalize($"interface:{type.FullName}|{implementation.InterfaceType.FullName}|{Attributes(implementation)}", externalType));
            foreach (var generic in type.GenericParameters)
                snapshot.Add(MaybeNormalize(Generic(type.FullName, generic), externalType));
            foreach (var field in type.Fields)
            {
                var externalField = field.IsPublic || field.IsFamily || field.IsFamilyOrAssembly;
                if (externalType && externalField)
                    snapshot.Add($"field:{field.FullName}|{field.Attributes}|{field.Offset}|{Attributes(field)}");
                else if (externalField)
                    snapshot.Add($"field:{NormalizeExceptMemberName(field.FullName, field.Name)}|{field.Attributes}|{field.Offset}|{normalize(Attributes(field))}");
                else
                    snapshot.Add(normalize($"field:{field.FullName}|{field.Attributes}|{field.Offset}|{Attributes(field)}"));
            }
            foreach (var property in type.Properties)
            {
                var externalProperty = (property.GetMethod is { } g && (g.IsPublic || g.IsFamily || g.IsFamilyOrAssembly))
                    || (property.SetMethod is { } s && (s.IsPublic || s.IsFamily || s.IsFamilyOrAssembly));
                if (externalType && externalProperty)
                    snapshot.Add($"property:{property.FullName}|{property.Attributes}|{Attributes(property)}");
                else if (externalProperty)
                    snapshot.Add($"property:{NormalizeExceptMemberName(property.FullName, property.Name)}|{property.Attributes}|{normalize(Attributes(property))}");
                else
                    snapshot.Add(normalize($"property:{property.FullName}|{property.Attributes}|{Attributes(property)}"));
            }
            foreach (var item in type.Events)
            {
                var externalEvent = (item.AddMethod is { } a && (a.IsPublic || a.IsFamily || a.IsFamilyOrAssembly))
                    || (item.RemoveMethod is { } r && (r.IsPublic || r.IsFamily || r.IsFamilyOrAssembly));
                if (externalType && externalEvent)
                    snapshot.Add($"event:{item.FullName}|{item.Attributes}|{Attributes(item)}");
                else if (externalEvent)
                    snapshot.Add($"event:{NormalizeExceptMemberName(item.FullName, item.Name)}|{item.Attributes}|{normalize(Attributes(item))}");
                else
                    snapshot.Add(normalize($"event:{item.FullName}|{item.Attributes}|{Attributes(item)}"));
            }
            foreach (var method in type.Methods.Where(m => !m.IsPrivate))
            {
                // FullName retains return/parameter custom modifiers and generic arity;
                // constraints and attributes need separate entries to detect contract loss.
                var externalMethod = method.IsPublic || method.IsFamily || method.IsFamilyOrAssembly;
                var keepRaw = externalType && externalMethod;
                var methodFullName = keepRaw ? method.FullName
                    : externalMethod ? NormalizeExceptMemberName(method.FullName, method.Name)
                    : normalize(method.FullName);
                snapshot.Add($"method:{methodFullName}|{method.Attributes}|{method.ImplAttributes}|{MaybeNormalize(Attributes(method), keepRaw)}|{MaybeNormalize(Attributes(method.MethodReturnType), keepRaw)}");
                foreach (var parameter in method.Parameters)
                    snapshot.Add($"parameter:{methodFullName}|{parameter.Index}|{(externalMethod ? parameter.Name : normalize(parameter.Name))}|{parameter.Attributes}|{MaybeNormalize(Attributes(parameter), keepRaw)}");
                foreach (var generic in method.GenericParameters)
                    snapshot.Add(MaybeNormalize(Generic(methodFullName, generic), keepRaw));
                foreach (var implementation in method.Overrides)
                    snapshot.Add($"override:{methodFullName}|{MaybeNormalize(implementation.FullName, keepRaw)}");
            }
        }
        return snapshot.Order(StringComparer.Ordinal).ToArray();
        static bool IsExternallyVisibleType(TypeDefinition type)
        {
            for (var current = type; current is not null; current = current.DeclaringType)
            {
                if (current.DeclaringType is null)
                { if (!current.IsPublic) return false; }
                else if (!(current.IsNestedPublic || current.IsNestedFamily || current.IsNestedFamilyOrAssembly))
                    return false;
            }
            return true;
        }
        static string Attributes(ICustomAttributeProvider provider) => string.Join(";", provider.CustomAttributes.Select(a => a.Constructor.FullName + ":" + Convert.ToHexString(a.GetBlob())).Order(StringComparer.Ordinal));
        static string Generic(string owner, GenericParameter generic) => $"generic:{owner}|{generic.Position}|{generic.Name}|{generic.Attributes}|{Attributes(generic)}|"
            + string.Join(";", generic.Constraints.Select(c => c.ConstraintType.FullName + ":" + Attributes(c)).Order(StringComparer.Ordinal));
    }
    private static byte[] ReadBoundedFile(string path, int maxBytes, string missingCode, string missingMessage, string limitCode, string limitMessage)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var buffer = new MemoryStream();
            var chunk = new byte[Math.Min(8192, maxBytes + 1)];
            while (true)
            {
                var remaining = maxBytes + 1 - (int)buffer.Length;
                if (remaining <= 0) break;
                var read = stream.Read(chunk, 0, Math.Min(chunk.Length, remaining));
                if (read == 0) break;
                buffer.Write(chunk, 0, read);
                if (buffer.Length > maxBytes) ManagedPreflight.Fail(limitCode, limitMessage);
            }
            return buffer.ToArray();
        }
        catch (ManagedProtectionException) { throw; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        { throw new ManagedProtectionException(missingCode, missingMessage, error); }
    }
    private static string[] ReadKeeps(ManagedProtectionOptions options)
    {
        var keeps = options.KeepPatterns.ToList();
        if (options.KeepFileEnvironmentVariable is { } variable)
        {
            var path = Environment.GetEnvironmentVariable(variable);
            if (string.IsNullOrWhiteSpace(path)) ManagedPreflight.Fail("MANAGED_KEEP_FILE", "The configured keep file is unavailable.");
            var bytes = ReadBoundedFile(path!, 65536, "MANAGED_KEEP_FILE", "The configured keep file is unavailable.", "MANAGED_KEEP_FILE", "The keep file exceeds its size limit.");
            using var reader = new StreamReader(new MemoryStream(bytes, writable: false), Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            while (reader.ReadLine() is { } line)
            {
                var trimmed = line.Trim();
                if (trimmed.Length > 0 && !trimmed.StartsWith('#')) keeps.Add(trimmed);
            }
        }
        if (keeps.Count > 4096 || keeps.Any(k => k.Length > 4096)) ManagedPreflight.Fail("MANAGED_KEEP_LIMIT", "The keep policy exceeds its limits.");
        return keeps.ToArray();
    }
    private static byte[]? ReadSigningKey(ModuleDefinition module, ManagedProtectionOptions options)
    {
        if (!module.Assembly.Name.HasPublicKey && options.StrongNameKeyEnvironmentVariable is null) return null;
        if (options.StrongNameKeyEnvironmentVariable is not { } variable) ManagedPreflight.Fail("MANAGED_SIGNING_KEY_REQUIRED", "A strong-named assembly requires an explicit re-signing key for mutation.");
        var path = Environment.GetEnvironmentVariable(options.StrongNameKeyEnvironmentVariable!);
        if (string.IsNullOrWhiteSpace(path)) ManagedPreflight.Fail("MANAGED_SIGNING_KEY_REQUIRED", "The configured signing key is unavailable.");
        return ReadBoundedFile(path!, 16384, "MANAGED_SIGNING_KEY_REQUIRED", "The configured signing key is unavailable.", "MANAGED_SIGNING_KEY_FORMAT", "The signing key exceeds its supported size.");
    }
    private static bool RequireHelperRuntime(ModuleDefinition module)
    {
        var target = module.Assembly.CustomAttributes.FirstOrDefault(a => a.AttributeType.FullName == "System.Runtime.Versioning.TargetFrameworkAttribute");
        var name = target?.ConstructorArguments.FirstOrDefault().Value as string;
        if (name is not null)
        {
            var parts = name.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            var identifier = parts.Length > 0 ? parts[0] : "";
            var versionPart = parts.FirstOrDefault(p => p.StartsWith("Version=v", StringComparison.OrdinalIgnoreCase));
            if (versionPart is not null && Version.TryParse(versionPart[9..], out var version))
            {
                if (identifier.Equals(".NETFramework", StringComparison.OrdinalIgnoreCase)
                    && version.Major == 4 && version.Minor == 8
                    && (version.Build <= 0 || (version.Build == 1 && version.Revision <= 0))
                    && module.TypeSystem.CoreLibrary.Name == "mscorlib")
                    return true;
                if (identifier.Equals(".NETCoreApp", StringComparison.OrdinalIgnoreCase) && version.Major >= 8)
                    return false;
            }
        }
        ManagedPreflight.Fail("MANAGED_HELPER_RUNTIME", "Runtime helpers require .NET 8 or later, or .NET Framework 4.8 or 4.8.1.");
        return false;
    }
    private static bool HasEmbeddedPdb(byte[] input)
    {
        try { using var pe = new PEReader(new MemoryStream(input, false)); return pe.ReadDebugDirectory().Any(d => d.Type == DebugDirectoryEntryType.EmbeddedPortablePdb); }
        catch (BadImageFormatException error) { throw new ManagedProtectionException("MANAGED_INVALID_SYMBOLS", "The image debug directory is malformed.", error); }
    }
    private static (MethodDefinition Initializer, bool Created) AddInitializer(ModuleDefinition module, MethodDefinition helper, string resource, string digest)
    {
        var type = module.Types.Single(t => t.Name == "<Module>");
        var initializer = type.Methods.SingleOrDefault(m => m.Name == ".cctor");
        var created = initializer is null;
        if (initializer is null)
        {
            initializer = new MethodDefinition(".cctor", MethodAttributes.Static | MethodAttributes.Private | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, module.TypeSystem.Void);
            type.Methods.Add(initializer); initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        }
        var il = initializer.Body.GetILProcessor(); var first = initializer.Body.Instructions[0];
        il.InsertBefore(first, Instruction.Create(OpCodes.Ldstr, resource)); il.InsertBefore(first, Instruction.Create(OpCodes.Ldstr, digest));
        il.InsertBefore(first, Instruction.Create(OpCodes.Call, helper));
        ManagedTransforms.ExpandBranches(initializer);
        ManagedIlVerifier.UpdateMaxStackSize(initializer);
        ManagedIlVerifier.Validate(initializer);
        return (initializer, created);
    }
}
