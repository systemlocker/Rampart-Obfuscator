using System.Diagnostics;
using System.Globalization;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using Rampart.Config;
using Rampart.Targets;

namespace Rampart.MSBuild;

/// <summary>Stages explicitly selected application artifacts without rewriting
/// compiler outputs or assemblies from runtime packs.</summary>
public sealed class ProtectPublishArtifacts : Microsoft.Build.Utilities.Task
{
    [Required] public ITaskItem[] Artifacts { get; set; } = [];
    [Required] public string MainAssemblyName { get; set; } = "";
    [Required] public string StagingDirectory { get; set; } = "";
    [Required] public string WorkerTool { get; set; } = "";
    [Required] public string TargetKind { get; set; } = "";
    public ITaskItem[] SelectedAssemblies { get; set; } = [];
    public ITaskItem[] VerificationReferences { get; set; } = [];
    public ITaskItem[] FrameworkVerificationReferences { get; set; } = [];
    public string? VerificationSystemModule { get; set; }
    public string? ConfigurationFile { get; set; }
    public bool HardenedNativeAot { get; set; }
    public string Seed { get; set; } = "0";
    [Output] public ITaskItem[] ProtectedArtifacts { get; set; } = [];
    [Output] public string ManifestPath { get; set; } = "";
    [Output] public string PrimaryOutputDirectory { get; set; } = "";

    private sealed record ManifestEntry(string Name, string InputSha256, string? OutputSha256, string Role, bool Changed)
    {
        public string? ConfigurationSha256 { get; init; }
    }
    private sealed record CacheRecord(string Key, string OutputSha256, string? PdbSha256, string? MapSha256);
    private sealed record PreparedConfiguration(ProtectionSettings Settings, string Json, string Hash, string ReferenceHash);

    public override bool Execute()
    {
        try
        {
            long seed = long.Parse(Seed, CultureInfo.InvariantCulture);
            if (!Enum.TryParse<ProtectionTargetKind>(TargetKind, out var kind) || kind is not (ProtectionTargetKind.ManagedIl or ProtectionTargetKind.NativeAot))
                throw new InvalidOperationException("RP_PUBLISH_TARGET: Unsupported publish-stage target.");
            string stage = Path.GetFullPath(StagingDirectory);
            Directory.CreateDirectory(stage);
            PreparedConfiguration PrepareConfiguration(string? configurationFile)
            {
                string? suppliedConfiguration = string.IsNullOrEmpty(configurationFile) ? null : File.ReadAllText(configurationFile);
                var settings = suppliedConfiguration is null ? new ProtectionSettings()
                    : ProtectionSettingsJson.Deserialize(suppliedConfiguration);
                if (kind == ProtectionTargetKind.ManagedIl && suppliedConfiguration is not null)
                {
                    using var supplied = JsonDocument.Parse(suppliedConfiguration);
                    JsonElement configurationRoot = supplied.RootElement;
                    foreach (var property in supplied.RootElement.EnumerateObject())
                        if (property.Name.Equals("Settings", StringComparison.OrdinalIgnoreCase)) configurationRoot = property.Value;
                    if (configurationRoot.EnumerateObject().Any(property => property.Name.Equals("Preset", StringComparison.OrdinalIgnoreCase)))
                        throw new InvalidOperationException("RP_MANAGED_PRESET_UNSUPPORTED: Select managed protections through managed options or supported knobs.");
                }
                settings.Seed = seed;
                settings.Targets ??= new();
                if (settings.Targets.Override is { } configured && configured != kind)
                    throw new InvalidOperationException("RP_SIGNING_ORDER: Configuration target does not match this publish stage.");
                settings.Targets.Override = kind;
                string referenceHash = "";
                if (kind == ProtectionTargetKind.ManagedIl)
                {
                    settings.Targets.Managed ??= new();
                    if (HardenedNativeAot)
                    {
                        var managed = settings.Targets.Managed;
                        if (!managed.Rules.Any(rule => rule.Virtualize == true))
                            throw new InvalidOperationException("RP_AOT_METHOD_SELECTION_REQUIRED: Select application methods for required virtualization.");
                        managed.HardenedRuntime = true; managed.RequireVirtualization = true;
                        managed.Strings = true; managed.Constants = true; managed.Integrity = true;
                        managed.MetadataHygiene = true; managed.RenamePrivateMembers = true;
                        managed.ControlFlow = true; managed.Virtualize = true;
                    }
                    settings.Targets.Managed.Verification ??= new();
                    var verification = settings.Targets.Managed.Verification;
                    verification.SystemModuleName = VerificationSystemModule;
                    // Use the references chosen by this SDK compilation. Inspecting
                    // the build host's own runtime would silently verify against a
                    // different target framework in multi-targeted projects.
                    // Newer NativeAOT packs include native DLLs in IlcReference and
                    // DefaultFrameworkAssemblies. Keep those compiler artifacts, but
                    // do not pass native PE files to the managed metadata verifier.
                    // Explicit user references are never filtered, and malformed PE
                    // or managed metadata still fails instead of being omitted.
                    var sdkReferences = VerificationReferences.Select(item => Path.GetFullPath(item.ItemSpec)).Where(IsManagedSdkReference).ToArray();
                    verification.ReferencePaths = verification.ReferencePaths.Concat(sdkReferences)
                        .Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.Ordinal).ToList();
                    verification.FrameworkReferencePaths = verification.FrameworkReferencePaths.Concat(VerificationReferences
                        .Where(item => !string.IsNullOrEmpty(item.GetMetadata("FrameworkReferenceName")))
                        .Concat(FrameworkVerificationReferences).Select(item => Path.GetFullPath(item.ItemSpec)).Where(IsManagedSdkReference))
                        .Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.Ordinal).ToList();
                    if (verification.ReferencePaths.Count == 0)
                        throw new InvalidOperationException("RP_PUBLISH_VERIFICATION_REFERENCES: Target framework references were not supplied by the SDK.");
                    referenceHash = Hash(Encoding.UTF8.GetBytes(string.Join("\n", verification.ReferencePaths.Select(path => FileHash(path)))));
                }
                string configuration = ProtectionSettingsJson.Serialize(settings);
                if (kind == ProtectionTargetKind.ManagedIl)
                {
                    // The common model has a native default preset. Do not turn that
                    // implicit placeholder into an explicit managed CLI request.
                    var workerConfiguration = JsonNode.Parse(configuration)!.AsObject();
                    workerConfiguration.Remove("Preset");
                    configuration = workerConfiguration.ToJsonString(ProtectionSettingsJson.Options);
                }
                string configHash = Hash(Encoding.UTF8.GetBytes(configuration));
                return new(settings, configuration, configHash, referenceHash);
            }
            var defaults = PrepareConfiguration(ConfigurationFile);
            var configurations = new Dictionary<string, PreparedConfiguration>(StringComparer.OrdinalIgnoreCase);
            var selected = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { MainAssemblyName };
            foreach (var selection in SelectedAssemblies)
            {
                string name = Path.GetFileName(selection.ItemSpec);
                if (!selected.Add(name))
                    throw new InvalidOperationException("RP_PUBLISH_SELECTION_AMBIGUOUS: Select each dependency once; configure the application through RampartConfiguration.");
                string configurationFile = selection.GetMetadata("Configuration");
                if (string.IsNullOrWhiteSpace(configurationFile)) continue;
                // Resolve dependency settings explicitly. MSBuild's working
                // directory is not necessarily the application's directory.
                if (!Path.IsPathFullyQualified(configurationFile))
                    throw new InvalidOperationException("RP_PUBLISH_CONFIGURATION_PATH: Dependency configuration paths must be absolute.");
                if (!File.Exists(configurationFile))
                    throw new InvalidOperationException("RP_PUBLISH_CONFIGURATION_MISSING: A dependency configuration file is missing.");
                configurations.Add(name, PrepareConfiguration(configurationFile));
            }
            foreach (string selection in selected)
            {
                int matches = Artifacts.Count(item => Path.GetFileName(item.ItemSpec).Equals(selection, StringComparison.OrdinalIgnoreCase));
                if (matches == 0)
                    throw new InvalidOperationException("RP_PUBLISH_SELECTION_MISSING: An explicitly selected assembly is absent from this publish stage.");
                if (matches != 1)
                    throw new InvalidOperationException("RP_PUBLISH_SELECTION_AMBIGUOUS: More than one publish input has a selected assembly name.");
            }
            string tool = Path.GetFullPath(WorkerTool);
            string toolHash = FileHash(tool);
            // Same-version development builds must not reuse artifacts from old
            // Core/Cecil code. Package versions remain part of the digest too.
            string core = Path.Combine(Path.GetDirectoryName(tool)!, "Rampart.Core.dll");
            if (File.Exists(core)) toolHash += FileHash(core);
            foreach (string dependency in Directory.EnumerateFiles(Path.GetDirectoryName(tool)!, "*.dll").Order(StringComparer.Ordinal))
                toolHash += FileHash(dependency);
            string dependencies = Path.ChangeExtension(tool, ".deps.json");
            if (File.Exists(dependencies)) toolHash += FileHash(dependencies);
            var replacements = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var symbolReplacements = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var omittedSymbols = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var manifest = new List<ManifestEntry>();
            bool primaryFound = false;
            foreach (var item in Artifacts)
            {
                string input = Path.GetFullPath(item.ItemSpec);
                string name = Path.GetFileName(input);
                if (!File.Exists(input)) throw new IOException("RP_ARTIFACT_MISSING: A publish input is missing.");
                string inputHash = FileHash(input);
                if (!selected.Contains(name))
                {
                    manifest.Add(new(PublicName(item), inputHash, inputHash, "unchanged", false));
                    continue;
                }
                var prepared = configurations.GetValueOrDefault(name, defaults);
                var settings = prepared.Settings;
                string configuration = prepared.Json, configHash = prepared.Hash, referenceHash = prepared.ReferenceHash;
                bool cacheable = settings.Targets!.Managed?.StrongNameKeyEnvironmentVariable is null
                    && settings.Targets.Managed?.KeepFileEnvironmentVariable is null;
                if (name.Equals(MainAssemblyName, StringComparison.OrdinalIgnoreCase))
                {
                    if (primaryFound) throw new InvalidOperationException("RP_PUBLISH_PRIMARY_AMBIGUOUS: More than one publish input has the application assembly name.");
                    primaryFound = true;
                }
                byte[] bytes = ProtectionPipeline.ReadInput(input);
                var classification = TargetClassifier.Classify(bytes, input);
                if (!classification.CanProtect || classification.Target.Kind != kind)
                    throw new InvalidOperationException("RP_PUBLISH_ORDER: Protect pure IL before native compilation or bundling, and NativeAOT before signing.");
                if (classification.Target.SigningState == "authenticode-present"
                    || classification.Target.CompatibilityFeatures.Contains("authenticode-present"))
                    throw new InvalidOperationException("RP_SIGNING_ORDER: Apply Authenticode signing after publish protection.");
                string? inputPdb = File.Exists(Path.ChangeExtension(input, ".pdb")) ? Path.ChangeExtension(input, ".pdb") : null;
                string key = Hash(Encoding.UTF8.GetBytes(string.Join("\n", inputHash, inputPdb is null ? "" : FileHash(inputPdb),
                    toolHash, typeof(ProtectionPipeline).Assembly.GetName().Version, classification.Target.Kind,
                    classification.Target.Architecture, configHash, referenceHash, seed.ToString(CultureInfo.InvariantCulture))));
                string outputDirectory = Path.Combine(stage, key);
                Directory.CreateDirectory(outputDirectory);
                string output = Path.Combine(outputDirectory, name);
                string cachePath = Path.Combine(outputDirectory, "cache.json");
                string outputPdb = Path.ChangeExtension(output, ".pdb");
                string outputMap = Path.ChangeExtension(output, ".rmap.json");
                bool hit = false;
                if (cacheable && File.Exists(cachePath) && File.Exists(output))
                {
                    CacheRecord? cached = JsonSerializer.Deserialize<CacheRecord>(File.ReadAllText(cachePath));
                    hit = cached?.Key == key && cached.OutputSha256 == FileHash(output)
                        && (cached.PdbSha256 is null ? !File.Exists(outputPdb) : File.Exists(outputPdb) && cached.PdbSha256 == FileHash(outputPdb))
                        && cached.MapSha256 is not null && File.Exists(outputMap) && cached.MapSha256 == FileHash(outputMap);
                }
                if (!hit)
                {
                    string configPath = Path.Combine(outputDirectory, "configuration.json");
                    File.WriteAllText(configPath, configuration);
                    RunWorker(tool, input, output, configPath, kind);
                    var cache = new CacheRecord(key, FileHash(output), File.Exists(outputPdb) ? FileHash(outputPdb) : null, FileHash(outputMap));
                    File.WriteAllText(cachePath, JsonSerializer.Serialize(cache));
                }
                replacements.Add(input, output);
                if (inputPdb is not null)
                {
                    if (File.Exists(outputPdb) && !(kind == ProtectionTargetKind.ManagedIl && settings.Targets.Managed?.PreserveDebugSymbols == false))
                        symbolReplacements[Path.GetFullPath(inputPdb)] = outputPdb;
                    else omittedSymbols.Add(Path.GetFullPath(inputPdb));
                }
                if (name.Equals(MainAssemblyName, StringComparison.OrdinalIgnoreCase))
                    PrimaryOutputDirectory = outputDirectory + Path.DirectorySeparatorChar;
                string outputHash = FileHash(output);
                manifest.Add(new(PublicName(item), inputHash, outputHash, kind.ToString(), inputHash != outputHash)
                { ConfigurationSha256 = configHash });
            }
            if (!primaryFound) throw new InvalidOperationException("RP_PUBLISH_PRIMARY_MISSING: The application assembly was not present at the protection extension point.");
            var published = new List<ITaskItem>();
            for (int i = 0; i < Artifacts.Length; i++)
            {
                var item = Artifacts[i];
                var copy = new TaskItem(item);
                string input = Path.GetFullPath(item.ItemSpec);
                if (omittedSymbols.Contains(input))
                {
                    // Opting out of symbol preservation must also remove the SDK's
                    // original PDB item; it no longer describes the emitted IL.
                    manifest[i] = manifest[i] with { OutputSha256 = null, Role = "omitted-symbols", Changed = true };
                    continue;
                }
                if (replacements.TryGetValue(input, out string? replacement)) copy.ItemSpec = replacement;
                else if (Path.GetExtension(input).Equals(".pdb", StringComparison.OrdinalIgnoreCase)
                    && symbolReplacements.TryGetValue(input, out string? symbol)) copy.ItemSpec = symbol;
                published.Add(copy);
                string outputHash = FileHash(copy.ItemSpec);
                manifest[i] = manifest[i] with { OutputSha256 = outputHash, Changed = manifest[i].InputSha256 != outputHash };
            }
            ProtectedArtifacts = published.ToArray();
            ManifestPath = Path.Combine(stage, "manifest.json");
            ArtifactWriter.Write([new(ManifestPath, JsonSerializer.SerializeToUtf8Bytes(new
            {
                SchemaVersion = 1, ToolVersion = typeof(ProtectionPipeline).Assembly.GetName().Version?.ToString(),
                Target = kind.ToString(), Seed = seed, ConfigurationSha256 = defaults.Hash,
                ProtectionProfile = HardenedNativeAot ? "nativeaot-hardened" : "configured",
                Artifacts = manifest.OrderBy(item => item.Name, StringComparer.Ordinal).ToArray(),
            }, ProtectionSettingsJson.Options))], overwrite: true);
            return true;
        }
        catch (Exception error)
        {
            string code = error.Message.Split(':')[0];
            if (!IsReasonCode(code)) code = "RP_PUBLISH_FAILED";
            Log.LogError(null, code, null, null, 0, 0, 0, 0,
                "Rampart publish protection failed. Compiler outputs were preserved; review the selected target, configuration and publish order.");
            return false;
        }
    }

    private static void RunWorker(string tool, string input, string output, string config, ProtectionTargetKind kind)
    {
        var start = new ProcessStartInfo("dotnet") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string argument in new[] { tool, "protect", input, "--out", output, "--config", config, "--force", "--json" }) start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("RP_WORKER_START: Cannot start protection.");
        var outputRead = process.StandardOutput.BaseStream.CopyToAsync(Stream.Null);
        var errorRead = ReadDiagnosticPrefix(process.StandardError);
        if (!process.WaitForExit(660000))
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit();
            throw new InvalidOperationException("RP_WORKER_LIMIT: Protection timed out.");
        }
        outputRead.GetAwaiter().GetResult();
        string diagnostic = errorRead.GetAwaiter().GetResult();
        if (process.ExitCode != 0)
        {
            // Forward only a bounded machine reason, never the worker's message,
            // paths or exception text. A publish failure must identify an invalid
            // method selection without disclosing build/signing inputs.
            string code = diagnostic.StartsWith("error: ", StringComparison.Ordinal) ? diagnostic[7..].Split(':')[0] : "";
            if (!IsReasonCode(code)) code = "RP_PUBLISH_PROTECTION";
            throw new InvalidOperationException(code + ": The protection worker rejected the artifact.");
        }
        // The protected kind may be AlreadyProtected because a valid marker is
        // expected. A failed/opaque bundle can never be accepted as task output.
        var classification = TargetClassifier.Classify(ProtectionPipeline.ReadInput(output));
        if (classification.Target.Kind != kind && classification.Target.Kind != ProtectionTargetKind.AlreadyProtected)
            throw new InvalidOperationException("RP_WORKER_OUTPUT: The worker produced an invalid artifact.");
    }

    private static bool IsManagedSdkReference(string path)
    {
        using var stream = File.OpenRead(path);
        using var reader = new PEReader(stream);
        if (reader.PEHeaders.PEHeader is null) throw new InvalidDataException("RP_PUBLISH_VERIFICATION_REFERENCES: A compiler reference is not a PE image.");
        return reader.PEHeaders.CorHeader is not null;
    }

    private static bool IsReasonCode(string code) => code.Length is > 0 and <= 80
        && (code.StartsWith("RP_", StringComparison.Ordinal) || code.StartsWith("MANAGED_", StringComparison.Ordinal) || code.StartsWith("NAOT_", StringComparison.Ordinal))
        && code.All(character => character is >= 'A' and <= 'Z' or >= '0' and <= '9' or '_');

    private static async System.Threading.Tasks.Task<string> ReadDiagnosticPrefix(StreamReader reader)
    {
        var prefix = new StringBuilder(); var buffer = new char[512]; int count;
        while ((count = await reader.ReadAsync(buffer)) != 0)
            if (prefix.Length < 256) prefix.Append(buffer, 0, Math.Min(count, 256 - prefix.Length));
        return prefix.ToString();
    }

    private static string PublicName(ITaskItem item)
    {
        string relative = item.GetMetadata("RelativePath").Replace('\\', '/');
        return string.IsNullOrEmpty(relative) || Path.IsPathRooted(relative) || relative.Split('/').Contains("..")
            ? Path.GetFileName(item.ItemSpec) : relative;
    }
    private static string FileHash(string path) { using var stream = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(stream)); }
    private static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));
}
