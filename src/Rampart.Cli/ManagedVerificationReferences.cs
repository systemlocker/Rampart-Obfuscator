using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text.Json;
using Rampart.Config;
using Rampart.Managed;

namespace Rampart.Cli;

internal static class ManagedVerificationReferences
{
    public static void Configure(string input, ProtectionSettings settings, List<string> explicitReferences, string? systemModule, bool resolveAutomatic)
    {
        settings.Targets ??= new();
        settings.Targets.Managed ??= new();
        var options = settings.Targets.Managed.Verification;
        if (options is null && explicitReferences.Count == 0)
        {
            if (systemModule is not null)
                throw new ArgumentException("MANAGED_VERIFICATION_REFERENCES: --verification-system-module requires an explicit reference set.");
            if (!resolveAutomatic) return; // Discovery runs under the protection worker's budgets.
            options = Discover(input);
        }
        options ??= new();
        options.ReferencePaths.AddRange(explicitReferences.Select(Path.GetFullPath));
        options.ReferencePaths = options.ReferencePaths.Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        options.SystemModuleName = systemModule ?? options.SystemModuleName;
        settings.Targets.Managed.Verification = options;
    }

    internal static ManagedVerificationOptions Discover(string input, byte[]? image = null)
    {
        using Stream stream = image is null ? File.OpenRead(input) : new MemoryStream(image, writable: false);
        using var reader = new PEReader(stream);
        var metadata = reader.GetMetadataReader();
        string? framework = null;
        foreach (var handle in metadata.GetAssemblyDefinition().GetCustomAttributes())
        {
            var attribute = metadata.GetCustomAttribute(handle);
            if (attribute.Constructor.Kind != HandleKind.MemberReference) continue;
            var parent = metadata.GetMemberReference((MemberReferenceHandle)attribute.Constructor).Parent;
            if (parent.Kind != HandleKind.TypeReference) continue;
            var type = metadata.GetTypeReference((TypeReferenceHandle)parent);
            if (metadata.GetString(type.Namespace) != "System.Runtime.Versioning" || metadata.GetString(type.Name) != "TargetFrameworkAttribute") continue;
            var blob = metadata.GetBlobReader(attribute.Value);
            if (blob.ReadUInt16() != 1) throw new BadImageFormatException();
            framework = blob.ReadSerializedString();
        }
        bool frameworkReference = metadata.AssemblyReferences.Any(handle =>
            metadata.GetString(metadata.GetAssemblyReference(handle).Name) == "mscorlib");
        string inputIdentity = metadata.GetString(metadata.GetAssemblyDefinition().Name);
        var paths = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var frameworkPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void AddDirectory(string directory, bool local = false, bool frameworkSource = false)
        {
            var localNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string path in Directory.EnumerateFiles(directory, "*.dll").Order(StringComparer.Ordinal))
            {
                if (new FileInfo(path).Length > 256L * 1024 * 1024)
                    throw new ManagedProtectionException("MANAGED_VERIFICATION_LIMIT", "A potential verification reference exceeds the supported byte budget.");
                using var file = File.OpenRead(path);
                try
                {
                    using var pe = new PEReader(file);
                    if (pe.HasMetadata && pe.GetMetadataReader().IsAssembly)
                    {
                        string name = pe.GetMetadataReader().GetString(pe.GetMetadataReader().GetAssemblyDefinition().Name);
                        if (name.Equals(inputIdentity, StringComparison.OrdinalIgnoreCase)) continue;
                        if (local && !localNames.Add(name))
                            throw new ManagedProtectionException("MANAGED_VERIFICATION_REFERENCE_AMBIGUOUS", "The input directory contains multiple assemblies with the same name. Supply explicit verification references.");
                        paths[name] = path;
                        if (frameworkSource) frameworkPaths.Add(path);
                        if (paths.Count > 1024)
                            throw new ManagedProtectionException("MANAGED_VERIFICATION_LIMIT", "Too many verification references were discovered. Supply an explicit dependency set.");
                    }
                }
                catch (BadImageFormatException) { /* Native companions are not verification references. */ }
            }
        }
        string directory = Path.GetDirectoryName(input)!;
        string runtimeConfig = Path.ChangeExtension(input, ".runtimeconfig.json");
        var frameworks = new List<(string Name, Version Version)>();
        if (File.Exists(runtimeConfig))
        {
            if (new FileInfo(runtimeConfig).Length > 1024 * 1024)
                throw new ManagedProtectionException("MANAGED_VERIFICATION_LIMIT", "The runtime configuration exceeds the supported size.");
            using var config = JsonDocument.Parse(File.ReadAllText(runtimeConfig));
            var runtime = config.RootElement.GetProperty("runtimeOptions");
            void AddFramework(JsonElement item)
            {
                string name = item.GetProperty("name").GetString()!;
                if (name is not ("Microsoft.NETCore.App" or "Microsoft.WindowsDesktop.App" or "Microsoft.AspNetCore.App"))
                    throw new ManagedProtectionException("MANAGED_VERIFICATION_RUNTIME", "Supply explicit references for this runtime framework.");
                frameworks.Add((name, Version.Parse(item.GetProperty("version").GetString()!)));
            }
            if (runtime.TryGetProperty("framework", out var single)) AddFramework(single);
            if (runtime.TryGetProperty("frameworks", out var multiple)) foreach (var item in multiple.EnumerateArray()) AddFramework(item);
        }
        bool legacy = framework?.StartsWith(".NETFramework,Version=v4", StringComparison.Ordinal) == true
            || framework is null && frameworkReference && frameworks.Count == 0;
        if (legacy)
        {
            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string references = Path.Combine(windows, "Microsoft.NET", "Framework64", "v4.0.30319");
            if (!Directory.Exists(references)) throw new ManagedProtectionException("MANAGED_VERIFICATION_RUNTIME", "Supply .NET Framework verification references explicitly on this host.");
            AddDirectory(references);
            if (Directory.Exists(Path.Combine(references, "WPF"))) AddDirectory(Path.Combine(references, "WPF"));
        }
        else if (!File.Exists(Path.Combine(directory, "System.Private.CoreLib.dll")))
        {
            if (frameworks.Count == 0)
            {
                const string prefix = ".NETCoreApp,Version=v";
                if (framework is null || !framework.StartsWith(prefix, StringComparison.Ordinal)
                    || !Version.TryParse(framework[prefix.Length..], out var targetVersion))
                    throw new ManagedProtectionException("MANAGED_VERIFICATION_RUNTIME", "The target runtime is unknown. Supply explicit verification references.");
                frameworks.Add(("Microsoft.NETCore.App", targetVersion));
            }
            if (!frameworks.Any(item => item.Name == "Microsoft.NETCore.App"))
                frameworks.Insert(0, ("Microsoft.NETCore.App", frameworks[0].Version));
            var sharedRoots = new List<string>();
            string processShared = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(typeof(object).Assembly.Location)!, "..", ".."));
            if (Path.GetFileName(processShared).Equals("shared", StringComparison.OrdinalIgnoreCase)) sharedRoots.Add(processShared);
            // A self-contained protector carries CoreLib beside the executable;
            // walking its parents does not locate the user's shared frameworks.
            // Use explicit/standard dotnet roots as well, but retain the declared
            // target family's exact major/minor restriction below.
            foreach (string? root in new[] { Environment.GetEnvironmentVariable("DOTNET_ROOT_X64"), Environment.GetEnvironmentVariable("DOTNET_ROOT"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet") })
                if (!string.IsNullOrWhiteSpace(root)) sharedRoots.Add(Path.Combine(Path.GetFullPath(root), "shared"));
            foreach (var target in frameworks.OrderBy(item => item.Name == "Microsoft.NETCore.App" ? 0 : 1))
            {
                string? selected = sharedRoots.Distinct(StringComparer.OrdinalIgnoreCase).Select(root => Path.Combine(root, target.Name))
                    .Where(Directory.Exists).SelectMany(Directory.EnumerateDirectories)
                    .Select(path => (Path: path, Version: Version.TryParse(Path.GetFileName(path), out var version) ? version : null))
                    .Where(item => item.Version is not null && item.Version.Major == target.Version.Major && item.Version.Minor == target.Version.Minor
                        && item.Version >= target.Version)
                    .OrderByDescending(item => item.Version).ThenBy(item => item.Path, StringComparer.Ordinal).Select(item => item.Path).FirstOrDefault();
                if (selected is null)
                    throw new ManagedProtectionException("MANAGED_VERIFICATION_RUNTIME", $"Install the matching {target.Name} {target.Version.Major}.{target.Version.Minor} runtime or supply its reference assemblies explicitly.");
                AddDirectory(selected, frameworkSource: true);
            }
        }
        // A self-contained deployment declares runtime-pack provenance in its
        // deps manifest. Only those assets receive framework binding semantics;
        // an arbitrary local System.* package does not become a framework file.
        if (File.Exists(Path.Combine(directory, "System.Private.CoreLib.dll")))
        {
            string depsPath = Path.ChangeExtension(input, ".deps.json");
            if (File.Exists(depsPath))
            {
                if (new FileInfo(depsPath).Length > 16L * 1024 * 1024)
                    throw new ManagedProtectionException("MANAGED_VERIFICATION_LIMIT", "The dependency manifest exceeds the supported size.");
                using var deps = JsonDocument.Parse(File.ReadAllText(depsPath));
                if (deps.RootElement.TryGetProperty("targets", out var targets))
                    foreach (var target in targets.EnumerateObject())
                        foreach (var library in target.Value.EnumerateObject())
                        {
                            string name = library.Name.StartsWith("runtimepack.", StringComparison.Ordinal) ? library.Name[12..] : library.Name;
                            if (!name.StartsWith("Microsoft.NETCore.App.Runtime.", StringComparison.Ordinal)
                                && !name.StartsWith("Microsoft.WindowsDesktop.App.Runtime.", StringComparison.Ordinal)
                                && !name.StartsWith("Microsoft.AspNetCore.App.Runtime.", StringComparison.Ordinal)) continue;
                            if (library.Value.TryGetProperty("runtime", out var runtime))
                                foreach (var asset in runtime.EnumerateObject())
                                    frameworkPaths.Add(Path.Combine(directory, Path.GetFileName(asset.Name)));
                        }
            }
        }
        // Local deployment assets win over framework facades (for example WPF's
        // WindowsBase). The resolver still requires exact metadata identities.
        AddDirectory(directory, local: true);
        return new()
        {
            ReferencePaths = paths.Values.Order(StringComparer.Ordinal).ToList(),
            FrameworkReferencePaths = paths.Values.Where(frameworkPaths.Contains).Order(StringComparer.Ordinal).ToList(),
            SystemModuleName = legacy ? "mscorlib" : "System.Private.CoreLib"
        };
    }
}
