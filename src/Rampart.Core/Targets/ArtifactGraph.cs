using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;

namespace Rampart.Targets;

public sealed record ArtifactNode(string RelativePath, string Role, string Sha256, long Size);

/// <summary>Signing order and opaque key-provider configuration. The environment
/// variable name identifies a provider; its value and key bytes are never read.</summary>
public sealed record ArtifactSigningInstructions(string StrongName, string Authenticode,
    string? StrongNameKeyEnvironmentVariable = null)
{
    public static ArtifactSigningInstructions ForTarget(ProtectionTarget target, string? keyEnvironmentVariable = null) => new(
        target.SigningState.StartsWith("strong-name", StringComparison.Ordinal)
            ? "Preserve assembly identity and re-sign after IL mutation."
            : keyEnvironmentVariable is null ? "No strong-name signing requested." : "Apply configured strong-name signing after IL mutation.",
        "Apply Authenticode after all protection and strong-name signing, before packaging.", keyEnvironmentVariable);
}

/// <summary>A bounded inventory of the primary artifact and its adjacent build
/// inputs. The graph contains hashes and relative names, never signing material.</summary>
public sealed record ArtifactGraph(string Primary, IReadOnlyList<ArtifactNode> Artifacts,
    ArtifactSigningInstructions? SigningInstructions = null)
{
    public static ArtifactGraph Inspect(string inputPath, TargetClassification? classification = null,
        ArtifactSigningInstructions? signingInstructions = null)
    {
        string fullPath = Path.GetFullPath(inputPath);
        string directory = Path.GetDirectoryName(fullPath)!;
        string basename = Path.GetFileNameWithoutExtension(fullPath);
        var nodes = new Dictionary<string, ArtifactNode>(StringComparer.OrdinalIgnoreCase);
        long totalBytes = 0;

        void Add(string path, string role)
        {
            if (!File.Exists(path)) return;
            if (nodes.Count >= 4096)
                throw new BadImageFormatException("RP_ARTIFACT_LIMIT: Too many related artifacts.");
            string relative = Path.GetRelativePath(directory, path).Replace('\\', '/');
            if (nodes.ContainsKey(relative)) return;
            using var file = File.OpenRead(path);
            if (file.Length > TargetClassifier.MaximumInputBytes || totalBytes + file.Length > 2L * 1024 * 1024 * 1024)
                throw new BadImageFormatException("RP_ARTIFACT_LIMIT: Related artifacts exceed the inspection byte budget.");
            totalBytes += file.Length;
            nodes.Add(relative, new(relative, role, Convert.ToHexString(SHA256.HashData(file)), file.Length));
        }

        Add(fullPath, "primary");
        Add(Path.Combine(directory, basename + ".pdb"), "symbols");
        Add(Path.Combine(directory, basename + ".runtimeconfig.json"), "runtime-configuration");
        Add(Path.Combine(directory, basename + ".deps.json"), "dependency-manifest");

        classification ??= TargetClassifier.Classify(ProtectionPipeline.ReadInput(fullPath), fullPath);
        signingInstructions ??= ArtifactSigningInstructions.ForTarget(classification.Target);
        string metadataPath = fullPath;
        if (classification.Target.Kind is ProtectionTargetKind.FrameworkDependentAppHost or ProtectionTargetKind.SelfContainedAppHost)
        {
            // A positively identified host launches its sibling application
            // assembly. Inventory that assembly's dependencies as part of the
            // same graph without loading it into the current process.
            string application = Path.Combine(directory, basename + ".dll");
            if (File.Exists(application))
            {
                Add(application, "application-assembly");
                metadataPath = application;
            }
        }
        using var stream = File.OpenRead(metadataPath);
        using var reader = new PEReader(stream);
        if (reader.HasMetadata)
        {
            var metadata = reader.GetMetadataReader();
            if (metadata.AssemblyReferences.Count > 4096)
                throw new BadImageFormatException("RP_ARTIFACT_LIMIT: Too many assembly references.");
            foreach (var handle in metadata.AssemblyReferences)
            {
                string name = metadata.GetString(metadata.GetAssemblyReference(handle).Name);
                // Assembly names are metadata, not paths supplied to a resolver.
                if (name.Length == 0 || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || name is "." or "..")
                    throw new BadImageFormatException("RP_ASSEMBLY_NAME: Invalid assembly reference name.");
                Add(Path.Combine(directory, name + ".dll"), "dependency");
            }
            int directories = 0;
            foreach (string child in Directory.EnumerateDirectories(directory))
            {
                if (++directories > 4096)
                    throw new BadImageFormatException("RP_ARTIFACT_LIMIT: Too many adjacent directories.");
                if ((File.GetAttributes(child) & FileAttributes.ReparsePoint) != 0) continue;
                Add(Path.Combine(child, basename + ".resources.dll"), "satellite-resource");
            }
        }
        return new(Path.GetFileName(fullPath), nodes.Values.OrderBy(n => n.RelativePath, StringComparer.Ordinal).ToArray(), signingInstructions);
    }
}
