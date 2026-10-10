using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using ILVerify;
using Rampart.Config;

namespace Rampart.Managed;

public sealed record ManagedVerificationReference(string Identity, string Sha256);
public sealed record ManagedFrameworkBinding(string RequestedIdentity, string ResolvedIdentity);
public sealed record ManagedVerificationReport(string Engine, string Status, string SystemModule,
    string OutputSha256, int VerifiedMethods, int VerifiedTypes, IReadOnlyList<ManagedVerificationReference> References,
    IReadOnlyList<ManagedFrameworkBinding> FrameworkBindings)
{
    public string? EngineSha256 { get; init; }
}

/// <summary>Independent ECMA-335 verification against the caller's exact assembly graph.</summary>
public static class ManagedVerification
{
    public static ManagedProtectionResult VerifyResult(ManagedProtectionResult result, ManagedProtectionOptions options)
    {
        if (options.Verification is null) return result;
        var report = Verify(result.Output, options.Verification);
        return result with
        {
            Verification = report,
            Evidence = result.Evidence.Select(method => method with { VerificationStatus = "verified-nominal" }).ToArray(),
            Diagnostics = result.Diagnostics.Where(code => code != "MANAGED_NOMINAL_VERIFICATION_REQUIRED"
                && !code.StartsWith("MANAGED_NOMINAL_VERIFICATION_REQUIRED:", StringComparison.Ordinal))
                .Append("MANAGED_NOMINAL_VERIFIED").ToArray(),
        };
    }

    public static ManagedVerificationReport Verify(byte[] image, ManagedVerificationOptions options)
    {
        ArgumentNullException.ThrowIfNull(image);
        ArgumentNullException.ThrowIfNull(options);
        try
        {
            using var resolver = new BoundedResolver(image, options);
            var verifier = new Verifier(resolver, new VerifierOptions { SanityChecks = true });
            verifier.SetSystemModuleName(AssemblyNameInfo.Parse(resolver.SystemIdentity));
            var metadata = resolver.Root.GetMetadataReader();
            int methods = 0, types = 0;
            // The library's assembly overload verifies methods only. Check each
            // type separately so invalid interfaces and generic constraints cannot
            // disappear behind a successful method-body pass.
            foreach (var handle in metadata.TypeDefinitions)
            {
                RejectErrors(verifier.Verify(resolver.Root, handle), MetadataTokens.GetToken(handle));
                types++;
            }
            foreach (var handle in metadata.MethodDefinitions)
            {
                RejectErrors(verifier.Verify(resolver.Root, handle), MetadataTokens.GetToken(handle));
                methods++;
            }
            var assembly = typeof(Verifier).Assembly;
            string version = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                ?? assembly.GetName().Version?.ToString() ?? "unknown";
            return new("Microsoft.ILVerification/" + version, "verified", resolver.SystemIdentity,
                Convert.ToHexString(SHA256.HashData(image)), methods, types, resolver.Evidence, resolver.FrameworkBindings)
            {
                EngineSha256 = string.IsNullOrEmpty(assembly.Location) ? null : Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(assembly.Location))),
            };
        }
        catch (ManagedProtectionException) { throw; }
        catch (Exception error) when (error is BadImageFormatException or IOException or UnauthorizedAccessException or ArgumentException)
        {
            throw Failure("MANAGED_VERIFICATION_REFERENCE_INVALID", "A verification input is unreadable or contains invalid metadata. Supply valid reference assemblies for the target framework.");
        }
    }

    private static void RejectErrors(IEnumerable<VerificationResult> errors, int token)
    {
        using var cursor = errors.GetEnumerator();
        if (cursor.MoveNext())
            throw Failure("MANAGED_NOMINAL_VERIFICATION_FAILED", $"Metadata token 0x{token:X8} does not satisfy ECMA-335 verifiability ({cursor.Current.Code}). This policy also rejects unverifiable unsafe IL that the CLR may permit. No output was promoted.");
    }

    private static ManagedProtectionException Failure(string code, string message) => new(code, message);

    private sealed class BoundedResolver : IResolver, IDisposable
    {
        private sealed record Reference(AssemblyName Identity, PEReader Reader, Stream Stream, string Hash);
        private readonly Dictionary<string, Reference> references = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<Reference> opened = [];
        private readonly HashSet<string> used = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> frameworks = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, ManagedFrameworkBinding> bindings = new(StringComparer.Ordinal);
        public IReadOnlyList<ManagedFrameworkBinding> FrameworkBindings => bindings.Values.OrderBy(value => value.RequestedIdentity, StringComparer.Ordinal).ToArray();
        public PEReader Root { get; }
        public string SystemIdentity { get; }
        public IReadOnlyList<ManagedVerificationReference> Evidence => used.Order(StringComparer.Ordinal)
            .Select(name => references[name]).Select(reference => new ManagedVerificationReference(reference.Identity.FullName, reference.Hash)).ToArray();

        public BoundedResolver(byte[] image, ManagedVerificationOptions options)
        {
            if (options.MaximumReferenceCount is < 1 or > 4096 || options.MaximumReferenceBytes is < 1 or > 2L * 1024 * 1024 * 1024
                || options.ReferencePaths.Count > options.MaximumReferenceCount)
                throw Failure("MANAGED_VERIFICATION_LIMIT", "The verification reference set exceeds its configured bounds.");
            var stream = new MemoryStream(image, writable: false);
            Root = new PEReader(stream);
            try
            {
                var root = new Reference(ReadIdentity(Root), Root, stream, Convert.ToHexString(SHA256.HashData(image)));
                opened.Add(root);
                references.Add(root.Identity.Name!, root);
                var frameworkPaths = options.FrameworkReferencePaths.Select(Path.GetFullPath).ToHashSet(StringComparer.OrdinalIgnoreCase);
                if (!frameworkPaths.IsSubsetOf(options.ReferencePaths.Select(Path.GetFullPath)))
                    throw Failure("MANAGED_VERIFICATION_REFERENCE_INVALID", "Framework references must be included in the explicit reference set.");
                long total = 0;
                foreach (string path in options.ReferencePaths.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    var input = new FileStream(Path.GetFullPath(path), FileMode.Open, FileAccess.Read, FileShare.Read);
                    PEReader? reader = null;
                    try
                    {
                        total = checked(total + input.Length);
                        if (total > options.MaximumReferenceBytes || input.Length > 256L * 1024 * 1024)
                            throw Failure("MANAGED_VERIFICATION_LIMIT", "The verification references exceed the configured byte budget.");
                        string hash = Convert.ToHexString(SHA256.HashData(input));
                        input.Position = 0;
                        reader = new PEReader(input, PEStreamOptions.LeaveOpen);
                        var identity = ReadIdentity(reader);
                        if (frameworkPaths.Contains(Path.GetFullPath(path))) frameworks.Add(identity.Name!);
                        if (references.TryGetValue(identity.Name!, out var previous))
                        {
                            // The unmodified input may occur in build references;
                            // resolve self references to the emitted image instead.
                            if (previous == root && SameIdentity(identity, root.Identity)) continue;
                            if (SameIdentity(identity, previous.Identity) && hash == previous.Hash) continue;
                            throw Failure("MANAGED_VERIFICATION_REFERENCE_AMBIGUOUS", "Multiple different assemblies have the same verification reference name. Supply one target-specific dependency set.");
                        }
                        var reference = new Reference(identity, reader, input, hash);
                        references.Add(identity.Name!, reference);
                        opened.Add(reference);
                        reader = null; // Ownership transfers to the resolver.
                        input = null!;
                    }
                    finally { reader?.Dispose(); input?.Dispose(); }
                }
                string system = options.SystemModuleName ?? (references.ContainsKey("System.Private.CoreLib") ? "System.Private.CoreLib" : "mscorlib");
                if (!references.TryGetValue(system, out var systemReference))
                    throw Failure("MANAGED_VERIFICATION_SYSTEM_MODULE_MISSING", "Supply the target framework's System.Private.CoreLib or mscorlib verification reference.");
                SystemIdentity = systemReference.Identity.FullName;
                ResolveClosure(root);
                ResolveClosure(systemReference);
            }
            catch { Dispose(); throw; }
        }

        private void ResolveClosure(Reference initial)
        {
            var queue = new Queue<Reference>(); queue.Enqueue(initial);
            while (queue.TryDequeue(out var current))
            {
                if (!used.Add(current.Identity.Name!)) continue;
                var metadata = current.Reader.GetMetadataReader();
                foreach (var handle in metadata.AssemblyReferences)
                {
                    var identity = metadata.GetAssemblyReference(handle).GetAssemblyName();
                    queue.Enqueue(Find(identity, allowFrameworkBinding: current.Reader != Root));
                }
            }
        }

        public PEReader ResolveAssembly(AssemblyNameInfo assemblyName)
        {
            var reference = Find(new AssemblyName(assemblyName.FullName));
            used.Add(reference.Identity.Name!);
            return reference.Reader;
        }

        public PEReader ResolveModule(AssemblyNameInfo referencingAssembly, string fileName)
            => throw Failure("MANAGED_VERIFICATION_MULTIMODULE_UNSUPPORTED", "Multi-module verification inputs are not supported.");

        private Reference Find(AssemblyName requested, bool allowFrameworkBinding = false)
        {
            if (!references.TryGetValue(requested.Name!, out var reference))
                throw Failure("MANAGED_VERIFICATION_REFERENCE_MISSING", $"Supply the exact dependency '{requested.FullName}' to verify this assembly.");
            if (!SameIdentity(requested, reference.Identity)
                && !(bindings.ContainsKey(requested.FullName) || allowFrameworkBinding && TryFrameworkBinding(requested, reference.Identity)))
                throw Failure("MANAGED_VERIFICATION_REFERENCE_VERSION", $"The reference for '{requested.Name}' has a different version, culture, or public key token. Supply the target framework's exact reference set.");
            return reference;
        }

        private bool TryFrameworkBinding(AssemblyName requested, AssemblyName resolved)
        {
            // A package compiled for an older TFM can run on a newer app TFM.
            // Record that target-framework binding explicitly; never generalize
            // it to arbitrary packages, a different signing key, or a downgrade.
            if (!frameworks.Contains(resolved.Name!) || requested.Version >= resolved.Version
                || (requested.GetPublicKeyToken()?.Length ?? 0) == 0 || !SameNameAndKey(requested, resolved)) return false;
            bindings[requested.FullName] = new(requested.FullName, resolved.FullName);
            return true;
        }

        private static AssemblyName ReadIdentity(PEReader reader)
        {
            if (!reader.HasMetadata) throw new BadImageFormatException();
            var metadata = reader.GetMetadataReader();
            if (!metadata.IsAssembly) throw new BadImageFormatException();
            return metadata.GetAssemblyDefinition().GetAssemblyName();
        }

        private static bool SameIdentity(AssemblyName left, AssemblyName right) => left.Version == right.Version && SameNameAndKey(left, right);
        private static bool SameNameAndKey(AssemblyName left, AssemblyName right) =>
            string.Equals(left.Name, right.Name, StringComparison.OrdinalIgnoreCase)
            && string.Equals(left.CultureName ?? "", right.CultureName ?? "", StringComparison.OrdinalIgnoreCase)
            && (left.GetPublicKeyToken() ?? []).AsSpan().SequenceEqual(right.GetPublicKeyToken() ?? []);

        public void Dispose()
        {
            foreach (var reference in opened) { reference.Reader.Dispose(); reference.Stream.Dispose(); }
            opened.Clear();
        }
    }
}
