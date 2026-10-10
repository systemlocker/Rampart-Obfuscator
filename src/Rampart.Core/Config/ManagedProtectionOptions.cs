namespace Rampart.Config;

/// <summary>Opt-in settings for pure-IL assemblies. Disabled settings preserve the original image.</summary>
public sealed class ManagedProtectionOptions
{
    public bool Strings { get; set; }
    public bool Constants { get; set; }
    public bool MetadataHygiene { get; set; }
    public bool Integrity { get; set; }
    public bool RenamePrivateMembers { get; set; }
    public bool ControlFlow { get; set; }
    public bool Virtualize { get; set; }
    /// <summary>Use authenticated encrypted payloads and method-specific VM dispatch.
    /// Intended for modern .NET, including transformation before NativeAOT compilation.
    /// Embedded decoding keys do not provide confidentiality from the running application.</summary>
    public bool HardenedRuntime { get; set; }
    /// <summary>Reject instead of retaining a selected method that cannot be virtualized.
    /// At least one method must be explicitly selected and successfully virtualized.</summary>
    public bool RequireVirtualization { get; set; }
    public string? Watermark { get; set; }
    public bool RemoveWatermark { get; set; }
    public bool StrictCompatibility { get; set; }
    public bool PreserveDebugSymbols { get; set; } = true;
    public string? StrongNameKeyEnvironmentVariable { get; set; }
    public List<ManagedMethodRule> Rules { get; set; } = [];
    public List<string> KeepPatterns { get; set; } = [];
    public string? KeepFileEnvironmentVariable { get; set; }
    public int MaximumProtectionMilliseconds { get; set; } = 60_000;
    public int MaximumVmInstructionCount { get; set; } = 4096;
    public int MaximumInputBytes { get; set; } = 64 * 1024 * 1024;
    public int MaximumMethods { get; set; } = 100_000;
    public int MaximumMethodBytes { get; set; } = 1024 * 1024;
    public int MaximumMetadataRows { get; set; } = 1_000_000;
    public int MaximumOutputGrowthPercent { get; set; } = 200;
    /// <summary>Require ECMA-335 nominal verifiability using an explicit dependency set, including unchanged methods. CLR-permitted unsafe IL may fail this policy. Omission leaves only the structural/category verifier active.</summary>
    public ManagedVerificationOptions? Verification { get; set; }
}

/// <summary>References are read as metadata; no inspected assembly is loaded or executed.</summary>
public sealed class ManagedVerificationOptions
{
    public List<string> ReferencePaths { get; set; } = [];
    /// <summary>Subset of ReferencePaths from the selected target framework. Older transitive framework identities may bind upward to these files, as the CLR does; application references remain exact.</summary>
    public List<string> FrameworkReferencePaths { get; set; } = [];
    public string? SystemModuleName { get; set; }
    public int MaximumReferenceCount { get; set; } = 1024;
    public long MaximumReferenceBytes { get; set; } = 512L * 1024 * 1024;
}

/// <summary>Ordered rules; the last matching rule wins. Patterns use * and ?.</summary>
public sealed class ManagedMethodRule
{
    public string Assembly { get; set; } = "*";
    public string Module { get; set; } = "*";
    public string Namespace { get; set; } = "*";
    public string Type { get; set; } = "*";
    public string Method { get; set; } = "*";
    public string Signature { get; set; } = "*";
    public string SourceDocument { get; set; } = "*";
    public int? MetadataToken { get; set; }
    public bool? GeneratedCode { get; set; }
    public bool? Include { get; set; }
    public bool? Virtualize { get; set; }
    public bool? Strings { get; set; }
    public bool? Constants { get; set; }
    public bool? ControlFlow { get; set; }
    public bool? RenamePrivateMembers { get; set; }
}
