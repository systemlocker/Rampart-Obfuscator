namespace Rampart.Config;

/// <summary>Options for post-publish Windows x64 NativeAOT images.</summary>
public sealed class NativeAotProtectionOptions
{
    /// <summary>Inspect and plan without changing any input bytes.</summary>
    public bool AuditOnly { get; set; }

    /// <summary>Validate an unsigned image for a subsequent Authenticode signing step.
    /// Existing signatures are never silently removed.</summary>
    public bool PrepareForSigning { get; set; }
}
