using Rampart.Targets;

namespace Rampart.Config;

/// <summary>How a target handles requested work whose compatibility is unproven.</summary>
public enum CompatibilityPolicy { Preserve, Warn, Strict }

/// <summary>Target options have an independent schema version so existing native
/// configuration documents retain their meaning.</summary>
public sealed class TargetProtectionOptions
{
    public int Version { get; set; } = 1;
    public ProtectionTargetKind? Override { get; set; }
    public CompatibilityPolicy Compatibility { get; set; } = CompatibilityPolicy.Preserve;
    public ManagedProtectionOptions? Managed { get; set; }
    public NativeAotProtectionOptions? NativeAot { get; set; }

    public void Validate()
    {
        if (Version != 1)
            throw new NotSupportedException("RP_CONFIG_VERSION: Unsupported target settings version.");
        if (!Enum.IsDefined(Compatibility) || Override is { } kind && !Enum.IsDefined(kind))
            throw new ArgumentException("RP_CONFIG_VALUE: Invalid target option value.");
    }
}
