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
        if (Managed is { } managed)
        {
            if (managed.Rules is null || managed.KeepPatterns is null)
                throw new ArgumentException("RP_CONFIG_VALUE: Managed option collections cannot be null.");
            if (managed.Rules.Any(rule => rule is null
                || rule.Assembly is null || rule.Module is null || rule.Namespace is null
                || rule.Type is null || rule.Method is null || rule.Signature is null || rule.SourceDocument is null))
                throw new ArgumentException("RP_CONFIG_VALUE: Managed method rules and their selector patterns cannot be null.");
            if (managed.KeepPatterns.Any(pattern => pattern is null))
                throw new ArgumentException("RP_CONFIG_VALUE: Managed keep patterns cannot contain null entries.");
            if (managed.MaximumProtectionMilliseconds <= 0 || managed.MaximumVmInstructionCount <= 0
                || managed.MaximumInputBytes <= 0 || managed.MaximumMethods <= 0
                || managed.MaximumMethodBytes <= 0 || managed.MaximumMetadataRows <= 0
                || managed.MaximumOutputGrowthPercent < 0)
                throw new ArgumentException("RP_CONFIG_VALUE: Managed budget limits must be positive.");
            if (managed.Verification is { } verification)
            {
                if (verification.ReferencePaths is null || verification.FrameworkReferencePaths is null
                    || verification.ReferencePaths.Any(path => path is null)
                    || verification.FrameworkReferencePaths.Any(path => path is null))
                    throw new ArgumentException("RP_CONFIG_VALUE: Managed verification reference lists cannot be null or contain null entries.");
                if (verification.MaximumReferenceCount <= 0 || verification.MaximumReferenceBytes <= 0)
                    throw new ArgumentException("RP_CONFIG_VALUE: Managed verification limits must be positive.");
            }
        }
    }
}
