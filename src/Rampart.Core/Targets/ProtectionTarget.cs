namespace Rampart.Targets;

/// <summary>The format and deployment role of an input, independent of its file extension.</summary>
public enum ProtectionTargetKind
{
    NativePe, NativeAot, ManagedIl, ReadyToRun, FrameworkDependentAppHost,
    SelfContainedAppHost, SingleFileBundle, MixedMode, AlreadyProtected, Unknown
}

public enum TargetDisposition { Supported, Inspect, Unsupported, Ambiguous }

public sealed record ProtectionTarget(
    ProtectionTargetKind Kind,
    string Architecture,
    string RuntimeFamily,
    string DeploymentShape,
    string SigningState,
    IReadOnlyList<string> CompatibilityFeatures);

/// <summary>Read-only inspection result. Backend planning still validates each requested operation.</summary>
public sealed record TargetClassification(
    ProtectionTarget Target,
    TargetDisposition Disposition,
    string ReasonCode,
    IReadOnlyList<string> Evidence)
{
    public bool CanProtect => Disposition == TargetDisposition.Supported;
}
