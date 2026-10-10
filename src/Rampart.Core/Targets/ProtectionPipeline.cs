using Rampart.Config;

namespace Rampart.Targets;

/// <summary>Dispatches only after read-only target admission and policy checks.</summary>
public sealed class ProtectionPipeline
{
    public ProtectionPlan Plan(byte[] input, ProtectionSettings settings)
    {
        var classification = TargetClassifier.Classify(input);
        return BackendFor(classification, settings).Plan(input, settings);
    }

    public BackendProtectionResult Protect(byte[] input, ProtectionSettings settings, byte[]? symbols = null)
    {
        var classification = TargetClassifier.Classify(input);
        IProtectionBackend backend = BackendFor(classification, settings);
        _ = backend.Plan(input, settings);
        BackendProtectionResult result = backend.Protect(input, settings, symbols);
        backend.Validate(input, result);
        return result;
    }

    public static IProtectionBackend BackendFor(TargetClassification classification, ProtectionSettings settings)
    {
        RequireTarget(classification, settings, classification.Target.Kind);
        return classification.Target.Kind switch
        {
            ProtectionTargetKind.NativePe => new NativePeBackend(),
            ProtectionTargetKind.NativeAot => new NativeAotProtectionBackend(),
            ProtectionTargetKind.ManagedIl => new ManagedProtectionBackend(),
            _ => throw new NotSupportedException("RP_BACKEND_UNAVAILABLE: No protection backend is available for this artifact."),
        };
    }

    internal static void RequireTarget(TargetClassification classification, ProtectionSettings settings, ProtectionTargetKind kind)
    {
        settings.Targets?.Validate();
        if (!classification.CanProtect || classification.Target.Kind != kind)
        {
            string guidance = classification.Target.Kind switch
            {
                ProtectionTargetKind.FrameworkDependentAppHost or ProtectionTargetKind.SelfContainedAppHost =>
                    " Protect the application assembly before publishing; the apphost cannot be protected alone.",
                ProtectionTargetKind.SingleFileBundle => " Protect the inputs before single-file bundling.",
                ProtectionTargetKind.ReadyToRun => " Protect the IL assembly before ReadyToRun compilation.",
                _ => " The input is not eligible for protection.",
            };
            throw new NotSupportedException(classification.ReasonCode + ":" + guidance);
        }
        // Overrides are assertions about a structurally validated target, never
        // permission to treat a managed host or opaque bundle as native code.
        if (settings.Targets?.Override is { } selected && selected != classification.Target.Kind)
            throw new NotSupportedException("RP_TARGET_OVERRIDE_MISMATCH: The target override does not match the input structure.");
    }

    public static byte[] ReadInput(string path)
    {
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length > TargetClassifier.MaximumInputBytes)
            throw new BadImageFormatException("target.input-limit: Input exceeds the supported size limit.");
        byte[] bytes = new byte[checked((int)input.Length)];
        input.ReadExactly(bytes);
        return bytes;
    }
}
