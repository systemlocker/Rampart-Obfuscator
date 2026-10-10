using Rampart.Config;

namespace Rampart.Targets;

/// <summary>An identity that does not require a particular executable format.</summary>
public sealed record ProtectionSubject(
    string Identity,
    string? Assembly = null,
    string? Module = null,
    string? Type = null,
    string? Signature = null,
    int? MetadataToken = null,
    uint? Rva = null);

public enum EvidenceDisposition { Applied, Skipped, Rejected }

/// <summary>An optional externally measured observation, with its unit and
/// provenance. Protection itself does not sample timings into deterministic maps.</summary>
public sealed record ProtectionMeasurement(string Metric, double Value, string Unit,
    string EvidenceSource, double? Baseline = null, double? Budget = null);

/// <summary>Private, per-subject evidence. Names and source identities can be
/// sensitive and must not be embedded in the protected application.</summary>
public sealed record ProtectionEvidence(
    string Protection,
    ProtectionSubject Original,
    ProtectionSubject Protected,
    string Requested,
    EvidenceDisposition Disposition,
    string ReasonCode,
    int? OriginalSize = null,
    int? ProtectedSize = null,
    string? OriginalHash = null,
    string? ProtectedHash = null,
    IReadOnlyList<ProtectionMeasurement>? Measurements = null,
    string? VerificationStatus = null);

public sealed record PlannedProtection(string Id, string Requested, string Effective, string ReasonCode);

public sealed record ProtectionPlan(
    TargetClassification Classification,
    string Backend,
    IReadOnlyList<PlannedProtection> Protections,
    IReadOnlyList<string> Diagnostics);

/// <summary>All implementations operate on private bytes. File promotion belongs
/// to the artifact writer and occurs only after validation succeeds.</summary>
public interface IProtectionBackend
{
    string Name { get; }
    ProtectionTargetKind Kind { get; }
    TargetClassification Inspect(byte[] input);
    ProtectionPlan Plan(byte[] input, ProtectionSettings settings);
    BackendProtectionResult Protect(byte[] input, ProtectionSettings settings, byte[]? symbols = null);
    void Validate(byte[] original, BackendProtectionResult result);
    IReadOnlyList<ProtectionEvidence> DescribeEvidence(BackendProtectionResult result);
}

public sealed class BackendProtectionResult
{
    public required byte[] Output { get; init; }
    public byte[]? Symbols { get; init; }
    public required ProtectionPlan Plan { get; init; }
    public required IReadOnlyList<ProtectionEvidence> Evidence { get; init; }
    public required object PrivateMap { get; init; }
    public required string InputSha256 { get; init; }
    public required string OutputSha256 { get; init; }
    public required long Seed { get; init; }
    public required int InputSize { get; init; }
    public object? Details { get; init; }
}
