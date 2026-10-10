using Rampart.Config;

namespace Rampart.NativeAot;

public enum NativeAotPassDisposition { Direct, Adapt, Blocked, RequiresRuntimeMetadataProof }
public enum NativeAotEvidenceStatus { Disabled, Planned, Applied, Skipped, Downgraded, Rejected }

public sealed record NativeAotPassEvidence(
    string Knob, ProtectionLevel Requested, ProtectionLevel Effective,
    NativeAotPassDisposition Disposition, NativeAotEvidenceStatus Status,
    string ReasonCode, string Detail, int ChangedBytes = 0);

public sealed record NativeAotOwnedRange(string Name, int FileOffset, int Length, string Sha256);
public sealed record NativeAotInvariantEvidence(string Pass, bool Preserved, string InputSha256, string OutputSha256);

/// <summary>Deterministic evidence; runtime measurements belong in a separate benchmark artifact.</summary>
public sealed record NativeAotReport(
    string InputSha256, string OutputSha256, long Seed, int InputBytes, int OutputBytes,
    bool AuditOnly, bool ReadyForAuthenticode,
    IReadOnlyList<NativeAotOwnedRange> OwnedRanges,
    IReadOnlyList<NativeAotPassEvidence> Passes,
    IReadOnlyList<NativeAotInvariantEvidence> Invariants)
{
    public bool CanProtect => Passes.All(pass => pass.Status != NativeAotEvidenceStatus.Rejected);
}

public sealed record NativeAotResult(byte[] Output, NativeAotReport Report);

public sealed class NativeAotCompatibilityException(string reasonCode, string message) : InvalidOperationException($"{reasonCode}: {message}")
{
    public string ReasonCode { get; } = reasonCode;
}
