namespace Rampart.Managed;

public sealed record ManagedMethodIdentity(string StableId, string Assembly, string Module,
    string Namespace, string Type, string Method, string Signature, int MetadataToken,
    string? SourceDocument, bool GeneratedCode);

public sealed record ManagedMethodEvidence(ManagedMethodIdentity Original, int ProtectedToken,
    string ProtectedName, string OriginalHash, string ProtectedHash, string? TransformationOwner,
    IReadOnlyList<string> Applied, IReadOnlyList<string> Skipped)
{
    public IReadOnlyList<ManagedSiteEvidence> Sites { get; init; } = [];
    public IReadOnlyList<string> Requested { get; init; } = [];
    public IReadOnlyList<string> Rejected { get; init; } = [];
    public int OriginalIlSize { get; init; }
    public int ProtectedIlSize { get; init; }
    public IReadOnlyList<ManagedSequencePointMapping> SequencePoints { get; init; } = [];
    public string VerificationStatus { get; init; } = "not-assessed";
}

public sealed record ManagedSiteEvidence(string StableId, int OriginalIlOffset, string Protection, string Status, string? Reason);

public sealed record ManagedSequencePointMapping(int OriginalMethodToken, int ProtectedMethodToken,
    int OriginalIlOffset, int? ProtectedIlOffset, string OriginalDocument, string? ProtectedDocument,
    int StartLine, int StartColumn, int EndLine, int EndColumn, string Status);

public sealed record ManagedTokenMapping(int OriginalToken, int ProtectedToken)
{
    public string Status { get; init; } = "mapped";
}

public sealed record ManagedProtectionResult(byte[] Output, byte[]? PdbOutput,
    IReadOnlyList<ManagedMethodEvidence> Evidence, IReadOnlyList<ManagedTokenMapping> TokenMap,
    string InputSha256, string OutputSha256, IReadOnlyList<string> Diagnostics)
{
    public IReadOnlyList<ManagedRenameEvidence> IdentifierRenames { get; init; } = [];
    public ManagedVerificationReport? Verification { get; init; }
    public ManagedCoverage Coverage => ManagedCoverage.Create(Evidence, IdentifierRenames);
}

public sealed record ManagedRenameEvidence(int OriginalToken, int ProtectedToken, string OriginalName, string ProtectedName, string Kind, string Reason);

public sealed class ManagedProtectionException : InvalidOperationException
{
    public string ReasonCode { get; }
    public ManagedProtectionException(string reasonCode, string message) : base($"{reasonCode}: {message}")
        => ReasonCode = reasonCode;
}
