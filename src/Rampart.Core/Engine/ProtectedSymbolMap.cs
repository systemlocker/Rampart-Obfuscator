using Rampart.Config;

namespace Rampart.Engine;

/// <summary>Private build sidecar. This document is never embedded in the PE.</summary>
public sealed class ProtectedSymbolMap
{
    public int SchemaVersion { get; init; } = 1;
    public required long Seed { get; init; }
    public required ulong ImageBase { get; init; }
    public required string InputSha256 { get; init; }
    public required string OutputSha256 { get; init; }
    public required List<ProtectedSymbolMapEntry> Functions { get; init; }
}

public sealed class ProtectedSymbolMapEntry
{
    public required string Name { get; init; }
    public required uint OriginalRva { get; init; }
    public required uint ProtectedRva { get; init; }
    public required uint Size { get; init; }
    /// <summary>Length of the emitted body when a transform moved this function.
    /// Size retains the original range length for source-side lookups.</summary>
    public uint? ProtectedSize { get; init; }
    public string? Transformation { get; init; }
    public string? Namespace { get; init; }
    public string? Module { get; init; }
    public string? Section { get; init; }
    public string? Source { get; init; }
    public required IReadOnlyDictionary<string, ProtectionLevel> Applied { get; init; }
}
