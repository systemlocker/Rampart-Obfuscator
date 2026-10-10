namespace Rampart.Managed;

/// <summary>Coverage of requested transformations, independent of execution or verification success.</summary>
public sealed record ManagedCoverage(int Methods, int MethodsWithIl, int ChangedMethods,
    long OriginalIlBytes, long ChangedOriginalIlBytes, int RenamedTypes, int RenamedFields,
    IReadOnlyList<ManagedProtectionCoverage> Protections)
{
    public static ManagedCoverage Create(IReadOnlyList<ManagedMethodEvidence> methods,
        IReadOnlyList<ManagedRenameEvidence> identifiers)
    {
        ArgumentNullException.ThrowIfNull(methods);
        ArgumentNullException.ThrowIfNull(identifiers);
        var rows = new List<ManagedProtectionCoverage>();
        foreach (var protection in methods.SelectMany(method => method.Requested)
            .Concat(methods.SelectMany(method => method.Sites.Select(site => site.Protection)))
            .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal))
        {
            bool Applied(ManagedMethodEvidence method) => method.Applied.Any(item =>
                item == protection || item.StartsWith(protection + ":", StringComparison.Ordinal)
                || protection == "rename" && item.StartsWith("rename-", StringComparison.Ordinal));
            var requested = methods.Where(method => method.Requested.Contains(protection, StringComparer.Ordinal)).ToArray();
            var applied = requested.Where(Applied).ToArray();
            var rejected = requested.Where(method => method.Rejected.Any(reason =>
                reason == protection || reason.StartsWith(protection + ":", StringComparison.Ordinal))).ToArray();
            var requestedSites = requested.SelectMany(method => method.Sites.Where(site => site.Protection == protection)).ToArray();
            var reasons = requested.Where(method => !Applied(method)).SelectMany(method => Reasons(method, protection))
                .GroupBy(reason => reason, StringComparer.Ordinal).OrderBy(group => group.Key, StringComparer.Ordinal)
                .Select(group => new ManagedCoverageReason(group.Key, group.Count())).ToArray();
            // Requested work is the denominator. Merely accepting an assembly, retaining
            // its unsupported methods, or emitting a helper must not increase coverage.
            rows.Add(new(protection, requested.Length, applied.Length,
                requested.Count(method => !Applied(method) && !rejected.Contains(method)), rejected.Length,
                requested.Sum(method => (long)method.OriginalIlSize), applied.Sum(method => (long)method.OriginalIlSize),
                methods.Sum(method => method.Sites.Count(site => site.Protection == protection)), requestedSites.Length,
                requestedSites.Count(site => site.Status == "applied"), requestedSites.Count(site => site.Status == "skipped"),
                requestedSites.Count(site => site.Status == "rejected"), reasons)
            {
                // Partially transformed methods still have meaningful preserved sites.
                // Keep their reasons instead of hiding them in the applied-method count.
                SiteSkipReasons = requestedSites.Where(site => site.Status == "skipped")
                    .GroupBy(site => site.Reason ?? "unspecified", StringComparer.Ordinal)
                    .OrderBy(group => group.Key, StringComparer.Ordinal)
                    .Select(group => new ManagedSiteCoverageReason(group.Key, group.Count())).ToArray()
            });
        }
        var changed = methods.Where(method => method.OriginalHash != method.ProtectedHash
            || method.Original.Signature != method.ProtectedName).ToArray();
        return new(methods.Count, methods.Count(method => method.OriginalIlSize > 0), changed.Length,
            methods.Sum(method => (long)method.OriginalIlSize), changed.Sum(method => (long)method.OriginalIlSize),
            identifiers.Count(identifier => identifier.Kind == "type"), identifiers.Count(identifier => identifier.Kind == "field"), rows);
    }

    private static IEnumerable<string> Reasons(ManagedMethodEvidence method, string protection)
    {
        var reasons = method.Skipped.Where(reason => reason.StartsWith(protection + ":", StringComparison.Ordinal)
            || reason.StartsWith("policy:", StringComparison.Ordinal) || reason.StartsWith("body:", StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal).ToArray();
        if (reasons.Length != 0) return reasons;
        // A VM owns the entire body, so a separately requested IL pass is not an
        // additional applied protection. Explain that denominator explicitly.
        return [method.TransformationOwner is null ? protection + ":not-applied"
            : protection + ":owned-by-" + method.TransformationOwner];
    }
}

public sealed record ManagedProtectionCoverage(string Protection, int MethodsRequested, int MethodsApplied,
    int MethodsSkipped, int MethodsRejected, long OriginalIlBytesRequested, long OriginalIlBytesApplied,
    int TotalSites, int RequestedSites, int AppliedSites, int SkippedSites, int RejectedSites,
    IReadOnlyList<ManagedCoverageReason> SkipReasons)
{
    public IReadOnlyList<ManagedSiteCoverageReason> SiteSkipReasons { get; init; } = [];
}

public sealed record ManagedCoverageReason(string Reason, int Methods);
public sealed record ManagedSiteCoverageReason(string Reason, int Sites);
