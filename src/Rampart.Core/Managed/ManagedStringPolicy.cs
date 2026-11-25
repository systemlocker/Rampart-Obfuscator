using Mono.Cecil;

namespace Rampart.Managed;

internal static class ManagedStringPolicy
{
    internal static bool IsMetadataOwnedConsumer(MethodReference callee)
    {
        var ns = ManagedPolicy.EffectiveNamespace(callee.DeclaringType);
        return ns.StartsWith("System.Resources", StringComparison.Ordinal)
            || ns.StartsWith("System.Runtime.InteropServices", StringComparison.Ordinal)
            || ns.StartsWith("System.Runtime.Serialization", StringComparison.Ordinal)
            || (callee.DeclaringType.FullName == "System.Reflection.Assembly"
                && callee.Name is "GetManifestResourceStream" or "GetManifestResourceInfo");
    }
    // Metadata blobs and attribute arguments never enter the ldstr pipeline.
    // Contract analysis identifies literal arguments at individual consumer sites.
}
