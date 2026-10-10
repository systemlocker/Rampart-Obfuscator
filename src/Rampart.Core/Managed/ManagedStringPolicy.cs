using Mono.Cecil;

namespace Rampart.Managed;

internal static class ManagedStringPolicy
{
    internal static bool IsMetadataOwnedConsumer(MethodReference callee) =>
            callee.DeclaringType.Namespace.StartsWith("System.Resources", StringComparison.Ordinal)
            || callee.DeclaringType.Namespace.StartsWith("System.Runtime.InteropServices", StringComparison.Ordinal)
            || callee.DeclaringType.Namespace.StartsWith("System.Runtime.Serialization", StringComparison.Ordinal);
    // Metadata blobs and attribute arguments never enter the ldstr pipeline.
    // Contract analysis identifies literal arguments at individual consumer sites.
}
