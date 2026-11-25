namespace Rampart.Engine.Passes;

/// <summary>Compatibility façade for callers that invoked the original public
/// anti-debug placeholder directly. New code should use <see cref="AntiDebugPass"/>.</summary>
[Obsolete("Use AntiDebugPass instead.")]
public sealed class GuardStubsPass
{
    public void Run(BuildContext ctx) => new AntiDebugPass().Run(ctx);
}
