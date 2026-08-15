namespace Rampart.Engine.Passes;

/// <summary>Code virtualization: lift functions into a per-build VM. This file
/// is the pass boundary; the ISA generator, lifter, and interpreter live in
/// Rampart.Vm. Placeholder until the VM module lands.</summary>
public sealed class VirtualizationPass
{
    public void Run(BuildContext ctx)
    {
        var level = ctx.Level("virtualization.per-build-isa");
        if (level == Config.ProtectionLevel.Off)
            return;
        ctx.Log.Add(new("vm", $"virtualization level {level} (module pending integration)"));
    }
}
