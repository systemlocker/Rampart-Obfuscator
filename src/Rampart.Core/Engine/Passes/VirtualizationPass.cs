using System.Buffers.Binary;
using Rampart.Config;
using Rampart.ControlFlow;
using Rampart.Virtualization;

namespace Rampart.Engine.Passes;

/// <summary>Virtualizes explicitly selected, verified scalar leaf functions.</summary>
public sealed class VirtualizationPass
{
    public void Run(BuildContext ctx)
    {
        if (ctx.MaximumFunctionLevel("virtualization.coverage") == ProtectionLevel.Off)
        {
            if (ctx.MaximumFunctionLevel("virtualization.per-build-isa") != ProtectionLevel.Off)
                ctx.Log.Add(new("vm", "no functions requested: virtualization.coverage is off"));
            return;
        }
        int changed = 0;
        foreach (FunctionDescriptor function in ctx.Functions.OrderBy(function => function.BeginRva))
        {
            ProtectionLevel coverage = ctx.LevelFor("virtualization.coverage", function);
            if (coverage == ProtectionLevel.Off)
                continue;
            ProtectionLevel isa = ctx.LevelFor("virtualization.per-build-isa", function);
            if (isa != ProtectionLevel.Light || coverage != ProtectionLevel.Light)
                throw new InvalidOperationException("Virtualization requires both per-build-isa and coverage at Light.");
            if (!ctx.FunctionPolicy.HasExplicitSelection("virtualization.coverage", function))
            {
                Skip("requires an explicit symbol, RVA selection, or coverage rule");
                continue;
            }
            if (ctx.IsFunctionClaimed(function))
            {
                Skip("already transformed by another function pass");
                continue;
            }
            if (!LeafFunctionEligibility.TryValidate(ctx, function, out string reason))
            {
                Skip(reason);
                continue;
            }
            if (!LeafVirtualizer.TryCompile(ctx.Pe.ReadRva(function.BeginRva, checked((int)function.Size)),
                    ctx.Rng, out CompiledLeafVm? vm, out reason))
            {
                Skip(reason);
                continue;
            }
            uint target = ctx.Alloc(vm!.Code.Length, 16);
            long displacement = (long)target - function.BeginRva - 5;
            if (displacement is < int.MinValue or > int.MaxValue)
                throw new InvalidOperationException("Virtualized function exceeds direct-branch reach.");
            // Bytecode is executable behavior even though the CPU reads it as
            // data. Include it in ownership so integrity measurements cover it.
            if (!ctx.TryClaimFunction(function, "virtualization", target, (uint)vm.Code.Length))
                throw new InvalidOperationException("Virtualization region ownership changed during emission.");
            ctx.WriteStub(target, vm.Code);
            byte[] jump = new byte[5];
            jump[0] = 0xE9;
            BinaryPrimitives.WriteInt32LittleEndian(jump.AsSpan(1), (int)displacement);
            // Retain the rest of the original body. Erasing it or pretending it is
            // a decoy body is a separate capability, not a prerequisite for lifting.
            ctx.Pe.WriteRva(function.BeginRva, jump);
            ctx.MarkApplied("virtualization.per-build-isa", isa);
            ctx.MarkApplied("virtualization.coverage", coverage);
            ctx.Log.Add(new("vm", $"lifted {function.Name} at {function.BeginRva:X8} to {target:X8}: " +
                $"{vm.InstructionCount} bytecode instructions, {vm.Code.Length} emitted bytes"));
            changed++;

            void Skip(string detail) => ctx.Log.Add(new("vm", $"skipped {function.Name} at {function.BeginRva:X8}: {detail}"));
        }
        if (changed == 0)
            ctx.Log.Add(new("vm", "no eligible explicitly selected leaf functions were virtualized"));
    }
}
