using System.Buffers.Binary;
using Rampart.Config;
using Rampart.ControlFlow;

namespace Rampart.Engine.Passes;

/// <summary>Rebuilds explicitly selected, verified native leaf control flow
/// around a per-build state dispatcher. Unsupported functions remain untouched.</summary>
public sealed class ControlFlowFlatteningPass
{
    public const string KnobId = "code-transformation.flattening";

    public void Run(BuildContext ctx)
    {
        foreach (var function in ctx.Functions)
        {
            if (ctx.LevelFor(KnobId, function) == ProtectionLevel.Off)
                continue;
            if (ctx.LevelFor(KnobId, function) != ProtectionLevel.Light)
                throw new InvalidOperationException("Control-flow flattening supports only Light.");
            string reason;
            if (!ctx.FunctionPolicy.HasExplicitSelection(KnobId, function))
                reason = "requires explicit function selection";
            else if (ctx.IsFunctionClaimed(function))
                reason = "function is owned by an earlier transformation";
            else if (LeafFunctionEligibility.TryValidate(ctx, function, out reason))
            {
                byte[] original = ctx.Pe.ReadRva(function.BeginRva, (int)function.Size);
                if (LeafControlFlowCompiler.TryCompile(original, ctx.Rng, out byte[] code, out reason))
                {
                    uint rva = ctx.Alloc(code.Length, 16);
                    long displacement = (long)rva - function.BeginRva - 5;
                    if (displacement is < int.MinValue or > int.MaxValue)
                        throw new InvalidOperationException("Flattened code is outside the native rel32 range.");
                    if (!ctx.TryClaimFunction(function, KnobId, rva, (uint)code.Length))
                        throw new InvalidOperationException("Function transformation ownership changed during emission.");
                    ctx.WriteStub(rva, code);
                    var entry = new byte[5];
                    entry[0] = 0xE9;
                    BinaryPrimitives.WriteInt32LittleEndian(entry.AsSpan(1), (int)displacement);
                    ctx.Pe.WriteRva(function.BeginRva, entry);
                    ctx.MarkApplied(function, KnobId, ProtectionLevel.Light);
                    ctx.Log.Add(new("flattening", $"flattened {function.Name} at RVA {function.BeginRva:X8} into {code.Length} bytes"));
                    continue;
                }
            }
            ctx.Log.Add(new("flattening", $"skipped {function.Name} at RVA {function.BeginRva:X8}: {reason}"));
        }
    }
}
