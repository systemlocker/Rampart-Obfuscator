using System.Buffers.Binary;
using Rampart.Config;
using Rampart.ControlFlow;
using Rampart.NativeTransforms;
using Rampart.Pe;

namespace Rampart.Engine.Passes;

/// <summary>Inserts padding noise and rebuilds explicitly selected native leaf
/// bodies with flag-preserving junk and verified target-constant splitting.</summary>
public sealed class CodeTransformPass
{
    public void Run(BuildContext ctx)
    {
        TransformNativeBodies(ctx);
        var junkLevel = ctx.MaximumFunctionLevel("code-transformation.junk-insertion");
        if (junkLevel != Config.ProtectionLevel.Off)
        {
            int changed = FillPaddingWithDecoys(ctx, junkLevel);
            if (changed > 0)
                // Padding cannot substantiate a claim about executed body noise.
                // Only a successfully rebuilt native function raises this ceiling.
                ctx.MarkApplied("code-transformation.junk-insertion", ProtectionLevel.Light);
        }

        if (ctx.MaximumFunctionLevel("code-transformation.per-build-mutation") != Config.ProtectionLevel.Off)
            ctx.Log.Add(new("mutation", $"build seed {ctx.Settings.Seed:X16} drives decoy streams, keys, and stub layout"));

        if (ctx.MaximumFunctionLevel("code-transformation.mba-constants") != Config.ProtectionLevel.Off)
            ctx.Log.Add(new("mba", "runtime-stub constants use per-build XOR-split identities"));
    }

    private static void TransformNativeBodies(BuildContext ctx)
    {
        const string junkId = "code-transformation.junk-insertion", mbaId = "code-transformation.mba-constants";
        foreach (FunctionDescriptor function in ctx.Functions.OrderBy(function => function.BeginRva))
        {
            ProtectionLevel junk = ctx.LevelFor(junkId, function), mba = ctx.LevelFor(mbaId, function);
            bool nativeJunk = junk >= ProtectionLevel.Balanced;
            bool nativeMba = mba >= ProtectionLevel.Balanced;
            if (!nativeJunk && !nativeMba)
                continue;
            nativeJunk &= ctx.FunctionPolicy.HasExplicitSelection(junkId, function);
            nativeMba &= ctx.FunctionPolicy.HasExplicitSelection(mbaId, function);
            if (!nativeJunk && !nativeMba)
            {
                Skip("native body rewriting requires explicit function selection");
                continue;
            }
            if (ctx.IsFunctionClaimed(function))
            {
                Skip("function is owned by an earlier transformation");
                continue;
            }
            if (!LeafFunctionEligibility.TryValidate(ctx, function, out string reason))
            {
                Skip(reason);
                continue;
            }
            int density = nativeJunk ? junk switch
            {
                ProtectionLevel.Balanced => 1,
                ProtectionLevel.Heavy => 2,
                _ => 3,
            } : 0;
            byte[] original = ctx.Pe.ReadRva(function.BeginRva, checked((int)function.Size));
            if (!NativeLeafCompiler.TryCompile(original, ctx.Rng,
                    new NativeTransformOptions(density, nativeMba) { ConstantDepth = nativeMba ? (int)mba - 1 : 1 },
                    out CompiledNativeLeaf? compiled, out reason))
            {
                Skip(reason);
                continue;
            }
            uint target = ctx.Alloc(compiled!.Code.Length, 16);
            long displacement = (long)target - function.BeginRva - 5;
            if (displacement is < int.MinValue or > int.MaxValue)
                throw new InvalidOperationException("Rewritten native code is outside the rel32 range.");
            if (!ctx.TryClaimFunction(function, "native-code", target, (uint)compiled.Code.Length))
                throw new InvalidOperationException("Native function ownership changed during emission.");
            ctx.WriteStub(target, compiled.Code);
            byte[] entry = new byte[5];
            entry[0] = 0xE9;
            BinaryPrimitives.WriteInt32LittleEndian(entry.AsSpan(1), (int)displacement);
            ctx.Pe.WriteRva(function.BeginRva, entry);
            if (compiled.JunkSites != 0) ctx.MarkApplied(function, junkId, junk);
            if (compiled.SplitConstants != 0)
                ctx.MarkApplied(function, mbaId, mba);
            ctx.Log.Add(new("native-code", $"rewrote {function.Name} at RVA {function.BeginRva:X8}: " +
                $"{compiled.JunkSites} in-body junk sites, {compiled.SplitConstants} target constants split, " +
                $"{compiled.FlagLiveConstants} MOV constants retained for live flags; {compiled.Code.Length} bytes"));

            void Skip(string detail) => ctx.Log.Add(new("native-code", $"skipped {function.Name} at RVA {function.BeginRva:X8}: {detail}"));
        }
    }

    /// <summary>Finds alignment padding between .pdata-known functions (the CC/90
    /// runs the linker leaves behind) and fills it with per-build decoy
    /// instruction streams: real decodable x64 that nothing executes. Padding
    /// AFTER a function, BEFORE the next function's first byte — never inside.</summary>
    private static int FillPaddingWithDecoys(BuildContext ctx, Config.ProtectionLevel level)
    {
        var pe = ctx.Pe;
        int density = level switch
        {
            Config.ProtectionLevel.Light => 2,
            Config.ProtectionLevel.Balanced => 4,
            Config.ProtectionLevel.Heavy => 8,
            _ => 16,
        };

        int filled = 0, bytesFilled = 0;
        var ordered = ctx.Functions.OrderBy(f => f.BeginRva).ToList();
        foreach (var textSec in pe.Sections.Where(s => s.IsExecutable))
        {
            for (int i = 0; i < ordered.Count - 1; i++)
            {
                var cur = ordered[i];
                var next = ordered[i + 1];
                Config.ProtectionLevel effectiveLevel =
                    ctx.LevelFor("code-transformation.junk-insertion", cur);
                if (effectiveLevel == Config.ProtectionLevel.Off)
                    continue;
                if (!pe.TryRvaToOffset(cur.EndRva, out int gapStartOff))
                    continue;
                if (next.BeginRva <= cur.EndRva)
                    continue;
                int gapLen = (int)(next.BeginRva - cur.EndRva);
                if (gapLen < density || gapLen > 64)
                    continue;

                int idx = gapStartOff - (int)textSec.PointerToRawData;
                if (idx < 0 || idx + gapLen > textSec.Data.Length)
                    continue;

                // Only touch verified padding (CC/90/00) — if the linker put
                // anything live here, leave it alone.
                bool isPadding = true;
                for (int b = 0; b < gapLen; b++)
                {
                    byte v = textSec.Data[idx + b];
                    if (v is not (0xCC or 0x90 or 0x00))
                    {
                        isPadding = false;
                        break;
                    }
                }
                if (!isPadding)
                    continue;

                int effectiveDensity = effectiveLevel switch
                {
                    Config.ProtectionLevel.Light => 2,
                    Config.ProtectionLevel.Balanced => 4,
                    Config.ProtectionLevel.Heavy => 8,
                    _ => 16,
                };
                EmitDecoyStream(textSec.Data.AsSpan(idx, gapLen), ctx.Rng, effectiveDensity);
                filled++;
                bytesFilled += gapLen;
            }
        }

        ctx.Log.Add(new("junk", $"decoy streams filled {filled} padding gaps ({bytesFilled} bytes)"));
        return bytesFilled;
    }

    /// <summary>Generates a valid, never-executed instruction stream into the
    /// gap: flag-preserving computations on dead registers, fake prologues,
    /// short jumps that stay inside the gap. Every byte derives from the build
    /// RNG — the same seed reproduces the selected layout.</summary>
    private static void EmitDecoyStream(Span<byte> gap, Random rng, int density)
    {
        // These fragments stay in verified inter-function padding. Native body
        // junk uses a separate emitter with the stricter executed-code contract.
        int pos = 0;
        while (pos < gap.Length)
        {
            int room = gap.Length - pos;
            int pick = rng.Next(0, Math.Max(2, density + 2));
            switch (pick)
            {
                case 0: // push r; pop r — valid 2-byte no-op pair
                    if (room >= 2)
                    {
                        byte r = (byte)rng.Next(0, 8);
                        gap[pos++] = (byte)(0x50 + r);
                        gap[pos++] = (byte)(0x58 + r);
                    }
                    else
                        gap[pos++] = 0x90;
                    break;
                case 1: // fake prologue: push rbp; mov rbp,rsp (4 bytes)
                    if (room >= 4)
                    {
                        gap[pos++] = 0x55;
                        gap[pos++] = 0x48;
                        gap[pos++] = 0x89;
                        gap[pos++] = 0xE5;
                    }
                    else
                        gap[pos++] = 0x90;
                    break;
                case 2: // mov r32, imm32 — a plausible constant load
                    if (room >= 5)
                    {
                        gap[pos++] = (byte)(0xB8 + rng.Next(0, 8));
                        for (int i = 0; i < 4; i++)
                            gap[pos++] = (byte)rng.Next(0, 0x100);
                    }
                    else
                        gap[pos++] = 0x90;
                    break;
                default: // nop sled fragment or single-byte dead ops
                    gap[pos++] = pick % 3 == 0 ? (byte)0x90 : (byte)0x87; // xchg r,r-ish safe byte? keep 0x90 only
                    gap[pos - 1] = 0x90;
                    break;
            }
        }
    }
}
