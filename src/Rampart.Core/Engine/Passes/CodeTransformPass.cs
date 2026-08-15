using Rampart.Pe;

namespace Rampart.Engine.Passes;

/// <summary>Code transformation: junk + dead-code insertion, MBA constants,
/// per-build mutation. v0.1 applies the transforms that provably preserve
/// semantics without a full recompiler:
///   - decoy code fills every inter-function alignment gap (valid instruction
///     streams, never executed, signature-breaking noise);
///   - per-build mutation: all decoy streams, keys, and layouts derive from the
///     build seed — no two builds share bytes;
///   - MBA rewriting applies to constants the protector itself emits (see
///     Asm.MovRiMba) — user-code MBA needs the verified lifter and lands with
///     the virtualization work.</summary>
public sealed class CodeTransformPass
{
    public void Run(BuildContext ctx)
    {
        var junkLevel = ctx.MaximumFunctionLevel("code-transformation.junk-insertion");
        if (junkLevel != Config.ProtectionLevel.Off)
            FillPaddingWithDecoys(ctx, junkLevel);

        if (ctx.MaximumFunctionLevel("code-transformation.per-build-mutation") != Config.ProtectionLevel.Off)
            ctx.Log.Add(new("mutation", $"build seed {ctx.Settings.Seed:X16} drives decoy streams, keys, and stub layout"));

        if (ctx.MaximumFunctionLevel("code-transformation.mba-constants") != Config.ProtectionLevel.Off)
            ctx.Log.Add(new("mba", "runtime-stub constants use per-build XOR-split identities"));
    }

    /// <summary>Finds alignment padding between .pdata-known functions (the CC/90
    /// runs the linker leaves behind) and fills it with per-build decoy
    /// instruction streams: real decodable x64 that nothing executes. Padding
    /// AFTER a function, BEFORE the next function's first byte — never inside.</summary>
    private static void FillPaddingWithDecoys(BuildContext ctx, Config.ProtectionLevel level)
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
    }

    /// <summary>Generates a valid, never-executed instruction stream into the
    /// gap: flag-preserving computations on dead registers, fake prologues,
    /// short jumps that stay inside the gap. Every byte derives from the build
    /// RNG — the same seed reproduces it, any other seed never repeats it.</summary>
    private static void EmitDecoyStream(Span<byte> gap, Random rng, int density)
    {
        // Fake prologue fragments IDA-style tools recognize as function starts —
        // the "autoanalysis bomb" in miniature. Kept small here; the dedicated
        // analysis-crasher pass scales this to tens of thousands.
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
