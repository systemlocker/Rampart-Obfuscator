using Rampart.Config;
using Rampart.Pe;

namespace Rampart.Engine.Passes;

/// <summary>
/// Adds cold instruction streams whose recursive decode begins one byte inside
/// the linear-sweep instruction. Both interpretations are valid and the normal
/// gadget entry returns; no malformed PE metadata or executable application
/// bytes are involved.
/// </summary>
public sealed class StaticDecodeDenialPass
{
    internal const int LightGadgetCount = 256;
    internal const int GadgetSize = 16;
    internal const string SectionName = ".rdec";

    public void Run(BuildContext ctx)
    {
        ProtectionLevel level = ctx.Level("analysis.static-decode-denial");
        if (level == ProtectionLevel.Off)
            return;

        int byteCount = checked(LightGadgetCount * GadgetSize);
        PeImage.Section section = ctx.Pe.AddSection(
            SectionName,
            byteCount,
            SectionCharacteristics.CntCode
                | SectionCharacteristics.CntInitializedData
                | SectionCharacteristics.MemExecute
                | SectionCharacteristics.MemRead);

        section.Data.AsSpan(0, byteCount).Fill(0x90);
        for (int index = 0; index < LightGadgetCount; index++)
        {
            Span<byte> gadget = section.Data.AsSpan(index * GadgetSize, GadgetSize);
            gadget[0] = 0xEB;
            gadget[1] = 0xFF; // jmp -1: target is byte 1, inside this instruction
            gadget[2] = (byte)(0xC0 + ctx.Rng.Next(0, 8)); // FF /0: inc r32
            gadget[3] = 0xC3; // ret

            // A second valid, independently discoverable entry increases the
            // disagreement without making the stream unbounded.
            gadget[8] = 0x31;
            gadget[9] = (byte)(0xC0 + ctx.Rng.Next(0, 8)); // xor r32,r32
            gadget[10] = 0xC3;
        }

        ctx.Log.Add(new("static-decode-denial",
            $"added {LightGadgetCount} bounded cold overlapping-decode gadgets (level {level})"));
    }
}
