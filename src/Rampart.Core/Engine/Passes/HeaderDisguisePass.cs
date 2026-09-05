using System.Buffers.Binary;
using System.Text;
using Rampart.Pe;

namespace Rampart.Engine.Passes;

/// <summary>Header disguise: rewrite the fields that fingerprint a build —
/// TimeDateStamp, linker version — and (at Balanced+) plant a decoy PDB path in
/// the DOS-stub slack so PDB-hunting heuristics chase a file that never existed.
/// "Defeats zero-timestamp heuristics, ProcDump reconstruction."</summary>
public sealed class HeaderDisguisePass
{
    private const string DecoyAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789_";

    public void Run(BuildContext ctx)
    {
        var level = ctx.Level("packaging.header-disguise");
        if (level == Config.ProtectionLevel.Off)
            return;
        var pe = ctx.Pe;
        var rng = ctx.Rng;

        // Timestamps: plausible build-time values, stable per build seed. A
        // plausible fake beats a zero — zero is itself a packer heuristic.
        pe.TimeDateStamp = (uint)(1_700_000_000 + rng.NextInt64(0, 200_000_000));
        pe.LinkerVersion = ((byte)rng.Next(10, 15), (byte)rng.Next(0, 33));

        if (level >= Config.ProtectionLevel.Heavy)
        {
            // Only build identity changes. Machine, subsystem, and minimum OS
            // versions retain the application's loader compatibility contract.
            byte[] linkerMinors = [0, 10, 20, 30];
            pe.LinkerVersion = (14, linkerMinors[rng.Next(linkerMinors.Length)]);
            pe.ImageVersion = ((ushort)rng.Next(1, 5), (ushort)rng.Next(0, 10));
            var export = pe.Directory(DataDir.Export);
            if (!export.IsEmpty && export.Size >= 40)
                pe.WriteRva(export.RelativeVirtualAddress + 4, BitConverter.GetBytes(pe.TimeDateStamp));
            var debug = pe.Directory(DataDir.Debug);
            if (!debug.IsEmpty)
            {
                if (debug.Size % 28 != 0) throw new BadImageFormatException("Incomplete debug directory.");
                for (uint offset = 0; offset < debug.Size; offset += 28)
                    pe.WriteRva(debug.RelativeVirtualAddress + offset + 4, BitConverter.GetBytes(pe.TimeDateStamp));
            }
            // Import timestamps are binding state, not cosmetic build identity.
            // They must not be changed to imitate the COFF timestamp.
            ctx.Log.Add(new("header-disguise", "applied a consistent linker/image-version profile and export/debug timestamps"));
        }

        if (level >= Config.ProtectionLevel.Balanced)
        {
            // Decoy PDB path in the DOS-stub area: plausible string, points at
            // nothing. Static tooling scanning for "*.pdb" finds this first.
            var probe = pe.ToBytes();
            int lfanew = BinaryPrimitives.ReadInt32LittleEndian(probe.AsSpan(0x3C));
            string decoy = BuildDecoyPdbPath(rng);
            var bytes = Encoding.ASCII.GetBytes(decoy);
            int at = 0x78;
            if (at + bytes.Length + 1 <= lfanew)
            {
                pe.WriteDosStub(at, [.. bytes, 0]);
                ctx.Log.Add(new("header-disguise",
                    $"timestamp/linker disguised, decoy PDB planted at stub+{at:X} (level {level})"));
                return;
            }
        }

        ctx.Log.Add(new("header-disguise", $"timestamp/linker disguised (level {level})"));
    }

    private static string BuildDecoyPdbPath(Random rng)
    {
        int len = rng.Next(24, 44);
        var chars = new char[len];
        for (int i = 0; i < len; i++)
            chars[i] = DecoyAlphabet[rng.Next(DecoyAlphabet.Length)];
        int lastSlash = rng.Next(6, len - 8);
        for (int i = 0; i <= lastSlash; i += 3)
            chars[i] = '\\';
        return new string(chars) + ".pdb";
    }
}
