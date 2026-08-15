using Rampart.Testing;
using Rampart.X64;

namespace Rampart.Cli;

internal static class SampleCommand
{
    public static int Run(string[] args)
    {
        if (args.Contains("--help", StringComparer.Ordinal))
        {
            Console.WriteLine("usage: rampart sample [-o|--out <file>]");
            return 0;
        }

        string outPath = "rampart-sample.exe";
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] is "--out" or "-o")
                outPath = SettingsArguments.RequireValue(args, ref i, args[i]);
            else
                throw new ArgumentException($"Unknown option '{args[i]}'.");
        }

        byte[] pe = SamplePeBuilder.Build(ctx =>
        {
            var a = ctx.Code;
            a.MovRi(Reg.Rax, 0);
            a.MovRi(Reg.Rcx, 6);
            a.MovRi(Reg.Rdx, 7);
            a.Label("loop_head");
            a.AddRr(Reg.Rax, Reg.Rdx);
            a.DecR(Reg.Rcx);
            a.Jcc(Cc.Ne, "loop_head");
            a.SubRi(Reg.Rax, 2);
            ctx.LeaString(Reg.Rdx, "demo");
            a.TestRr(Reg.Rdx, Reg.Rdx);
            ctx.String("demo", "rampart demo payload");
        });

        File.WriteAllBytes(outPath, pe);
        Console.WriteLine($"wrote {outPath} ({pe.Length} bytes) — exit code when run: 40");
        return 0;
    }
}
