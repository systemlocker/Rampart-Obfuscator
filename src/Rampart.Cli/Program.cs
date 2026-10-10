namespace Rampart.Cli;

internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            PrintUsage();
            return 2;
        }

        try
        {
            return args[0].ToLowerInvariant() switch
            {
                "protect" => ProtectCommand.Run(args[1..]),
                "__managed-worker" => ManagedWorker.Run(args[1..]),
                "inspect" => InspectCommand.Run(args[1..]),
                "check" => CheckCommand.Run(args[1..]),
                "knobs" => KnobsCommand.Run(args[1..]),
                "explain" => ExplainCommand.Run(args[1..]),
                "version" or "--version" => VersionCommand(),
                "help" or "--help" or "-h" => HelpCommand(),
                _ => UnknownCommand(args[0]),
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    private static int VersionCommand()
    {
        Version? version = typeof(Program).Assembly.GetName().Version;
        Console.WriteLine($"rampart {version?.ToString(3) ?? "unknown"}");
        return 0;
    }

    private static int HelpCommand()
    {
        PrintUsage();
        return 0;
    }

    private static int UnknownCommand(string verb)
    {
        Console.Error.WriteLine($"unknown command '{verb}'");
        PrintUsage();
        return 2;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("""
            Rampart — open-source protector for Windows PE (x64)

            usage: rampart <command> [options]

            commands:
              protect <file>   protect a PE image
              inspect <file>   display PE and Rampart metadata
              check            validate a configuration and show concerns
              knobs            list supported protection options
              explain <id>     show the level-by-level behavior of one knob
              version          print the version

            run `rampart <command> --help` for command-specific options.
            """);
    }
}
