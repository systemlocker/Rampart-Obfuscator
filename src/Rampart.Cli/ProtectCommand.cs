using System.Text.Json;
using Rampart.Config;
using Rampart.Engine;
using Rampart.Pe;
using Rampart.Symbols;
using Rampart.Targets;

namespace Rampart.Cli;

internal static class ProtectCommand
{
    public static int Run(string[] args)
    {
        if (args.Contains("--help", StringComparer.Ordinal))
        {
            PrintUsage();
            return 0;
        }

        string? input = null;
        string? output = null;
        bool dryRun = false;
        bool force = false;
        bool emitSymbolMap = true;
        string? symbolMap = null;
        var verificationReferences = new List<string>();
        string? verificationSystemModule = null;
        var settingsArgs = new SettingsArguments();

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--out" or "-o":
                    output = SettingsArguments.RequireValue(args, ref i, args[i]);
                    break;
                case "--dry-run":
                    dryRun = true;
                    break;
                case "--force":
                    force = true;
                    break;
                case "--symbol-map":
                    symbolMap = SettingsArguments.RequireValue(args, ref i, args[i]);
                    break;
                case "--no-symbol-map":
                    emitSymbolMap = false;
                    break;
                case "--verification-reference":
                    verificationReferences.Add(SettingsArguments.RequireValue(args, ref i, args[i]));
                    break;
                case "--verification-system-module":
                    verificationSystemModule = SettingsArguments.RequireValue(args, ref i, args[i]);
                    break;
                default:
                    if (settingsArgs.TryConsume(args, ref i))
                        break;
                    if (args[i].StartsWith("-", StringComparison.Ordinal))
                        throw new ArgumentException($"Unknown option '{args[i]}'.");
                    if (input is not null)
                        throw new ArgumentException("protect accepts exactly one input file.");
                    input = args[i];
                    break;
            }
        }

        if (input is null)
            throw new ArgumentException("protect requires an input PE file.");

        string inputPath = Path.GetFullPath(input);
        if (!File.Exists(inputPath))
            throw new FileNotFoundException("Input PE file was not found.", inputPath);
        string outputPath = Path.GetFullPath(output ?? DefaultOutputPath(inputPath));
        if (string.Equals(inputPath, outputPath, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Output must not overwrite the input file.");
        string? symbolMapPath = emitSymbolMap
            ? Path.GetFullPath(symbolMap ?? DefaultSymbolMapPath(outputPath))
            : null;
        if (symbolMapPath is not null
            && (string.Equals(inputPath, symbolMapPath, StringComparison.OrdinalIgnoreCase)
                || string.Equals(outputPath, symbolMapPath, StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException("The private symbol-map path must differ from input and output paths.");
        }

        var catalog = KnobCatalog.Load();
        byte[] inputBytes = ProtectionPipeline.ReadInput(inputPath);
        var settings = settingsArgs.Build(catalog, TargetClassifier.Classify(inputBytes, inputPath).Target.Kind);
        if (TargetClassifier.Classify(inputBytes, inputPath).Target.Kind == ProtectionTargetKind.ManagedIl)
            ManagedVerificationReferences.Configure(inputPath, settings, verificationReferences, verificationSystemModule, resolveAutomatic: dryRun);
        else if (verificationReferences.Count != 0 || verificationSystemModule is not null)
            throw new ArgumentException("RP_TARGET_OPTIONS_MISMATCH: Verification references apply only to managed IL.");
        var pipeline = new ProtectionPipeline();
        var plan = pipeline.Plan(inputBytes, settings);
        var graph = ArtifactGraph.Inspect(inputPath, plan.Classification,
            ArtifactSigningInstructions.ForTarget(plan.Classification.Target, settings.Targets?.Managed?.StrongNameKeyEnvironmentVariable));

        if (dryRun)
        {
            if (plan.Classification.Target.Kind == ProtectionTargetKind.NativePe)
                ThreatDials.Apply(settings, catalog);
            var concerns = plan.Classification.Target.Kind == ProtectionTargetKind.NativePe
                ? ConcernRules.Evaluate(settings, catalog) : [];
            WritePreview(inputPath, outputPath, symbolMapPath, settings, catalog, concerns, settingsArgs.Json, plan, graph);
            return 0;
        }

        EnsureCanWrite(outputPath, force);
        if (symbolMapPath is not null)
            EnsureCanWrite(symbolMapPath, force);
        string inputPdb = Path.ChangeExtension(inputPath, ".pdb");
        byte[]? pdb = plan.Classification.Target.Kind != ProtectionTargetKind.NativePe && File.Exists(inputPdb)
            ? ProtectionPipeline.ReadInput(inputPdb) : null;
        var result = plan.Classification.Target.Kind == ProtectionTargetKind.ManagedIl
            ? ManagedWorker.Protect(inputBytes, pdb, settings, plan, inputPath)
            : pipeline.Protect(inputBytes, settings, pdb);
        var artifacts = new List<OutputArtifact> { new(outputPath, result.Output) };
        if (symbolMapPath is not null)
            artifacts.Add(new(symbolMapPath, JsonSerializer.SerializeToUtf8Bytes(result.PrivateMap, ProtectionSettingsJson.Options)));
        string outputPdb = Path.ChangeExtension(outputPath, ".pdb");
        if (result.Symbols is not null)
            artifacts.Add(new(outputPdb, result.Symbols));
        // A previous output PDB no longer describes an image emitted without
        // symbols. Remove it in the same rollback transaction as the new image.
        string[] removals = plan.Classification.Target.Kind == ProtectionTargetKind.ManagedIl
            && result.Symbols is null && File.Exists(outputPdb) ? [outputPdb] : [];
        ArtifactWriter.Write(artifacts, force, [inputPath, inputPdb], removals);
        if (result.Details is ProtectionResult native)
            WriteResult(inputPath, outputPath, symbolMapPath, native, settingsArgs.Json);
        else
            WriteTargetResult(inputPath, outputPath, symbolMapPath, result, settingsArgs.Json, graph);
        return 0;
    }

    private static void WriteTargetResult(string input, string output, string? map, BackendProtectionResult result, bool json, ArtifactGraph graph)
    {
        if (json)
        {
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                Input = input,
                Output = output,
                SymbolMap = map,
                result.Seed,
                result.Plan,
                result.InputSize,
                OutputSize = result.Output.Length,
                result.InputSha256,
                result.OutputSha256,
                result.Evidence,
                Artifacts = graph,
            }, ProtectionSettingsJson.Options));
        }
        else
        {
            Console.WriteLine($"target: {result.Plan.Classification.Target.Kind}");
            foreach (string diagnostic in result.Plan.Diagnostics) Console.Error.WriteLine(diagnostic);
            Console.WriteLine($"wrote {output}");
            if (map is not null) Console.WriteLine($"private map {map}");
            Console.WriteLine($"sha256 {result.OutputSha256}");
        }
    }

    private static string DefaultSymbolMapPath(string outputPath)
    {
        string directory = Path.GetDirectoryName(outputPath)!;
        string name = Path.GetFileNameWithoutExtension(outputPath);
        return Path.Combine(directory, $"{name}.rmap.json");
    }

    private static void EnsureCanWrite(string path, bool force)
    {
        string? directory = Path.GetDirectoryName(path);
        if (directory is null || !Directory.Exists(directory))
            throw new DirectoryNotFoundException($"Output directory does not exist: {directory}");
        if (File.Exists(path) && !force)
            throw new IOException($"Output already exists: {path}. Pass --force to replace it.");
    }

    private static string DefaultOutputPath(string inputPath)
    {
        string directory = Path.GetDirectoryName(inputPath)!;
        string extension = Path.GetExtension(inputPath);
        string name = Path.GetFileNameWithoutExtension(inputPath);
        return Path.Combine(directory, $"{name}.protected{extension}");
    }

    private static void WriteOutput(string outputPath, byte[] bytes, bool force)
    {
        string directory = Path.GetDirectoryName(outputPath)!;

        string temporary = Path.Combine(directory, $".{Path.GetFileName(outputPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            File.WriteAllBytes(temporary, bytes);
            File.Move(temporary, outputPath, overwrite: force);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }

    private static void WriteJsonOutput(string outputPath, object value, bool force)
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(value, ProtectionSettingsJson.Options);
        WriteOutput(outputPath, json, force);
    }

    private static void WritePreview(
        string inputPath,
        string outputPath,
        string? symbolMapPath,
        ProtectionSettings settings,
        KnobCatalog catalog,
        List<Concern> concerns,
        bool json,
        ProtectionPlan plan,
        ArtifactGraph graph)
    {
        var preview = new
        {
            Input = inputPath,
            Output = outputPath,
            SymbolMap = symbolMapPath,
            Settings = SettingsArguments.SettingsPayload(settings, plan.Classification.Target.Kind),
            Plan = plan,
            Artifacts = graph,
            BudgetPoints = KnobCatalog.BudgetFor(settings, catalog),
            Concerns = concerns,
        };

        if (json)
        {
            Console.WriteLine(JsonSerializer.Serialize(preview, ProtectionSettingsJson.Options));
            return;
        }

        Console.WriteLine($"input:  {inputPath}");
        Console.WriteLine($"output: {outputPath}");
        Console.WriteLine(SettingsArguments.SettingsPayload(settings, plan.Classification.Target.Kind).ToJsonString(ProtectionSettingsJson.Options));
        PrintConcerns(concerns);
    }

    private static void WriteResult(
        string inputPath,
        string outputPath,
        string? symbolMapPath,
        ProtectionResult result,
        bool json)
    {
        if (json)
        {
            var report = new
            {
                Input = inputPath,
                Output = outputPath,
                SymbolMap = symbolMapPath,
                SymbolCount = result.SymbolMap.Functions.Count,
                result.Seed,
                result.InputSize,
                result.OutputSize,
                result.InputSha256,
                result.OutputSha256,
                result.BudgetPoints,
                Applied = result.Applied,
                result.Concerns,
                result.Log,
            };
            Console.WriteLine(JsonSerializer.Serialize(report, ProtectionSettingsJson.Options));
            return;
        }

        foreach (var entry in result.Log)
            Console.WriteLine($"[{entry.Pass}] {entry.Detail}");
        PrintConcerns(result.Concerns);
        Console.WriteLine($"wrote {outputPath}");
        if (symbolMapPath is not null)
            Console.WriteLine($"private symbol map {symbolMapPath} ({result.SymbolMap.Functions.Count} functions)");
        Console.WriteLine($"sha256 {result.OutputSha256}");
    }

    internal static void PrintConcerns(IEnumerable<Concern> concerns)
    {
        foreach (var concern in concerns)
        {
            Console.Error.WriteLine($"{concern.Severity.ToString().ToLowerInvariant()} {concern.Code}: {concern.Message}");
            if (concern.Suggestion is not null)
                Console.Error.WriteLine($"  suggestion: {concern.Suggestion}");
        }
    }

    private static void PrintUsage() => Console.WriteLine("""
        usage: rampart protect <file> [options]

          -o, --out <file>          output path (default: <name>.protected.<ext>)
              --config <file>       load settings JSON
              --target <kind>       assert native, nativeaot, or managed input
              --compatibility <p>   preserve, warn, or strict compatibility policy
              --preset <name>       light, balanced, heavy, maximum, or nuclear
              --seed <number>       reproducible signed 64-bit build seed
              --set <id>=<level>    override one knob; repeatable
              --only <ids>          enable only these comma-separated knobs + dependencies
              --disable <ids>       turn off comma-separated knobs; repeatable
              --group-level <g>=<l> set all ready knobs in a group, clamped per emitter
              --symbols <file>      load .map, .pdb, or JSON symbols; repeatable
              --map, --pdb <file>   aliases for --symbols
              --pdb-tool <file>     llvm-pdbutil path for PDB ingestion
              --include-symbol <g>  protect only matching symbol globs; repeatable
              --exclude-symbol <g>  always leave matching symbols untouched
              --rva-range <a>-<b>   include functions overlapping a hexadecimal RVA range
              --function-profile <glob>=<preset>
                                    apply a per-function preset; repeatable
              --symbol-map <file>   private sidecar path (default: <output-name>.rmap.json)
              --no-symbol-map       do not emit the private address map
              --verification-reference <file>
                                    explicit managed dependency; repeat for the complete reference set
              --verification-system-module <name>
                                    core type assembly for the supplied managed references
              --focus <tags>        comma-separated threat tags; repeatable
              --watermark <text>    build-owner watermark
              --custom-message <t>  response message for supported response knobs
              --dry-run             print the exact resolved payload without writing
              --json                emit machine-readable output
              --force               replace an existing output file
        """);
}
