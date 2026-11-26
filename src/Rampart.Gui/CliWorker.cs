using System.Diagnostics;
using System.IO;

namespace Rampart.Gui;

internal sealed record CliRunResult(int ExitCode, string StandardOutput, string StandardError);

internal static class CliWorker
{
    public static async Task<CliRunResult> ProtectAsync(
        string workerPath,
        string inputPath,
        string outputPath,
        string configurationPath,
        bool overwrite,
        CancellationToken cancellationToken)
    {
        ProcessStartInfo start = CreateStartInfo(workerPath);
        start.ArgumentList.Add("protect");
        start.ArgumentList.Add(inputPath);
        start.ArgumentList.Add("--out");
        start.ArgumentList.Add(outputPath);
        start.ArgumentList.Add("--config");
        start.ArgumentList.Add(configurationPath);
        start.ArgumentList.Add("--json");
        if (overwrite) start.ArgumentList.Add("--force");

        using var process = new Process { StartInfo = start };
        if (!process.Start()) throw new InvalidOperationException("Rampart CLI worker did not start.");

        // Keep draining both pipes through cancellation. After the process tree
        // is stopped, awaiting these readers prevents abandoned I/O tasks and
        // preserves any final diagnostic text the worker managed to emit.
        Task<string> stdout = process.StandardOutput.ReadToEndAsync();
        Task<string> stderr = process.StandardError.ReadToEndAsync();
        try
        {
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            try
            {
                if (!process.HasExited) process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
                // The worker can finish between HasExited and Kill. Either
                // outcome satisfies cancellation; still wait for final cleanup.
            }
            await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
            await Task.WhenAll(stdout, stderr).ConfigureAwait(false);
            throw;
        }

        return new(process.ExitCode, await stdout.ConfigureAwait(false), await stderr.ConfigureAwait(false));
    }

    public static string? FindDefaultWorker()
    {
        string? configured = Environment.GetEnvironmentVariable("RAMPART_CLI_PATH");
        if (IsWorker(configured)) return Path.GetFullPath(configured!);

        foreach (string name in new[] { "rampart.exe", "rampart.dll" })
        {
            string besideGui = Path.Combine(AppContext.BaseDirectory, name);
            if (File.Exists(besideGui)) return besideGui;
        }

        string? pathWorker = FindOnPath("rampart.exe");
        if (pathWorker is not null) return pathWorker;

        // Source builds keep the GUI and CLI in sibling project output folders.
        // Locate the repository marker instead of relying on the current directory.
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            // Repository builds may redirect every project's output beneath a
            // shared build root. Detect the sibling CLI project in that layout.
            string redirectedCli = Path.Combine(directory.FullName, "Rampart.Cli", "bin");
            if (Directory.Exists(redirectedCli))
            {
                foreach (string configuration in new[] { "Debug", "Release" })
                {
                    string candidate = Path.Combine(redirectedCli, configuration, "net8.0", "rampart.exe");
                    if (File.Exists(candidate)) return candidate;
                    candidate = Path.ChangeExtension(candidate, ".dll");
                    if (File.Exists(candidate)) return candidate;
                }
            }

            if (File.Exists(Path.Combine(directory.FullName, "Rampart.slnx")))
            {
                foreach (string configuration in new[] { "Debug", "Release" })
                {
                    string candidate = Path.Combine(directory.FullName, "src", "Rampart.Cli", "bin",
                        configuration, "net8.0", "rampart.exe");
                    if (File.Exists(candidate)) return candidate;
                    candidate = Path.ChangeExtension(candidate, ".dll");
                    if (File.Exists(candidate)) return candidate;
                }
            }
            directory = directory.Parent;
        }

        return null;
    }

    private static ProcessStartInfo CreateStartInfo(string workerPath)
    {
        if (!IsWorker(workerPath))
            throw new FileNotFoundException("Select a rampart.exe or rampart.dll CLI worker.", workerPath);
        workerPath = Path.GetFullPath(workerPath);

        var start = new ProcessStartInfo
        {
            FileName = Path.GetExtension(workerPath).Equals(".dll", StringComparison.OrdinalIgnoreCase)
                ? "dotnet"
                : workerPath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(workerPath)!,
        };
        if (Path.GetExtension(workerPath).Equals(".dll", StringComparison.OrdinalIgnoreCase))
            start.ArgumentList.Add(workerPath);
        return start;
    }

    private static bool IsWorker(string? path) => !string.IsNullOrWhiteSpace(path)
        && File.Exists(path)
        && (Path.GetFileName(path).Equals("rampart.exe", StringComparison.OrdinalIgnoreCase)
            || Path.GetFileName(path).Equals("rampart.dll", StringComparison.OrdinalIgnoreCase));

    private static string? FindOnPath(string name)
    {
        string? rawPath = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrWhiteSpace(rawPath)) return null;
        foreach (string directory in rawPath.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            try
            {
                string candidate = Path.Combine(directory, name);
                if (File.Exists(candidate)) return candidate;
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException) { }
        }
        return null;
    }
}
