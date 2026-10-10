using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Rampart.Config;
using Rampart.Managed;
using Rampart.Targets;

namespace Rampart.Cli;

/// <summary>The IL writer runs in a killable process. The parent bounds wall time,
/// memory and response size, then independently checks the returned artifact hashes.</summary>
internal static class ManagedWorker
{
    private sealed record Response(IReadOnlyList<ManagedMethodEvidence> Evidence,
        IReadOnlyList<ManagedTokenMapping> TokenMap, string InputSha256, string OutputSha256,
        IReadOnlyList<string> Diagnostics, IReadOnlyList<ManagedRenameEvidence> IdentifierRenames,
        ManagedVerificationReport? Verification);

    public static BackendProtectionResult Protect(byte[] input, byte[]? pdb, ProtectionSettings settings, ProtectionPlan plan, string inputPath)
    {
        ManagedProtectionOptions options = ManagedProtectionBackend.ResolveOptions(settings);
        if (options.MaximumProtectionMilliseconds is < 100 or > 600000)
            throw new ArgumentException("MANAGED_LIMITS: The worker time budget is outside the supported bounds.");
        string directory = Path.Combine(Path.GetTempPath(), "rampart-worker-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            File.WriteAllBytes(Path.Combine(directory, "input.dll"), input);
            File.WriteAllText(Path.Combine(directory, "origin.json"), JsonSerializer.Serialize(inputPath));
            if (pdb is not null) File.WriteAllBytes(Path.Combine(directory, "input.pdb"), pdb);
            File.WriteAllText(Path.Combine(directory, "options.json"), JsonSerializer.Serialize(options, ProtectionSettingsJson.Options));
            var start = new ProcessStartInfo
            {
                FileName = Environment.ProcessPath ?? throw new InvalidOperationException("RP_WORKER_HOST: Cannot locate the worker host."),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            if (Path.GetFileNameWithoutExtension(start.FileName).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
                start.ArgumentList.Add(Assembly.GetExecutingAssembly().Location);
            start.ArgumentList.Add("__managed-worker");
            start.ArgumentList.Add(directory);
            start.ArgumentList.Add(settings.Seed.ToString(System.Globalization.CultureInfo.InvariantCulture));
            start.Environment["DOTNET_GCHeapHardLimit"] = "18000000"; // 384 MiB, leaving room for native writer allocations.
            using var process = Process.Start(start) ?? throw new InvalidOperationException("RP_WORKER_START: Cannot start the managed writer.");
            var stdout = Drain(process.StandardOutput, 0);
            var stderr = Drain(process.StandardError, 128);
            var timer = Stopwatch.StartNew();
            while (!process.WaitForExit(50))
            {
                long workingSet;
                try
                {
                    process.Refresh();
                    workingSet = process.WorkingSet64;
                }
                catch (InvalidOperationException) when (process.HasExited) { break; }
                if (timer.ElapsedMilliseconds > options.MaximumProtectionMilliseconds || workingSet > 512L * 1024 * 1024)
                {
                    if (!process.HasExited) process.Kill(entireProcessTree: true);
                    process.WaitForExit();
                    throw new InvalidOperationException("RP_WORKER_LIMIT: The managed writer exceeded its time or memory budget; no output was promoted.");
                }
            }
            _ = stdout.GetAwaiter().GetResult();
            string diagnostic = stderr.GetAwaiter().GetResult();
            if (process.ExitCode != 0)
            {
                // The worker emits only bounded reason codes, not parser paths or
                // exception stacks that might disclose signing/build inputs.
                string code = diagnostic.Trim();
                if (code.Length is 0 or > 128 || code.Any(c => !(char.IsAsciiLetterOrDigit(c) || c == '_')))
                    code = "RP_WORKER_FAILED";
                string action = code.StartsWith("MANAGED_VERIFICATION_REFERENCE", StringComparison.Ordinal) || code == "MANAGED_VERIFICATION_SYSTEM_MODULE_MISSING"
                    ? " Supply one complete set of reference assemblies with matching versions, cultures and public key tokens using --verification-reference."
                    : code == "MANAGED_NOMINAL_VERIFICATION_FAILED" ? " The emitted IL does not satisfy ECMA-335 verifiability; this policy includes CLR-permitted unsafe IL." : "";
                throw new InvalidOperationException(code + ": The managed writer rejected this input; no output was promoted." + action);
            }
            string responsePath = Path.Combine(directory, "response.json");
            if (new FileInfo(responsePath).Length > 64L * 1024 * 1024)
                throw new InvalidOperationException("RP_WORKER_RESPONSE_LIMIT: The managed evidence exceeds the response limit.");
            var response = JsonSerializer.Deserialize<Response>(File.ReadAllText(responsePath), ProtectionSettingsJson.Options)
                ?? throw new InvalidOperationException("RP_WORKER_RESPONSE: Invalid managed writer response.");
            byte[] output = ProtectionPipeline.ReadInput(Path.Combine(directory, "output.dll"));
            if (response.InputSha256 != Convert.ToHexString(SHA256.HashData(input))
                || response.OutputSha256 != Convert.ToHexString(SHA256.HashData(output)))
                throw new InvalidOperationException("RP_WORKER_HASH: The managed writer response does not match its artifacts.");
            string outputPdb = Path.Combine(directory, "output.pdb");
            var result = new ManagedProtectionResult(output, File.Exists(outputPdb) ? ProtectionPipeline.ReadInput(outputPdb) : null,
                response.Evidence, response.TokenMap, response.InputSha256, response.OutputSha256, response.Diagnostics)
            { IdentifierRenames = response.IdentifierRenames, Verification = response.Verification };
            if (response.Verification?.Status != "verified" || response.Verification.OutputSha256 != response.OutputSha256)
                throw new InvalidOperationException("RP_WORKER_VERIFICATION: The worker did not verify the emitted artifact.");
            var adapted = ManagedProtectionBackend.Adapt(input, settings, plan, result);
            new ManagedProtectionBackend().Validate(input, adapted);
            return adapted;
        }
        finally
        {
            // The directory name is generated above; no input artifact path can
            // select what this cleanup removes.
            Directory.Delete(directory, recursive: true);
        }
    }

    public static int Run(string[] arguments)
    {
        try
        {
            if (arguments.Length != 2) throw new ArgumentException();
            string directory = Path.GetFullPath(arguments[0]);
            if (!Path.GetFileName(directory).StartsWith("rampart-worker-", StringComparison.Ordinal)) throw new ArgumentException();
            long seed = long.Parse(arguments[1], System.Globalization.CultureInfo.InvariantCulture);
            byte[] input = ProtectionPipeline.ReadInput(Path.Combine(directory, "input.dll"));
            string pdb = Path.Combine(directory, "input.pdb");
            var options = JsonSerializer.Deserialize<ManagedProtectionOptions>(File.ReadAllText(Path.Combine(directory, "options.json")), ProtectionSettingsJson.Options)
                ?? throw new ArgumentException();
            if (options.Verification is null)
            {
                string origin = JsonSerializer.Deserialize<string>(File.ReadAllText(Path.Combine(directory, "origin.json"))) ?? throw new ArgumentException();
                options.Verification = ManagedVerificationReferences.Discover(origin, input);
            }
            var result = new ManagedBackend().Protect(input, options, seed, File.Exists(pdb) ? ProtectionPipeline.ReadInput(pdb) : null);
            File.WriteAllBytes(Path.Combine(directory, "output.dll"), result.Output);
            if (result.PdbOutput is not null) File.WriteAllBytes(Path.Combine(directory, "output.pdb"), result.PdbOutput);
            File.WriteAllText(Path.Combine(directory, "response.json"), JsonSerializer.Serialize(new Response(
                result.Evidence, result.TokenMap, result.InputSha256, result.OutputSha256, result.Diagnostics, result.IdentifierRenames, result.Verification), ProtectionSettingsJson.Options));
            return 0;
        }
        catch (ManagedProtectionException error) { Console.Error.WriteLine(error.ReasonCode); return 1; }
        catch { Console.Error.WriteLine("RP_WORKER_FAILED"); return 1; }
    }

    private static async Task<string> Drain(StreamReader stream, int retain)
    {
        char[] buffer = new char[4096];
        var result = new System.Text.StringBuilder(retain);
        int read;
        while ((read = await stream.ReadAsync(buffer)) != 0)
        {
            int count = Math.Min(read, retain - result.Length);
            if (count > 0) result.Append(buffer, 0, count);
        }
        return result.ToString();
    }
}
