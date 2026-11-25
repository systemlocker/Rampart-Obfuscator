using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using Rampart.Pe;

namespace Rampart.Symbols;

/// <summary>Build-only symbol metadata. None of these strings are embedded in the protected image.</summary>
public sealed class SymbolRecord
{
    public string Name { get; set; } = "";
    public uint StartRva { get; set; }
    public uint? EndRva { get; set; }
    public string? Module { get; set; }
    public string? Source { get; set; }
}

public static partial class SymbolLoader
{
    public static List<SymbolRecord> Load(
        IEnumerable<string> sources,
        PeImage image,
        string? pdbTool = null)
    {
        var result = new List<SymbolRecord>();
        foreach (string source in sources)
        {
            string path = Path.GetFullPath(source);
            if (!File.Exists(path))
                throw new FileNotFoundException("Symbol source was not found.", path);

            string extension = Path.GetExtension(path).ToLowerInvariant();
            result.AddRange(extension switch
            {
                ".json" => ParseJson(File.ReadAllText(path)),
                ".map" => ParseMap(File.ReadAllText(path), image, path),
                ".pdb" => ReadPdb(path, image, pdbTool),
                _ => throw new NotSupportedException(
                    $"Unsupported symbol source '{path}'. Expected .map, .pdb, or .json."),
            });
        }

        return result
            .Where(symbol => symbol.StartRva < image.SizeOfImage && !string.IsNullOrWhiteSpace(symbol.Name))
            .GroupBy(symbol => (symbol.StartRva, symbol.Name), symbol => symbol)
            .Select(group => group.First())
            .OrderBy(symbol => symbol.StartRva)
            .ToList();
    }

    public static List<SymbolRecord> ParseJson(string json)
    {
        List<SymbolRecord> records = JsonSerializer.Deserialize<List<SymbolRecord>>(json, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
        }) ?? [];
        foreach (SymbolRecord record in records)
        {
            if (record.EndRva is { } end && end < record.StartRva)
                throw new FormatException(
                    $"Symbol '{record.Name}' has EndRva ({end:X8}) smaller than StartRva ({record.StartRva:X8}).");
        }
        return records;
    }

    public static List<SymbolRecord> ParseMap(string text, PeImage image, string sourceName = "symbols.map")
    {
        var result = new List<SymbolRecord>();
        foreach (string line in text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            Match msvc = MsvcMapLine().Match(line);
            if (msvc.Success)
            {
                string rawName = msvc.Groups["name"].Value;
                // MSVC section-table lines look like "0001:00000000 00001234H .text CODE".
                if (MsvcSectionLengthToken().IsMatch(rawName))
                    continue;
                if (!int.TryParse(msvc.Groups["segment"].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int segment)
                    || !ulong.TryParse(msvc.Groups["offset"].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong offset))
                    continue;
                // Segment 0000 entries in MSVC map files are linker-defined absolute symbols.
                if (segment == 0)
                    continue;
                ulong address = 0;
                bool hasAddress = msvc.Groups["address"].Success
                    && ulong.TryParse(msvc.Groups["address"].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out address);
                uint rva;
                if (hasAddress && address >= image.ImageBase && address - image.ImageBase <= uint.MaxValue)
                {
                    rva = (uint)(address - image.ImageBase);
                }
                else if (TrySegmentOffsetToRva(image, segment, offset, out uint mapped))
                {
                    rva = mapped;
                }
                else
                {
                    continue;
                }
                result.Add(new SymbolRecord
                {
                    Name = rawName,
                    StartRva = rva,
                    Module = NullIfWhiteSpace(msvc.Groups["module"].Value),
                    Source = sourceName,
                });
                continue;
            }

            Match gnu = GnuMapLine().Match(line);
            if (!gnu.Success)
                continue;
            string gnuName = gnu.Groups["name"].Value;
            // Skip linker expressions and section-size tokens in GNU/LLD map files.
            if (gnuName == "." || gnuName.StartsWith("0x", StringComparison.OrdinalIgnoreCase) || gnuName == "=")
                continue;
            if (!ulong.TryParse(gnu.Groups["address"].Value[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong absolute))
                continue;
            if (absolute < image.ImageBase || absolute - image.ImageBase > uint.MaxValue)
                continue;
            result.Add(new SymbolRecord
            {
                Name = gnuName,
                StartRva = (uint)(absolute - image.ImageBase),
                Module = NullIfWhiteSpace(gnu.Groups["module"].Value),
                Source = sourceName,
            });
        }
        return result;
    }

    public static List<SymbolRecord> ParseLlvmPdbDump(string text, PeImage image, string sourceName)
    {
        var result = new List<SymbolRecord>();
        (int Segment, ulong Offset)? address = null;
        string? name = null;

        foreach (string line in text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            // Real `llvm-pdbutil dump -publics` puts the symbol name on the S_PUB32
            // header line (`1234 | S_PUB32 [size = 44] \`SymbolName\``) and its
            // segment:offset on the next line (`flags = ..., addr = 0001:00000000`).
            // Reset pending state at each new S_PUB32 header so unmatched records
            // cannot bleed across entries.
            Match pubHeader = PdbPub32Header().Match(line);
            if (pubHeader.Success)
            {
                address = null;
                name = pubHeader.Groups["name"].Value.Trim();
            }

            Match addressMatch = PdbAddress().Match(line);
            if (addressMatch.Success
                && int.TryParse(addressMatch.Groups["segment"].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int seg)
                && ulong.TryParse(addressMatch.Groups["offset"].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong off))
            {
                address = (seg, off);
            }
            Match nameMatch = PdbName().Match(line);
            if (nameMatch.Success)
                name = nameMatch.Groups["name"].Value.Trim();

            if (address is not { } at || string.IsNullOrWhiteSpace(name))
                continue;
            if (TrySegmentOffsetToRva(image, at.Segment, at.Offset, out uint rva))
            {
                result.Add(new SymbolRecord
                {
                    Name = name,
                    StartRva = rva,
                    Source = sourceName,
                });
            }
            address = null;
            name = null;
        }
        return result;
    }

    private static List<SymbolRecord> ReadPdb(string path, PeImage image, string? configuredTool)
    {
        string tool = ResolvePdbTool(configuredTool);
        var start = new ProcessStartInfo
        {
            FileName = tool,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add("dump");
        start.ArgumentList.Add("-publics");
        start.ArgumentList.Add(path);

        using var process = Process.Start(start)
            ?? throw new InvalidOperationException($"Could not start PDB reader '{tool}'.");
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        // Drain stdout and stderr concurrently with WaitForExitAsync so large
        // dumps cannot deadlock the pipe buffer and the 60s timeout is enforced.
        Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync(cts.Token);
        Task<string> stderrTask = process.StandardError.ReadToEndAsync(cts.Token);
        try
        {
            Task.WhenAll(process.WaitForExitAsync(cts.Token), stdoutTask, stderrTask).GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            throw new TimeoutException($"PDB reader '{tool}' did not finish within 60 seconds.");
        }

        string stdout = stdoutTask.GetAwaiter().GetResult();
        string stderr = stderrTask.GetAwaiter().GetResult();
        if (process.ExitCode != 0)
            throw new InvalidOperationException($"PDB reader failed with exit code {process.ExitCode}: {stderr.Trim()}");
        return ParseLlvmPdbDump(stdout, image, path);
    }

    private static string ResolvePdbTool(string? configuredTool)
    {
        if (!string.IsNullOrWhiteSpace(configuredTool))
        {
            string full = Path.GetFullPath(configuredTool);
            if (!File.Exists(full))
                throw new FileNotFoundException("Configured llvm-pdbutil executable was not found.", full);
            return full;
        }

        string executable = OperatingSystem.IsWindows() ? "llvm-pdbutil.exe" : "llvm-pdbutil";
        foreach (string rawDirectory in (Environment.GetEnvironmentVariable("PATH") ?? "")
                     .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            string directory = rawDirectory.Trim().Trim('"');
            // Skip blank or relative PATH entries to avoid executing a binary from CWD.
            if (string.IsNullOrWhiteSpace(directory) || !Path.IsPathFullyQualified(directory))
                continue;
            string candidate = Path.Combine(directory, executable);
            if (File.Exists(candidate))
                return candidate;
        }
        throw new FileNotFoundException(
            "PDB input requires llvm-pdbutil. Install LLVM, put llvm-pdbutil on PATH, or pass --pdb-tool <file>.");
    }

    private static bool TrySegmentOffsetToRva(PeImage image, int segment, ulong offset, out uint rva)
    {
        rva = 0;
        if (segment <= 0 || segment > image.Sections.Count)
            return false;
        PeImage.Section section = image.Sections[segment - 1];
        if (offset >= section.ResolvedVirtualSize)
            return false;
        ulong combined = (ulong)section.VirtualAddress + offset;
        if (combined > uint.MaxValue)
            return false;
        rva = (uint)combined;
        return true;
    }

    private static string? NullIfWhiteSpace(string value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    [GeneratedRegex(@"^\s*(?<segment>[0-9A-Fa-f]{4}):(?<offset>[0-9A-Fa-f]{8,16})\s+(?<name>\S+)(?:\s+(?<address>[0-9A-Fa-f]{8,16}))?(?:\s+[fFiI])*(?:\s+(?<module>\S.*))?\s*$", RegexOptions.CultureInvariant)]
    private static partial Regex MsvcMapLine();

    [GeneratedRegex(@"^[0-9A-Fa-f]+[Hh]$", RegexOptions.CultureInvariant)]
    private static partial Regex MsvcSectionLengthToken();

    [GeneratedRegex(@"^\s*(?<address>0x[0-9A-Fa-f]+)\s+(?<name>\S+)(?:\s+(?<module>\S.*))?\s*$", RegexOptions.CultureInvariant)]
    private static partial Regex GnuMapLine();

    [GeneratedRegex(@"\bS_PUB32\b[^`]*`(?<name>[^`]+)`", RegexOptions.CultureInvariant)]
    private static partial Regex PdbPub32Header();

    [GeneratedRegex(@"addr\s*=\s*(?<segment>[0-9A-Fa-f]+):(?<offset>[0-9A-Fa-f]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PdbAddress();

    [GeneratedRegex(@"name\s*=\s*(?<name>.+)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PdbName();
}
