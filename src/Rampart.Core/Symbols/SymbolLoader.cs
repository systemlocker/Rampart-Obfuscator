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

    public static List<SymbolRecord> ParseJson(string json) =>
        JsonSerializer.Deserialize<List<SymbolRecord>>(json, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
        }) ?? [];

    public static List<SymbolRecord> ParseMap(string text, PeImage image, string sourceName = "symbols.map")
    {
        var result = new List<SymbolRecord>();
        foreach (string line in text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            Match msvc = MsvcMapLine().Match(line);
            if (msvc.Success)
            {
                int segment = int.Parse(msvc.Groups["segment"].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                ulong offset = ulong.Parse(msvc.Groups["offset"].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                ulong address = msvc.Groups["address"].Success
                    ? ulong.Parse(msvc.Groups["address"].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture)
                    : 0;
                uint rva = address >= image.ImageBase && address - image.ImageBase <= uint.MaxValue
                    ? (uint)(address - image.ImageBase)
                    : SegmentOffsetToRva(image, segment, offset);
                result.Add(new SymbolRecord
                {
                    Name = msvc.Groups["name"].Value,
                    StartRva = rva,
                    Module = NullIfWhiteSpace(msvc.Groups["module"].Value),
                    Source = sourceName,
                });
                continue;
            }

            Match gnu = GnuMapLine().Match(line);
            if (!gnu.Success)
                continue;
            ulong absolute = ulong.Parse(gnu.Groups["address"].Value[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            if (absolute < image.ImageBase || absolute - image.ImageBase > uint.MaxValue)
                continue;
            result.Add(new SymbolRecord
            {
                Name = gnu.Groups["name"].Value,
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
            Match addressMatch = PdbAddress().Match(line);
            if (addressMatch.Success)
            {
                address = (
                    int.Parse(addressMatch.Groups["segment"].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture),
                    ulong.Parse(addressMatch.Groups["offset"].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture));
            }
            Match nameMatch = PdbName().Match(line);
            if (nameMatch.Success)
                name = nameMatch.Groups["name"].Value.Trim();

            if (address is not { } at || string.IsNullOrWhiteSpace(name))
                continue;
            result.Add(new SymbolRecord
            {
                Name = name,
                StartRva = SegmentOffsetToRva(image, at.Segment, at.Offset),
                Source = sourceName,
            });
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
        string stdout = process.StandardOutput.ReadToEnd();
        string stderr = process.StandardError.ReadToEnd();
        if (!process.WaitForExit(60_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException($"PDB reader '{tool}' did not finish within 60 seconds.");
        }
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
        foreach (string directory in (Environment.GetEnvironmentVariable("PATH") ?? "")
                     .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            string candidate = Path.Combine(directory.Trim('"'), executable);
            if (File.Exists(candidate))
                return candidate;
        }
        throw new FileNotFoundException(
            "PDB input requires llvm-pdbutil. Install LLVM, put llvm-pdbutil on PATH, or pass --pdb-tool <file>.");
    }

    private static uint SegmentOffsetToRva(PeImage image, int segment, ulong offset)
    {
        if (segment <= 0 || segment > image.Sections.Count || offset > uint.MaxValue)
            throw new FormatException($"Symbol address {segment:X4}:{offset:X} does not map to a PE section.");
        return checked(image.Sections[segment - 1].VirtualAddress + (uint)offset);
    }

    private static string? NullIfWhiteSpace(string value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    [GeneratedRegex(@"^\s*(?<segment>[0-9A-Fa-f]{4}):(?<offset>[0-9A-Fa-f]{8,16})\s+(?<name>\S+)(?:\s+(?<address>[0-9A-Fa-f]{8,16}))?(?:\s+[fFiI])?(?:\s+(?<module>\S.*))?\s*$", RegexOptions.CultureInvariant)]
    private static partial Regex MsvcMapLine();

    [GeneratedRegex(@"^\s*(?<address>0x[0-9A-Fa-f]+)\s+(?<name>\S+)(?:\s+(?<module>\S.*))?\s*$", RegexOptions.CultureInvariant)]
    private static partial Regex GnuMapLine();

    [GeneratedRegex(@"addr\s*=\s*(?<segment>[0-9A-Fa-f]+):(?<offset>[0-9A-Fa-f]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PdbAddress();

    [GeneratedRegex(@"name\s*=\s*(?<name>.+)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PdbName();
}
