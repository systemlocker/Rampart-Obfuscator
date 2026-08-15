using System.Security.Cryptography;
using System.Text.Json;
using Rampart.Config;
using Rampart.Engine;
using Rampart.Pe;

namespace Rampart.Cli;

internal static class InspectCommand
{
    public static int Run(string[] args)
    {
        if (args.Contains("--help", StringComparer.Ordinal))
        {
            Console.WriteLine("usage: rampart inspect <file> [--json]");
            return 0;
        }

        bool json = args.Contains("--json", StringComparer.Ordinal);
        var positional = args.Where(a => a != "--json").ToList();
        if (positional.Count != 1)
            throw new ArgumentException("inspect requires exactly one PE file.");

        string path = Path.GetFullPath(positional[0]);
        byte[] bytes = File.ReadAllBytes(path);
        var pe = PeImage.Load(bytes);
        var directories = Enumerable.Range(0, DataDir.Names.Length)
            .Select(i => new { Name = DataDir.Names[i], Value = pe.Directory(i) })
            .Where(d => !d.Value.IsEmpty)
            .Select(d => new { d.Name, Rva = d.Value.RelativeVirtualAddress, d.Value.Size })
            .ToList();
        var sections = pe.Sections.Select(s => new
        {
            s.Name,
            Rva = s.VirtualAddress,
            s.VirtualSize,
            RawOffset = s.PointerToRawData,
            RawSize = s.SizeOfRawData,
            Characteristics = $"0x{(uint)s.Characteristics:X8}",
        }).ToList();
        bool rampart = pe.Sections.Any(s => s.Name == ".rmpt");
        string sha = Convert.ToHexString(SHA256.HashData(bytes));
        string? compatibilityError = null;
        PeCompatibilityFeatures? compatibility = null;
        try
        {
            compatibility = PeCompatibility.Inspect(pe);
            PeCompatibility.Validate(pe);
        }
        catch (Exception ex) when (ex is NotSupportedException or InvalidOperationException or BadImageFormatException)
        {
            compatibilityError = ex.Message;
        }

        if (json)
        {
            var report = new
            {
                Path = path,
                Size = bytes.Length,
                Sha256 = sha,
                Machine = pe.Machine.ToString(),
                Pe32Plus = pe.IsPe32Plus,
                pe.ImageBase,
                pe.EntryPointRva,
                pe.SizeOfImage,
                pe.OverlaySize,
                RampartSection = rampart,
                CompatibleInput = compatibilityError is null,
                CompatibilityError = compatibilityError,
                Compatibility = compatibility,
                Sections = sections,
                Directories = directories,
            };
            Console.WriteLine(JsonSerializer.Serialize(report, ProtectionSettingsJson.Options));
            return 0;
        }

        Console.WriteLine($"path:        {path}");
        Console.WriteLine($"size:        {bytes.Length} bytes");
        Console.WriteLine($"sha256:      {sha}");
        Console.WriteLine($"machine:     {pe.Machine} ({(pe.IsPe32Plus ? "PE32+" : "PE32")})");
        Console.WriteLine($"image base:  0x{pe.ImageBase:X16}");
        Console.WriteLine($"entry point: RVA 0x{pe.EntryPointRva:X8}");
        Console.WriteLine($"overlay:     {pe.OverlaySize} bytes");
        Console.WriteLine($"Rampart:     {(rampart ? "section present" : "not detected")}");
        Console.WriteLine($"compatible:  {(compatibilityError is null ? "yes" : $"no — {compatibilityError}")}");
        if (compatibility is not null)
            Console.WriteLine($"loader data: {compatibility.Summary}");
        Console.WriteLine("sections:");
        foreach (var section in sections)
            Console.WriteLine($"  {section.Name,-8} RVA {section.Rva:X8} VS {section.VirtualSize:X8} RAW {section.RawSize:X8}@{section.RawOffset:X8} {section.Characteristics}");
        Console.WriteLine("directories:");
        foreach (var directory in directories)
            Console.WriteLine($"  {directory.Name,-14} RVA {directory.Rva:X8} size {directory.Size:X8}");
        return 0;
    }
}
