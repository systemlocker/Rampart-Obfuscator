using System.Security.Cryptography;
using System.Text.Json;
using Rampart.Config;
using Rampart.Engine;
using Rampart.NativeAot;
using Rampart.Pe;
using Rampart.Targets;

namespace Rampart.Cli;

internal static class InspectCommand
{
    public static int Run(string[] args)
    {
        if (args.Contains("--help", StringComparer.Ordinal) || args.Contains("-h", StringComparer.Ordinal))
        {
            Console.WriteLine("usage: rampart inspect <file> [--json]");
            return 0;
        }

        bool json = false;
        var positional = new List<string>();
        foreach (string arg in args)
        {
            if (arg == "--json") json = true;
            else if (arg.StartsWith("-", StringComparison.Ordinal))
                throw new ArgumentException($"Unknown option '{arg}'.");
            else
                positional.Add(arg);
        }
        if (positional.Count != 1)
            throw new ArgumentException("inspect requires exactly one PE file.");

        string path = Path.GetFullPath(positional[0]);
        byte[] bytes = ProtectionPipeline.ReadInput(path);
        var classification = TargetClassifier.Classify(bytes, path);
        bool inspectNativePe = classification.Target.Kind is ProtectionTargetKind.NativePe or ProtectionTargetKind.NativePeX86
            || (classification.Target.Kind == ProtectionTargetKind.AlreadyProtected && HasRampartSection(bytes));
        if (!inspectNativePe)
        {
            object? audit = null;
            string? auditError = null;
            if (classification.Target.Kind == ProtectionTargetKind.NativeAot && classification.CanProtect)
            {
                try { audit = new NativeAotBackend().Audit(bytes, new ProtectionSettings { Seed = 0 }); }
                catch (NativeAotCompatibilityException error) { auditError = error.Message; }
            }
            if (json)
            {
                Console.WriteLine(JsonSerializer.Serialize(new
                {
                    Path = path,
                    Size = bytes.Length,
                    Sha256 = Convert.ToHexString(SHA256.HashData(bytes)),
                    Classification = classification,
                    NativeAotAudit = audit,
                    NativeAotAuditError = auditError,
                }, ProtectionSettingsJson.Options));
            }
            else
            {
                Console.WriteLine($"target:      {classification.Target.Kind}");
                Console.WriteLine($"disposition: {classification.Disposition}");
                Console.WriteLine($"reason:      {classification.ReasonCode}");
                foreach (string evidence in classification.Evidence) Console.WriteLine($"  {evidence}");
                if (auditError is not null) Console.WriteLine($"audit error: {auditError}");
                if (classification.Target.Kind is ProtectionTargetKind.FrameworkDependentAppHost or ProtectionTargetKind.SelfContainedAppHost)
                    Console.WriteLine("Protect the application DLL before publishing this host.");
            }
            return 0;
        }
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
            if (pe.Machine == MachineType.I386 && !pe.IsPe32Plus)
                PeCompatibility.ValidateX86(pe);
            else
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
                Classification = classification,
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

    private static bool HasRampartSection(byte[] bytes)
    {
        try { return PeImage.Load(bytes).Sections.Any(s => s.Name == ".rmpt"); }
        catch (Exception ex) when (ex is BadImageFormatException or InvalidOperationException or ArgumentException) { return false; }
    }
}
