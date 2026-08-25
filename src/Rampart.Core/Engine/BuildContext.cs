using System.Buffers.Binary;
using Rampart.Config;
using Rampart.Pe;
using Rampart.Symbols;
using Rampart.X64;

namespace Rampart.Engine;

/// <summary>One entry in the build log: what a pass did, in order. Feeds
/// `rampart inspect`, the build history, and the payload preview.</summary>
public sealed record BuildLogEntry(string Pass, string Detail);

/// <summary>State shared by every pass for one build. The seed drives all
/// randomization: same seed ⇒ identical output; different seed ⇒ no shared bytes.</summary>
public sealed class BuildContext
{
    public PeImage Pe { get; }
    public ProtectionSettings Settings { get; }
    public KnobCatalog Catalog { get; }
    public Random Rng { get; }
    public List<BuildLogEntry> Log { get; } = [];
    private readonly Dictionary<string, ProtectionLevel> _applied = new(StringComparer.Ordinal);
    public IReadOnlyDictionary<string, ProtectionLevel> Applied => _applied;

    /// <summary>Functions from `.pdata`, enriched with optional build symbols.</summary>
    public List<FunctionDescriptor> Functions { get; private set; } = [];
    public FunctionPolicy FunctionPolicy { get; }
    public IReadOnlyList<SymbolRecord> Symbols { get; }

    /// <summary>Executable protector stubs, created on first use.</summary>
    public PeImage.Section? Stub { get; private set; }
    public uint StubRva { get; private set; }
    private int _stubUsed;

    /// <summary>Mutable protector state and loader-written tables.</summary>
    public PeImage.Section? Data { get; private set; }
    public uint DataRva { get; private set; }
    private int _dataUsed;

    private const int StubVirtualReservation = 0x10_0000;

    /// <summary>Init routines (RVAs) the runtime calls before the original entry
    /// point, in registration order.</summary>
    public List<uint> InitChain { get; } = [];

    /// <summary>RVA slots (8 bytes each) that will hold absolute pointers and need
    /// DIR64 relocation entries in the rebuilt table.</summary>
    public List<uint> RelocSlots { get; } = [];

    public BuildContext(
        PeImage pe,
        ProtectionSettings settings,
        KnobCatalog catalog,
        IReadOnlyList<SymbolRecord>? symbols = null)
    {
        Pe = pe;
        Settings = settings;
        Catalog = catalog;
        Symbols = symbols ?? [];
        FunctionPolicy = new FunctionPolicy(settings, catalog);
        // Random() seeds from int; fold the long seed in so both halves matter.
        Rng = new Random(unchecked((int)(settings.Seed ^ (settings.Seed >> 32)) | 1));
    }

    public ProtectionLevel Level(string knobId) => Settings.LevelOf(Catalog.Get(knobId));
    public ProtectionLevel LevelFor(string knobId, FunctionDescriptor function) =>
        FunctionPolicy.Level(knobId, function);
    public ProtectionLevel MaximumFunctionLevel(string knobId) =>
        FunctionPolicy.MaximumLevel(knobId, Functions);

    public void MarkApplied(string knobId)
    {
        ProtectionLevel level = ProtectionCapabilities.FunctionScopedKnobs.Contains(knobId)
            ? MaximumFunctionLevel(knobId)
            : Level(knobId);
        MarkApplied(knobId, level);
    }

    public void MarkApplied(string knobId, ProtectionLevel level)
    {
        Catalog.Get(knobId);
        if (level == ProtectionLevel.Off)
            return;
        if (!_applied.TryGetValue(knobId, out ProtectionLevel current) || level > current)
            _applied[knobId] = level;
    }

    public void Analyze()
    {
        Functions = FunctionDescriptor.Attach(Pe, ExceptionTable.Parse(Pe), Symbols);
        int selected = Functions.Count(FunctionPolicy.IsSelected);
        PeCompatibilityFeatures features = PeCompatibility.Inspect(Pe);
        Log.Add(new("analyze",
            $"parsed {Functions.Count} runtime functions ({selected} selected, {Symbols.Count} symbols), " +
            $"{ImportTable.Parse(Pe).Count} imports, machine {Pe.Machine}; {features.Summary}"));
    }

    /// <summary>Creates the protector's RX code section if it does not exist.</summary>
    public PeImage.Section EnsureStubSection()
    {
        if (Stub != null)
            return Stub;

        Stub = Pe.AddSection(".rmpt", 0x1000,
            SectionCharacteristics.CntCode | SectionCharacteristics.CntInitializedData | SectionCharacteristics.MemRead
            | SectionCharacteristics.MemExecute);
        StubRva = Stub.VirtualAddress;
        _stubUsed = 0;
        Log.Add(new("stub-section", $"allocated .rmpt at RVA {StubRva:X8}"));
        return Stub;
    }

    /// <summary>Creates the protector's RW data section. The code section keeps
    /// a bounded virtual reservation so later stub growth cannot overlap it.</summary>
    public PeImage.Section EnsureDataSection()
    {
        if (Data != null)
            return Data;

        PeImage.Section stub = EnsureStubSection();
        stub.VirtualSize = PeImage.AlignUp(
            Math.Max(stub.SizeOfRawData, StubVirtualReservation),
            Pe.SectionAlignment);
        Data = Pe.AddSection(".rmpd", 0x1000,
            SectionCharacteristics.CntInitializedData | SectionCharacteristics.MemRead
            | SectionCharacteristics.MemWrite);
        DataRva = Data.VirtualAddress;
        _dataUsed = 0;
        Log.Add(new("data-section", $"allocated .rmpd at RVA {DataRva:X8}"));
        return Data;
    }

    /// <summary>Bump-allocates in the stub section and returns the RVA.</summary>
    public uint Alloc(int size, int alignment = 1)
    {
        var stub = EnsureStubSection();
        while (_stubUsed % alignment != 0)
            _stubUsed++;
        int off = _stubUsed;
        _stubUsed += size;
        EnsureStubCapacity(stub, _stubUsed);
        return StubRva + (uint)off;
    }

    private void EnsureStubCapacity(PeImage.Section stub, int required)
    {
        if (required <= stub.Data.Length)
            return;

        uint fileAlignment = Pe.FileAlignment;
        if (Data != null && required > stub.VirtualSize)
            throw new InvalidOperationException(
                $"Protector stubs exceed the {stub.VirtualSize}-byte RX reservation.");
        int doubled = checked(stub.Data.Length * 2);
        uint newSize = PeImage.AlignUp((uint)Math.Max(required, doubled), fileAlignment);
        uint growth = newSize - stub.SizeOfRawData;
        foreach (PeImage.Section later in Pe.Sections.Where(section =>
                     section != stub && section.PointerToRawData > stub.PointerToRawData))
            later.PointerToRawData = checked(later.PointerToRawData + growth);
        Array.Resize(ref stub.Data, checked((int)newSize));
        if (Data is null)
        {
            stub.VirtualSize = newSize;
            Pe.SizeOfImage = PeImage.AlignUp(stub.VirtualAddress + newSize, Pe.SectionAlignment);
        }
        stub.SizeOfRawData = newSize;
        Log.Add(new("stub-section", $"grew .rmpt capacity to {newSize} bytes"));
    }

    /// <summary>Writes bytes into the stub section at an allocated RVA.</summary>
    public void WriteStub(uint rva, ReadOnlySpan<byte> data)
    {
        var stub = EnsureStubSection();
        data.CopyTo(stub.Data.AsSpan((int)(rva - StubRva)));
    }

    /// <summary>Bump-allocates in the non-executable data section.</summary>
    public uint AllocData(int size, int alignment = 1)
    {
        PeImage.Section data = EnsureDataSection();
        while (_dataUsed % alignment != 0)
            _dataUsed++;
        int off = _dataUsed;
        _dataUsed += size;
        EnsureDataCapacity(data, _dataUsed);
        return DataRva + (uint)off;
    }

    private void EnsureDataCapacity(PeImage.Section data, int required)
    {
        if (required <= data.Data.Length)
            return;

        int doubled = checked(data.Data.Length * 2);
        uint newSize = PeImage.AlignUp((uint)Math.Max(required, doubled), Pe.FileAlignment);
        Array.Resize(ref data.Data, checked((int)newSize));
        data.VirtualSize = newSize;
        data.SizeOfRawData = newSize;
        Pe.SizeOfImage = PeImage.AlignUp(data.VirtualAddress + newSize, Pe.SectionAlignment);
        Log.Add(new("data-section", $"grew .rmpd capacity to {newSize} bytes"));
    }

    public void WriteData(uint rva, ReadOnlySpan<byte> data)
    {
        PeImage.Section section = EnsureDataSection();
        data.CopyTo(section.Data.AsSpan((int)(rva - DataRva)));
    }

    /// <summary>Registers an absolute-pointer slot (needs a DIR64 relocation).</summary>
    public uint AllocPointerSlot()
    {
        uint rva = AllocData(8, 8);
        RelocSlots.Add(rva);
        return rva;
    }

    /// <summary>Redirects assembled RIP-relative operands to external data RVAs.</summary>
    public static void PatchRipReferences(
        byte[] code,
        Asm assembler,
        uint codeRva,
        IReadOnlyDictionary<string, uint> targets)
    {
        foreach ((int position, string target, int extra) in assembler.RipFixups)
        {
            if (!targets.TryGetValue(target, out uint targetRva))
                continue;
            long displacement = (long)targetRva + extra - ((long)codeRva + position + 4);
            if (displacement is < int.MinValue or > int.MaxValue)
                throw new InvalidOperationException($"RIP-relative target '{target}' is outside disp32 range.");
            BinaryPrimitives.WriteInt32LittleEndian(code.AsSpan(position), checked((int)displacement));
        }
    }

    /// <summary>Registers an init routine to run before the original entry point.</summary>
    public void RegisterInit(uint rva, string what)
    {
        InitChain.Add(rva);
        Log.Add(new("init-chain", $"registered {what} at RVA {rva:X8}"));
    }
}
