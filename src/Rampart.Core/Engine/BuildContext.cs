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

    /// <summary>Functions from `.pdata`, enriched with optional build symbols.</summary>
    public List<FunctionDescriptor> Functions { get; private set; } = [];
    public FunctionPolicy FunctionPolicy { get; }
    public IReadOnlyList<SymbolRecord> Symbols { get; }

    /// <summary>Stub section (protector code + data), created on first use.</summary>
    public PeImage.Section? Stub { get; private set; }
    public uint StubRva { get; private set; }
    private int _stubUsed;

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

    public void Analyze()
    {
        Functions = FunctionDescriptor.Attach(Pe, ExceptionTable.Parse(Pe), Symbols);
        int selected = Functions.Count(FunctionPolicy.IsSelected);
        PeCompatibilityFeatures features = PeCompatibility.Inspect(Pe);
        Log.Add(new("analyze",
            $"parsed {Functions.Count} runtime functions ({selected} selected, {Symbols.Count} symbols), " +
            $"{ImportTable.Parse(Pe).Count} imports, machine {Pe.Machine}; {features.Summary}"));
    }

    /// <summary>Creates the protector's own section (RWX: code, tables, and
    /// relocated pointer slots all live here) if it does not exist yet.</summary>
    public PeImage.Section EnsureStubSection()
    {
        if (Stub != null)
            return Stub;

        Stub = Pe.AddSection(".rmpt", 0x1000,
            SectionCharacteristics.CntCode | SectionCharacteristics.CntInitializedData | SectionCharacteristics.MemRead
            | SectionCharacteristics.MemWrite | SectionCharacteristics.MemExecute);
        StubRva = Stub.VirtualAddress;
        _stubUsed = 0;
        Log.Add(new("stub-section", $"allocated .rmpt at RVA {StubRva:X8}"));
        return Stub;
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
        uint sectionAlignment = Pe.SectionAlignment;
        int doubled = checked(stub.Data.Length * 2);
        uint newSize = PeImage.AlignUp((uint)Math.Max(required, doubled), fileAlignment);
        Array.Resize(ref stub.Data, checked((int)newSize));
        stub.VirtualSize = newSize;
        stub.SizeOfRawData = newSize;
        Pe.SizeOfImage = PeImage.AlignUp(stub.VirtualAddress + newSize, sectionAlignment);
        Log.Add(new("stub-section", $"grew .rmpt capacity to {newSize} bytes"));
    }

    /// <summary>Writes bytes into the stub section at an allocated RVA.</summary>
    public void WriteStub(uint rva, ReadOnlySpan<byte> data)
    {
        var stub = EnsureStubSection();
        data.CopyTo(stub.Data.AsSpan((int)(rva - StubRva)));
    }

    /// <summary>Registers an absolute-pointer slot (needs a DIR64 relocation).</summary>
    public uint AllocPointerSlot()
    {
        uint rva = Alloc(8, 8);
        RelocSlots.Add(rva);
        return rva;
    }

    /// <summary>Registers an init routine to run before the original entry point.</summary>
    public void RegisterInit(uint rva, string what)
    {
        InitChain.Add(rva);
        Log.Add(new("init-chain", $"registered {what} at RVA {rva:X8}"));
    }
}
