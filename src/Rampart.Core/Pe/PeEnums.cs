namespace Rampart.Pe;

public enum MachineType : ushort
{
    I386 = 0x014C,
    Amd64 = 0x8664,
    Arm64 = 0xAA64,
}

/// <summary>Subset of data-directory indices a protector touches. The unused
/// slots still round-trip untouched.</summary>
public static class DataDir
{
    public const int Export = 0;
    public const int Import = 1;
    public const int Resource = 2;
    public const int Exception = 3;
    public const int Security = 4;
    public const int Basereloc = 5;
    public const int Debug = 6;
    public const int Architecture = 7;
    public const int GlobalPtr = 8;
    public const int Tls = 9;
    public const int LoadConfig = 10;
    public const int BoundImport = 11;
    public const int Iat = 12;
    public const int DelayImport = 13;
    public const int ComDescriptor = 14;

    public static readonly string[] Names =
    [
        "Export", "Import", "Resource", "Exception", "Security", "BaseReloc",
        "Debug", "Architecture", "GlobalPtr", "TLS", "LoadConfig", "BoundImport",
        "IAT", "DelayImport", "COM Descriptor", "Reserved",
    ];
}

[Flags]
public enum DllCharacteristics : ushort
{
    HighEntropyVa = 0x0020,
    DynamicBase = 0x0040,
    ForceIntegrity = 0x0080,
    NxCompatible = 0x0100,
    NoIsolation = 0x0200,
    NoSeh = 0x0400,
    NoBind = 0x0800,
    AppContainer = 0x1000,
    WdmDriver = 0x2000,
    GuardCf = 0x4000,
    TerminalServerAware = 0x8000,
}

[Flags]
public enum ImageGuardFlags : uint
{
    CfInstrumented = 0x00000100,
    CfFunctionTablePresent = 0x00000400,
    ProtectDelayLoadIat = 0x00001000,
    CfLongJumpTablePresent = 0x00010000,
    RetpolinePresent = 0x00100000,
    EhContinuationTablePresent = 0x00400000,
    XfgEnabled = 0x00800000,
}

[Flags]
public enum SectionCharacteristics : uint
{
    TypeNoPad = 0x00000008,
    CntCode = 0x00000020,
    CntInitializedData = 0x00000040,
    CntUninitializedData = 0x00000080,
    MemExecute = 0x20000000,
    MemRead = 0x40000000,
    MemWrite = 0x80000000,
}

public sealed record DataDirectory(uint RelativeVirtualAddress, uint Size)
{
    public bool IsEmpty => RelativeVirtualAddress == 0 && Size == 0;
}
