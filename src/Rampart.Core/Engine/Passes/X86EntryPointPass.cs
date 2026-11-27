using System.Buffers.Binary;

namespace Rampart.Engine.Passes;

/// <summary>
/// PE32 entry-point confusion that stays within the Win32 execution contract.
/// The original register and flag state is restored before a direct relative
/// transfer, so the stub needs no absolute pointers or new base relocations.
/// </summary>
internal sealed class X86EntryPointPass
{
    private const int NoiseBytes = 16;
    private const int StubBytes = 27;

    public void Run(BuildContext context)
    {
        if (context.Level("packaging.ep-confusion") == Config.ProtectionLevel.Off)
            return;
        if (context.InitChain.Count != 0)
            throw new InvalidOperationException("The x86 entry stub does not accept runtime initializers.");

        uint originalEntryPoint = context.Pe.EntryPointRva;
        uint stubRva = context.Alloc(StubBytes, 16);
        var stub = new byte[StubBytes];
        stub[0] = 0x9C; // pushfd
        stub[1] = 0x60; // pushad
        stub[2] = 0xEB;
        stub[3] = NoiseBytes; // skip the cold overlapping-decode field
        context.Rng.NextBytes(stub.AsSpan(4, NoiseBytes));
        stub[20] = 0x61; // popad
        stub[21] = 0x9D; // popfd
        stub[22] = 0xE9;

        long displacement = (long)originalEntryPoint - (stubRva + StubBytes);
        if (displacement is < int.MinValue or > int.MaxValue)
            throw new NotSupportedException("RP_X86_ENTRY_RANGE: The original entry point is outside the rel32 transfer range.");
        BinaryPrimitives.WriteInt32LittleEndian(stub.AsSpan(23), (int)displacement);

        context.WriteStub(stubRva, stub);
        context.Pe.EntryPointRva = stubRva;
        context.Log.Add(new("ep-confusion",
            $"x86 entry rerouted to register-preserving gem at {stubRva:X8}; original entry {originalEntryPoint:X8}"));
    }
}
