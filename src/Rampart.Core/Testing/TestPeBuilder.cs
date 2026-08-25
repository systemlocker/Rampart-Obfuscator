using System.Buffers.Binary;
using System.Text;
using Rampart.Pe;
using Rampart.X64;

namespace Rampart.Testing;

/// <summary>Builds small native x64 console PEs from hand-assembled code, entirely
/// in C#. The engine's end-to-end tests protect these and assert exit codes, which
/// is the only honest proof that a transform preserved semantics. Strings land in
/// a read-only .rdata section exactly like real compiler output, so code reaches
/// them with cross-section RIP-relative accesses the engine must handle.</summary>
public sealed class TestPeBuilder
{
    /// <summary>Context handed to the emitter: the code under construction plus
    /// named data blobs (strings) that land in .rdata.</summary>
    public sealed class Ctx
    {
        public readonly Asm Code = new();
        private readonly List<(string Name, byte[] Data)> _data = [];

        public void String(string name, string value) =>
            _data.Add((name, Encoding.ASCII.GetBytes(value + "\0")));

        /// <summary>Emits lea reg,[rip+name] as a cross-section reference the
        /// builder patches once .rdata layout is known.</summary>
        public void LeaString(Reg reg, string name) => Code.LeaRip(reg, $"str::{name}");

        internal IEnumerable<(string Name, byte[] Data)> DataBlobs => _data;
    }

    public static byte[] Build(Action<Ctx> emit)
    {
        var ctx = new Ctx();
        emit(ctx);

        // Epilogue: move the computed exit code from eax to ecx (ExitProcess(UINT))
        // and call through the IAT slot, RIP-relative. At process entry RSP is
        // 8 mod 16; the push realigns so the callee sees the ABI-required
        // 8 mod 16 after our call pushes the return address.
        ctx.Code.Label("fixture_done");
        ctx.Code.MovRr(Reg.Rcx, Reg.Rax);
        ctx.Code.PushR(Reg.Rax);
        ctx.Code.CallRip("iat_exit");

        ctx.Code.Align(8);
        ctx.Code.Label("iat_exit");
        ctx.Code.Dq(0); // filled with the hint/name RVA below

        // Placeholder bodies for cross-section string references: the lea's disp32
        // resolves against these in-blob offsets first, then gets re-pointed at the
        // final .rdata placement after layout (see RipFixups patching below).
        foreach (var (name, _) in ctx.DataBlobs)
        {
            ctx.Code.Align(8);
            ctx.Code.Label($"str::{name}");
            ctx.Code.Dq(0);
        }

        byte[] text = ctx.Code.Assemble();
        int iatSlotIndex = ctx.Code.LabelOffset("iat_exit");
        int textLen = text.Length;

        // ---- .rdata: imports + strings ----------------------------------------
        // Layout: descriptors(2×20) | dll name | hint/name | INT | strings...
        // The IAT itself (FirstThunk) is the "iat_exit" slot inside .text so the
        // code can reach it RIP-relative; the loader resolves it in place.
        string dll = "KERNEL32.DLL";
        string func = "ExitProcess";

        int descOff = 0;                            // 40 bytes (2 descriptors)
        int dllOff = descOff + 40;                  // dll name + NUL
        int hnOff = dllOff + dll.Length + 1;        // 2-byte hint + name + NUL (+pad)
        int hnLen = 2 + func.Length + 1;
        if (hnLen % 2 != 0) { hnLen++; }
        int intOff = hnOff + hnLen;                 // 16 bytes: name ptr + terminator
        int strOff = intOff + 16;
        int strLen = ctx.DataBlobs.Sum(b => (b.Data.Length + 15) & ~15);
        int rdataLen = strOff + strLen;

        uint textRva = 0x1000;
        uint rdataRva = textRva + AlignUp((uint)textLen, 0x1000);

        var rdata = new byte[rdataLen];
        uint hnRva = rdataRva + (uint)hnOff;
        uint textIatRva = textRva + (uint)iatSlotIndex;

        // Descriptor 1: INT, timestamp(0), forwarder(0), name, FirstThunk → .text slot
        BinaryPrimitives.WriteUInt32LittleEndian(rdata.AsSpan(descOff), rdataRva + (uint)intOff);
        BinaryPrimitives.WriteUInt32LittleEndian(rdata.AsSpan(descOff + 12), rdataRva + (uint)dllOff);
        BinaryPrimitives.WriteUInt32LittleEndian(rdata.AsSpan(descOff + 16), textIatRva);
        Encoding.ASCII.GetBytes(dll + "\0").CopyTo(rdata, dllOff);
        BinaryPrimitives.WriteUInt16LittleEndian(rdata.AsSpan(hnOff), 0);
        Encoding.ASCII.GetBytes(func + "\0").CopyTo(rdata, hnOff + 2);
        BinaryPrimitives.WriteUInt64LittleEndian(rdata.AsSpan(intOff), hnRva);

        // The .text slot starts as a hint/name RVA; the loader replaces it with
        // the resolved address of ExitProcess at import-snap time.
        BinaryPrimitives.WriteUInt64LittleEndian(text.AsSpan(iatSlotIndex), hnRva);

        // Strings into .rdata, 16-aligned; patch the cross-section lea disp32s
        // recorded by LeaString (Asm.RipFixups exposes each operand site).
        int sp = strOff;
        var strRvas = new Dictionary<string, uint>(StringComparer.Ordinal);
        foreach (var (name, data) in ctx.DataBlobs)
        {
            data.CopyTo(rdata, sp);
            strRvas[name] = rdataRva + (uint)sp;
            sp += (data.Length + 15) & ~15;
        }

        // ---- Assemble the PE -----------------------------------------------------
        var file = new byte[0x400 + AlignUp((uint)textLen, 0x200) + AlignUp((uint)rdataLen, 0x200) + 0x200];

        file[0] = (byte)'M'; file[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(file.AsSpan(0x3C), 0x80);

        int p = 0x80;
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(p), 0x00004550); p += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(p), (ushort)MachineType.Amd64); p += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(p), 3); p += 2;  // NumberOfSections
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(p), 0x6651A3DE); p += 4; // a timestamp
        p += 8;                                                                // sym table + count
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(p), 0xF0); p += 2; // SizeOfOptionalHeader
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(p), 0x0022); p += 2; // EXECUTABLE_IMAGE|LARGE_ADDRESS_AWARE

        // .pdata: one RUNTIME_FUNCTION covering the code region (end = the
        // iat_exit label, before the data tail) + a minimal NHANDLER unwind blob.
        // Real compiler output always carries this map; the engine's function
        // discovery relies on it.
        uint pdataRva = rdataRva + AlignUp((uint)rdataLen, 0x1000);
        uint unwindRva = pdataRva + 12u; // entry(12) then unwind info
        var pdata = new byte[24];
        BinaryPrimitives.WriteUInt32LittleEndian(pdata.AsSpan(0), textRva);
        BinaryPrimitives.WriteUInt32LittleEndian(pdata.AsSpan(4), textIatRva);
        BinaryPrimitives.WriteUInt32LittleEndian(pdata.AsSpan(8), unwindRva);
        pdata[12] = 0x09; // UNWIND_INFO: version 1, flags = UNW_FLAG_NHANDLER(2)
        pdata[13] = 0;
        pdata[14] = 0;
        pdata[15] = 0;

        Span<byte> oh = file.AsSpan(p, 0xF0);
        BuildOptionalHeader(oh, textRva, rdataRva, (uint)rdataLen, textIatRva, pdataRva);

        int st = p + 0xF0;
        uint textRawSize = AlignUp((uint)textLen, 0x200);
        uint rdataRawSize = AlignUp((uint)rdataLen, 0x200);
        uint pdataRawSize = 0x200;
        WriteSection(file, st, ".text", (uint)textLen, textRva, textRawSize, 0x400,
            // Writable because the IAT slot lives here and the loader resolves
            // imports in place; a read-only IAT relies on loader COW behavior.
            SectionCharacteristics.CntCode | SectionCharacteristics.MemExecute
                | SectionCharacteristics.MemRead | SectionCharacteristics.MemWrite);
        WriteSection(file, st + 40, ".rdata", (uint)rdataLen, rdataRva, rdataRawSize, 0x400 + textRawSize,
            SectionCharacteristics.CntInitializedData | SectionCharacteristics.MemRead);
        WriteSection(file, st + 80, ".pdata", 24, pdataRva, pdataRawSize, 0x400 + textRawSize + rdataRawSize,
            SectionCharacteristics.CntInitializedData | SectionCharacteristics.MemRead);
        pdata.CopyTo(file, (int)(0x400 + textRawSize + rdataRawSize));

        text.CopyTo(file, 0x400);
        rdata.CopyTo(file, (int)(0x400 + textRawSize));

        // Re-point each string lea at its final .rdata home. The blob-relative
        // disp32 sits at the fixup position; the next-instruction RVA is
        // textRva + pos + 4 (disp32 is the instruction's last operand).
        foreach (var (pos, target, _) in ctx.Code.RipFixups)
        {
            if (!target.StartsWith("str::", StringComparison.Ordinal))
                continue;
            string name = target["str::".Length..];
            uint strRva = strRvas[name];
            int newDisp = (int)strRva - (int)(textRva + (uint)pos + 4);
            BinaryPrimitives.WriteInt32LittleEndian(text.AsSpan(pos), newDisp);
        }
        text.CopyTo(file, 0x400); // again: the patched copy

        return file;

        static uint AlignUp(uint v, uint a) => (v + a - 1) / a * a;

        static void WriteSection(byte[] f, int off, string name, uint vsize, uint rva, uint rawSize, uint rawPtr, SectionCharacteristics chars)
        {
            Encoding.ASCII.GetBytes(name.PadRight(8, '\0')[..8]).CopyTo(f, off);
            BinaryPrimitives.WriteUInt32LittleEndian(f.AsSpan(off + 8), vsize);
            BinaryPrimitives.WriteUInt32LittleEndian(f.AsSpan(off + 12), rva);
            BinaryPrimitives.WriteUInt32LittleEndian(f.AsSpan(off + 16), rawSize);
            BinaryPrimitives.WriteUInt32LittleEndian(f.AsSpan(off + 20), rawPtr);
            BinaryPrimitives.WriteUInt32LittleEndian(f.AsSpan(off + 36), (uint)chars);
        }
    }

    private static void BuildOptionalHeader(Span<byte> oh, uint textRva, uint rdataRva, uint rdataLen, uint iatRva, uint pdataRva)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(oh, 0x20B);                       // magic
        oh[2] = 14; oh[3] = 0;                                                     // linker version
        BinaryPrimitives.WriteUInt32LittleEndian(oh[16..], textRva);               // AddressOfEntryPoint (patched by caller if needed)
        BinaryPrimitives.WriteUInt32LittleEndian(oh[20..], textRva);               // BaseOfCode
        BinaryPrimitives.WriteUInt64LittleEndian(oh[24..], 0x140000000);           // ImageBase
        BinaryPrimitives.WriteUInt32LittleEndian(oh[32..], 0x1000);                // SectionAlignment
        BinaryPrimitives.WriteUInt32LittleEndian(oh[36..], 0x200);                 // FileAlignment
        BinaryPrimitives.WriteUInt16LittleEndian(oh[40..], 6);                     // MajorOSVersion
        BinaryPrimitives.WriteUInt16LittleEndian(oh[48..], 6);                     // MajorSubsystemVersion (0 here is a classic loader rejection)
        BinaryPrimitives.WriteUInt32LittleEndian(oh[60..], 0x400);                 // SizeOfHeaders
        BinaryPrimitives.WriteUInt16LittleEndian(oh[68..], 3);                     // Subsystem: console
        BinaryPrimitives.WriteUInt16LittleEndian(oh[70..], (ushort)(DllCharacteristics.HighEntropyVa | DllCharacteristics.DynamicBase | DllCharacteristics.NxCompatible));
        // Zero stack/heap sizes would hand the main thread a zero-sized stack —
        // every push faults. Use MSVC's defaults.
        BinaryPrimitives.WriteUInt64LittleEndian(oh[72..], 0x100000);              // SizeOfStackReserve
        BinaryPrimitives.WriteUInt64LittleEndian(oh[80..], 0x1000);                // SizeOfStackCommit
        BinaryPrimitives.WriteUInt64LittleEndian(oh[88..], 0x100000);              // SizeOfHeapReserve
        BinaryPrimitives.WriteUInt64LittleEndian(oh[96..], 0x1000);                // SizeOfHeapCommit
        BinaryPrimitives.WriteUInt32LittleEndian(oh[108..], 16);                   // NumberOfRvaAndSizes
        uint sizeOfImage = pdataRva + 0x1000;
        BinaryPrimitives.WriteUInt32LittleEndian(oh[56..], sizeOfImage);
        BinaryPrimitives.WriteUInt32LittleEndian(oh[(112 + DataDir.Exception * 8)..], pdataRva);
        BinaryPrimitives.WriteUInt32LittleEndian(oh[(112 + DataDir.Exception * 8 + 4)..], 12);
        // Data directories: import (1) and IAT (12). The IAT lives in .text.
        BinaryPrimitives.WriteUInt32LittleEndian(oh[(112 + DataDir.Import * 8)..], rdataRva);
        BinaryPrimitives.WriteUInt32LittleEndian(oh[(112 + DataDir.Import * 8 + 4)..], 40);
        BinaryPrimitives.WriteUInt32LittleEndian(oh[(112 + DataDir.Iat * 8)..], iatRva);
        BinaryPrimitives.WriteUInt32LittleEndian(oh[(112 + DataDir.Iat * 8 + 4)..], 8);
    }
}
