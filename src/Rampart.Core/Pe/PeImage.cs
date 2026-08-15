using System.Buffers.Binary;
using System.Text;

namespace Rampart.Pe;

/// <summary>One parsed, mutable PE image. The header blobs are kept raw with typed
/// accessors layered on top so a load→save round-trip is byte-exact even for
/// header fields this class never interprets.</summary>
public sealed class PeImage
{
    public const ushort DosMagic = 0x5A4D;      // "MZ"
    public const uint PeSignature = 0x00004550; // "PE\0\0"
    public const ushort MagicPe32Plus = 0x20B;
    public const ushort MagicPe32 = 0x10B;

    private byte[] _dosHeaderAndStub = [];   // everything before the PE signature
    private byte[] _optionalHeader = [];     // raw optional header (PE32+ = 240 bytes)
    private byte[] _overlay = [];            // bytes after the final section (assets/certificates)

    public MachineType Machine { get; set; }
    public ushort NumberOfSections { get; set; }
    public uint TimeDateStamp { get; set; }
    public ushort SizeOfOptionalHeader { get; set; }
    public ushort Characteristics { get; set; }

    public bool IsPe32Plus => OptionalMagic == MagicPe32Plus;
    public int OverlaySize => _overlay.Length;

    /// <summary>All sections in table order. Raw data blobs are mutable in place.</summary>
    public List<Section> Sections { get; } = [];

    public sealed class Section
    {
        public string Name = "";
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public SectionCharacteristics Characteristics;
        public byte[] Data = [];

        public uint ResolvedVirtualSize => Math.Max(VirtualSize, SizeOfRawData);
        public bool ContainsRva(uint rva) => rva >= VirtualAddress && rva < VirtualAddress + ResolvedVirtualSize;
        public bool IsExecutable => (Characteristics & SectionCharacteristics.MemExecute) != 0;

        public override string ToString() => $"{Name} @ RVA {VirtualAddress:X8} VS {VirtualSize:X8} RAW {SizeOfRawData:X8}@{PointerToRawData:X8}";
    }

    private PeImage() { }

    // ---- Typed optional-header accessors (offsets per PE32+/PE32+) ----------

    public ushort OptionalMagic => ReadU16InOptional(0);
    public ulong ImageBase => IsPe32Plus ? ReadU64InOptional(24) : ReadU32InOptional(28);
    public uint EntryPointRva { get => ReadU32InOptional(16); set => WriteU32InOptional(16, value); }
    public uint BaseOfCode => ReadU32InOptional(20);
    public uint SectionAlignment { get => ReadU32InOptional(32); set => WriteU32InOptional(32, value); }
    public uint FileAlignment { get => ReadU32InOptional(36); set => WriteU32InOptional(36, value); }
    public ushort DllCharacteristicsRaw { get => ReadU16InOptional(70); set => WriteU16InOptional(70, value); }
    public uint SizeOfImage { get => ReadU32InOptional(56); set => WriteU32InOptional(56, value); }
    public uint SizeOfHeaders { get => ReadU32InOptional(60); set => WriteU32InOptional(60, value); }

    /// <summary>Major/minor linker version (optional header bytes 2/3).</summary>
    public (byte Major, byte Minor) LinkerVersion
    {
        get => (_optionalHeader[2], _optionalHeader[3]);
        set => (_optionalHeader[2], _optionalHeader[3]) = (value.Major, value.Minor);
    }

    /// <summary>Writes bytes into the DOS header/stub blob (the Rich header and
    /// decoy-planting area — not covered by any section).</summary>
    public void WriteDosStub(int offset, ReadOnlySpan<byte> data)
    {
        if (offset < 0 || offset + data.Length > _dosHeaderAndStub.Length)
            throw new ArgumentOutOfRangeException(nameof(offset));
        data.CopyTo(_dosHeaderAndStub.AsSpan(offset));
    }
    public DllCharacteristics DllChars
    {
        get => (DllCharacteristics)DllCharacteristicsRaw;
        set => DllCharacteristicsRaw = (ushort)value;
    }

    public DataDirectory Directory(int index)
    {
        var off = DataDirectoryOffset(index);
        return new DataDirectory(ReadU32InOptional(off), ReadU32InOptional(off + 4));
    }

    public void SetDirectory(int index, uint rva, uint size)
    {
        var off = DataDirectoryOffset(index);
        WriteU32InOptional(off, rva);
        WriteU32InOptional(off + 4, size);
    }

    private int DataDirectoryOffset(int index)
    {
        // Data directories start at offset 112 in PE32+ (96 in PE32+ there is no
        // BaseOfData difference ahead of them beyond width; 96+16 for PE32).
        int baseOff = IsPe32Plus ? 112 : 96;
        return baseOff + index * 8;
    }

    private ushort ReadU16InOptional(int offset) => BinaryPrimitives.ReadUInt16LittleEndian(_optionalHeader.AsSpan(offset));
    private uint ReadU32InOptional(int offset) => BinaryPrimitives.ReadUInt32LittleEndian(_optionalHeader.AsSpan(offset));
    private ulong ReadU64InOptional(int offset) => BinaryPrimitives.ReadUInt64LittleEndian(_optionalHeader.AsSpan(offset));
    private void WriteU16InOptional(int offset, ushort v) => BinaryPrimitives.WriteUInt16LittleEndian(_optionalHeader.AsSpan(offset), v);
    private void WriteU32InOptional(int offset, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(_optionalHeader.AsSpan(offset), v);

    /// <summary>When set, serialization zeroes the DOS stub (everything between
    /// the DOS header fields and the PE signature) — the Rich header lives there.
    /// MZ, e_lfanew, and the signature itself are preserved.</summary>
    public bool ScrubDosStub { get; set; }

    /// <summary>Immediately clears toolchain-identifying DOS-stub content while
    /// preserving MZ and e_lfanew. Later passes may deliberately plant new
    /// decoy data without serialization erasing it again.</summary>
    public void ScrubDosStubContent()
    {
        if (_dosHeaderAndStub.Length <= 0x40)
            return;

        _dosHeaderAndStub.AsSpan(2, 0x3A).Clear();
        _dosHeaderAndStub.AsSpan(0x40).Clear();
        ScrubDosStub = false;
    }

    // ---- Loading --------------------------------------------------------------

    public static PeImage LoadFile(string path) => Load(File.ReadAllBytes(path));

    public static PeImage Load(byte[] file)
    {
        if (file.Length < 0x100)
            throw new BadImageFormatException("File too small to be a PE image.");

        var dosMagic = BinaryPrimitives.ReadUInt16LittleEndian(file);
        if (dosMagic != DosMagic)
            throw new BadImageFormatException("Missing MZ signature — not a PE file.");

        var pe = new PeImage();
        int lfanew = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C));
        if (lfanew <= 0 || lfanew + 4 + 20 > file.Length)
            throw new BadImageFormatException("e_lfanew out of range.");

        if (BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(lfanew)) != PeSignature)
            throw new BadImageFormatException("Missing PE\\0\\0 signature.");

        pe._dosHeaderAndStub = file[..lfanew];

        int fh = lfanew + 4;
        pe.Machine = (MachineType)BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(fh));
        pe.NumberOfSections = BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(fh + 2));
        pe.TimeDateStamp = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(fh + 4));
        pe.SizeOfOptionalHeader = BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(fh + 16));
        pe.Characteristics = BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(fh + 18));

        int oh = fh + 20;
        if (pe.SizeOfOptionalHeader == 0)
            throw new BadImageFormatException("No optional header (object file?).");
        pe._optionalHeader = file[oh..(oh + pe.SizeOfOptionalHeader)];

        if (pe.OptionalMagic is not (MagicPe32Plus or MagicPe32))
            throw new BadImageFormatException($"Unknown optional header magic {pe.OptionalMagic:X}.");

        int st = oh + pe.SizeOfOptionalHeader;
        if (st + pe.NumberOfSections * 40 > file.Length)
            throw new BadImageFormatException("Section table truncated.");

        for (int i = 0; i < pe.NumberOfSections; i++)
        {
            int s = st + i * 40;
            var sec = new Section
            {
                Name = Encoding.ASCII.GetString(file, s, 8).TrimEnd('\0'),
                VirtualSize = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(s + 8)),
                VirtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(s + 12)),
                SizeOfRawData = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(s + 16)),
                PointerToRawData = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(s + 20)),
                Characteristics = (SectionCharacteristics)BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(s + 36)),
            };
            if (sec.SizeOfRawData > 0)
            {
                if (sec.PointerToRawData + sec.SizeOfRawData > (uint)file.Length)
                    throw new BadImageFormatException($"Section '{sec.Name}' raw data out of range.");
                sec.Data = file[(int)sec.PointerToRawData..(int)(sec.PointerToRawData + sec.SizeOfRawData)];
            }
            else
            {
                sec.Data = [];
            }
            pe.Sections.Add(sec);
        }

        long rawEnd = Math.Max(
            pe.SizeOfHeaders,
            pe.Sections.Count == 0 ? 0 : pe.Sections.Max(s => (long)s.PointerToRawData + s.SizeOfRawData));
        if (rawEnd < file.Length)
            pe._overlay = file[(int)rawEnd..];

        return pe;
    }

    // ---- RVA mapping ------------------------------------------------------------

    public Section? SectionFromRva(uint rva) => Sections.FirstOrDefault(s => s.ContainsRva(rva));

    public bool TryRvaToOffset(uint rva, out int offset)
    {
        offset = 0;
        var sec = SectionFromRva(rva);
        if (sec is null || rva - sec.VirtualAddress >= sec.SizeOfRawData)
            return false;
        offset = (int)(sec.PointerToRawData + (rva - sec.VirtualAddress));
        return true;
    }

    public int RvaToOffset(uint rva) =>
        TryRvaToOffset(rva, out var off)
            ? off
            : throw new ArgumentOutOfRangeException(nameof(rva), $"RVA {rva:X8} has no raw file backing.");

    public bool TryOffsetToRva(int offset, out uint rva)
    {
        rva = 0;
        var sec = Sections.FirstOrDefault(s =>
            offset >= s.PointerToRawData && offset < s.PointerToRawData + s.SizeOfRawData);
        if (sec is null)
            return false;
        rva = sec.VirtualAddress + (uint)(offset - sec.PointerToRawData);
        return true;
    }

    public uint OffsetToRva(int offset) =>
        TryOffsetToRva(offset, out var rva)
            ? rva
            : throw new ArgumentOutOfRangeException(nameof(offset), $"File offset {offset:X8} is inside no section.");

    /// <summary>VA (ImageBase + RVA) → RVA.</summary>
    public uint VaToRva(ulong va) =>
        va >= ImageBase && va - ImageBase < SizeOfImage
            ? (uint)(va - ImageBase)
            : throw new ArgumentOutOfRangeException(nameof(va), $"VA {va:X16} outside image.");

    // ---- Section data access ------------------------------------------------------

    public byte[] ReadRva(uint rva, int length)
    {
        var result = new byte[length];
        int done = 0;
        while (done < length)
        {
            // RvaToOffset pins us to one section's raw window; copy what fits
            // there, clamped to the remaining request.
            uint at = rva + (uint)done;
            int off = RvaToOffset(at);
            var sec = SectionFromRva(at)!;
            int avail = Math.Min(length - done,
                (int)(sec.PointerToRawData + sec.SizeOfRawData - (uint)off));
            Array.Copy(sec.Data, off - (int)sec.PointerToRawData, result, done, avail);
            done += avail;
        }
        return result;
    }

    public uint ReadU32(uint rva) => BinaryPrimitives.ReadUInt32LittleEndian(ReadRva(rva, 4));
    public ulong ReadU64(uint rva) => BinaryPrimitives.ReadUInt64LittleEndian(ReadRva(rva, 8));

    public void WriteRva(uint rva, ReadOnlySpan<byte> data)
    {
        int off = RvaToOffset(rva);
        var sec = SectionFromRva(rva)!;
        data.CopyTo(sec.Data.AsSpan(off - (int)sec.PointerToRawData));
    }

    /// <summary>Reads a NUL-terminated ASCII/UTF-8 string at an RVA.</summary>
    public string ReadCString(uint rva)
    {
        int off = RvaToOffset(rva);
        var sec = SectionFromRva(rva)!;
        var span = sec.Data.AsSpan(off - (int)sec.PointerToRawData);
        int len = span.IndexOf((byte)0);
        if (len < 0)
            len = span.Length;
        return Encoding.UTF8.GetString(span[..len]);
    }

    // ---- Section management -------------------------------------------------------

    /// <summary>Appends a new section (virtual+raw) at the end of the image and
    /// returns it. File alignment is respected for the raw placement; the virtual
    /// address follows the current highest section rounded to section alignment.
    /// Fails when the section-table area cannot grow within SizeOfHeaders.</summary>
    public Section AddSection(string name, int virtualSize, SectionCharacteristics chars)
    {
        if (name.Length > 8)
            throw new ArgumentException("Section name limited to 8 bytes.", nameof(name));

        uint fileAlign = FileAlignment;
        uint sectAlign = SectionAlignment;
        if (fileAlign == 0 || sectAlign == 0)
            throw new BadImageFormatException("Cannot add a section to an image with zero alignment.");

        long oldRawEnd = Math.Max(
            SizeOfHeaders,
            Sections.Count == 0 ? 0 : Sections.Max(s => (long)s.PointerToRawData + s.SizeOfRawData));
        DataDirectory securityBefore = Directory(DataDir.Security);

        int tableStart = DosAndNtHeaderSize + (int)SizeOfOptionalHeader;
        int tableBytes = (NumberOfSections + 1) * 40;
        EnsureSectionTableCapacity(checked(tableStart + tableBytes), fileAlign);

        // Raw placement: end of file rounded up.
        uint rawEnd = Sections.Count > 0
            ? Sections.Max(s => s.PointerToRawData + s.SizeOfRawData)
            : Math.Max(SizeOfHeaders, fileAlign);
        uint rawPtr = AlignUp(rawEnd, fileAlign);
        uint rawSize = AlignUp((uint)virtualSize, fileAlign);

        // Virtual placement: end of image rounded up.
        uint virtEnd = Sections.Count > 0
            ? Sections.Max(s => s.VirtualAddress + s.ResolvedVirtualSize)
            : sectAlign;
        uint virtAddr = AlignUp(virtEnd, sectAlign);

        var sec = new Section
        {
            Name = name,
            VirtualSize = (uint)virtualSize,
            VirtualAddress = virtAddr,
            SizeOfRawData = rawSize,
            PointerToRawData = rawPtr,
            Characteristics = chars,
            Data = new byte[rawSize],
        };
        Sections.Add(sec);
        NumberOfSections++;

        SizeOfImage = AlignUp(virtAddr + rawSize, sectAlign);
        long newOverlayStart = (long)rawPtr + rawSize;
        if (!securityBefore.IsEmpty && securityBefore.RelativeVirtualAddress >= oldRawEnd)
        {
            uint adjusted = checked((uint)(securityBefore.RelativeVirtualAddress + (newOverlayStart - oldRawEnd)));
            SetDirectory(DataDir.Security, adjusted, securityBefore.Size);
        }
        return sec;
    }

    private void EnsureSectionTableCapacity(int requiredBytes, uint fileAlignment)
    {
        if (requiredBytes <= SizeOfHeaders)
            return;

        uint oldHeaders = SizeOfHeaders;
        uint newHeaders = AlignUp(checked((uint)requiredBytes), fileAlignment);
        uint delta = checked(newHeaders - oldHeaders);

        // IMAGE_DEBUG_DIRECTORY stores a raw file pointer in addition to its
        // RVA. Adjust it before moving section file positions; RVA mappings and
        // section payloads themselves remain unchanged.
        DataDirectory debug = Directory(DataDir.Debug);
        if (!debug.IsEmpty && debug.Size >= 28)
        {
            int count = checked((int)(debug.Size / 28));
            for (int i = 0; i < count; i++)
            {
                uint descriptorRva = debug.RelativeVirtualAddress + (uint)(i * 28);
                byte[] descriptor = ReadRva(descriptorRva, 28);
                uint rawPointer = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(24));
                if (rawPointer >= oldHeaders && rawPointer != 0)
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(24), checked(rawPointer + delta));
                    WriteRva(descriptorRva, descriptor);
                }
            }
        }

        foreach (Section section in Sections.Where(section => section.PointerToRawData != 0))
            section.PointerToRawData = checked(section.PointerToRawData + delta);
        SizeOfHeaders = newHeaders;
    }

    internal int DosAndNtHeaderSize => _dosHeaderAndStub.Length + 4 + 20;

    public static uint AlignUp(uint value, uint alignment) =>
        (value + alignment - 1) / alignment * alignment;

    // ---- Serialization ---------------------------------------------------------

    /// <summary>Rebuilds the file: DOS header+stub, PE signature, file header,
    /// optional header, section table, then each section's raw data at its
    /// recorded file offset.</summary>
    public byte[] ToBytes()
    {
        long sectionEnd = Math.Max(
            SizeOfHeaders,
            Sections.Count == 0 ? 0 : Sections.Max(s => (long)s.PointerToRawData + s.SizeOfRawData));
        long fileSize = sectionEnd + _overlay.Length;
        var out_ = new byte[fileSize];

        _dosHeaderAndStub.CopyTo(out_, 0);
        if (ScrubDosStub && _dosHeaderAndStub.Length > 0x40)
        {
            // Keep "MZ" (0-1) and e_lfanew (0x3C-0x3F); wipe the rest of the stub.
            out_.AsSpan(2, 0x3A).Clear();
            out_.AsSpan(0x40, _dosHeaderAndStub.Length - 0x40).Clear();
        }
        int pos = _dosHeaderAndStub.Length;

        BinaryPrimitives.WriteUInt32LittleEndian(out_.AsSpan(pos), PeSignature);
        pos += 4;

        Span<byte> fh = stackalloc byte[20];
        BinaryPrimitives.WriteUInt16LittleEndian(fh, (ushort)Machine);
        BinaryPrimitives.WriteUInt16LittleEndian(fh[2..], NumberOfSections);
        BinaryPrimitives.WriteUInt32LittleEndian(fh[4..], TimeDateStamp);
        BinaryPrimitives.WriteUInt32LittleEndian(fh[8..], 0); // PointerToSymbolTable
        BinaryPrimitives.WriteUInt32LittleEndian(fh[12..], 0); // NumberOfSymbols
        BinaryPrimitives.WriteUInt16LittleEndian(fh[16..], SizeOfOptionalHeader);
        BinaryPrimitives.WriteUInt16LittleEndian(fh[18..], Characteristics);
        fh.CopyTo(out_.AsSpan(pos));
        pos += 20;

        _optionalHeader.CopyTo(out_, pos);
        pos += _optionalHeader.Length;

        Span<byte> sh = stackalloc byte[40];
        foreach (var s in Sections)
        {
            sh.Clear();
            var nameBytes = Encoding.ASCII.GetBytes(s.Name.PadRight(8, '\0')[..8]);
            nameBytes.CopyTo(sh);
            BinaryPrimitives.WriteUInt32LittleEndian(sh[8..], s.VirtualSize);
            BinaryPrimitives.WriteUInt32LittleEndian(sh[12..], s.VirtualAddress);
            BinaryPrimitives.WriteUInt32LittleEndian(sh[16..], s.SizeOfRawData);
            BinaryPrimitives.WriteUInt32LittleEndian(sh[20..], s.PointerToRawData);
            BinaryPrimitives.WriteUInt32LittleEndian(sh[36..], (uint)s.Characteristics);
            sh.CopyTo(out_.AsSpan(pos));
            pos += 40;
        }

        foreach (var s in Sections)
        {
            if (s.SizeOfRawData == 0)
                continue;
            Array.Copy(s.Data, 0, out_, (int)s.PointerToRawData, Math.Min(s.Data.Length, (int)s.SizeOfRawData));
        }

        if (_overlay.Length > 0)
            _overlay.CopyTo(out_, (int)sectionEnd);

        return out_;
    }

    public void Save(string path) => File.WriteAllBytes(path, ToBytes());
}
