using System.Buffers.Binary;
using Rampart.X64;
using Xunit;

namespace Rampart.Tests.X64;

public class AsmTests
{
    [Fact]
    public void MovRrUsesCorrectRexBitsForMixedLowAndHighRegisters()
    {
        var assembler = new Asm();
        assembler.MovRr(Reg.R9, Reg.Rdx);
        assembler.MovRr(Reg.Rcx, Reg.R10);

        Assert.Equal(new byte[]
        {
            0x49, 0x89, 0xD1, // mov r9, rdx
            0x4C, 0x89, 0xD1, // mov rcx, r10
        }, assembler.Assemble());
    }

    [Fact]
    public void XorSplitMaterializesTheRequestedValue()
    {
        const long value = unchecked((long)0xF123456789ABCDEFUL);
        const long mask = unchecked((long)0x55AA33CC77EE1199UL);
        var assembler = new Asm();

        assembler.MovRiXorSplit(Reg.R14, value, Reg.Rax, mask);
        byte[] code = assembler.Assemble();

        // Both values require imm64 encodings here: 49 BE <term>, 48 B8 <mask>,
        // then 49 31 C6 (xor r14,rax).
        long encoded = BinaryPrimitives.ReadInt64LittleEndian(code.AsSpan(2));
        long emittedMask = BinaryPrimitives.ReadInt64LittleEndian(code.AsSpan(12));
        Assert.Equal(value, encoded ^ emittedMask);
        Assert.Equal(mask, emittedMask);
        Assert.Equal(new byte[] { 0x49, 0x31, 0xC6 }, code[^3..]);
    }

    [Theory]
    [InlineData(Reg.Rax, 9)]
    [InlineData(Reg.R15, 10)]
    public void LoadRuntimeBaseSubtractsTheCallReturnAddress(Reg register, int immediateOffset)
    {
        const uint blobRva = 0x4200;
        var assembler = new Asm();
        assembler.LoadRuntimeBase(register, blobRva);

        byte[] code = assembler.Assemble();
        int subtract = BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(immediateOffset));

        // The return address pushed by CALL is blob RVA + 5 for both low and
        // extended registers; POP's encoding width must not affect the value.
        Assert.Equal((int)blobRva + 5, subtract);
    }

    [Fact]
    public void AtomicStateInstructionsEncodeLockAndExtendedBaseRegisters()
    {
        var assembler = new Asm();

        assembler.LockBtsMi(Reg.R15, 24, 6);
        assembler.LockXorMr(Reg.R15, Reg.Rcx, 32);

        Assert.Equal(new byte[]
        {
            0xF0, 0x49, 0x0F, 0xBA, 0x6F, 0x18, 0x06, // lock bts qword [r15+24], 6
            0xF0, 0x49, 0x31, 0x4F, 0x20,             // lock xor qword [r15+32], rcx
        }, assembler.Assemble());
    }

    [Fact]
    public void AtomicBitSetRejectsIndexesOutsideItsQword()
    {
        var assembler = new Asm();

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            assembler.LockBtsMi(Reg.Rax, 0, 64));
    }
}
