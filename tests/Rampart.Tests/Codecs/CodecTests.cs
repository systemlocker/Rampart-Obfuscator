using System.Buffers.Binary;
using System.Text;
using Rampart.Codecs;
using Xunit;

namespace Rampart.Tests.Codecs;

/// <summary>Known-answer, layout-conformance, and roundtrip tests for the codecs.</summary>
public class CodecTests
{
    private static byte[] Hex(string hex) => Convert.FromHexString(hex);

    // ---------------------------------------------------------------- AES-128

    [Fact]
    public void EncryptBlock_MatchesFips197AppendixC1()
    {
        byte[] key = Hex("000102030405060708090a0b0c0d0e0f");
        byte[] block = Hex("00112233445566778899aabbccddeeff");

        Aes128Ctr.EncryptBlock(key, block);

        Assert.Equal(Hex("69c4e0d86a7b0430d8cdb78070b4c55a"), block);
    }

    [Fact]
    public void Crypt_MatchesNistSp800_38A_CtrAes128()
    {
        // NIST SP 800-38A F.5.1 (CTR-AES128.Encrypt) uses key 2b7e1516..4f3c with the
        // initial counter block f0f1f2f3f4f5f6f7 f8f9fafbfcfdfeff, and encrypting
        // 6bc1bee2..172a yields 874d6191b620e3261bef6864990db6ce for the first block.
        //
        // Crypt lays the counter block out as nonce | block counter, both LITTLE-endian,
        // so NIST's block is reproduced by feeding the byte-reversed halves:
        //   bytes 0..7  = LE64(0xf7f6f5f4f3f2f1f0) = f0 f1 f2 f3 f4 f5 f6 f7
        //   bytes 8..15 = LE64(0xfffefdfcfbfaf9f8) = f8 f9 fa fb fc fd fe ff
        // Note that the spec-suggested nonce=0xf0f1f2f3f4f5f6f7 with counter=1 would
        // lay out f7f6f5f4f3f2f1f0 0100000000000000 — a different block that cannot
        // produce the NIST ciphertext; the layout-pinning test below covers that
        // arrangement explicitly.
        byte[] key = Hex("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] plaintext = Hex("6bc1bee22e409f96e93d7e117393172a");

        byte[] ciphertext = Aes128Ctr.Crypt(key, 0xF7F6F5F4F3F2F1F0UL, plaintext, 0xFFFEFDFCFBFAF9F8UL);

        Assert.Equal(Hex("874d6191b620e3261bef6864990db6ce"), ciphertext);
    }

    [Fact]
    public void Crypt_CounterBlockLayoutIsNonceLeThenCounterLe()
    {
        // Pins the exact convention: nonce=0xf0f1f2f3f4f5f6f7 and initialCounter=1
        // must encrypt block 0 with the keystream AES(f7f6f5f4f3f2f1f0 0100000000000000).
        // The keystream is derived with EncryptBlock — itself proven against FIPS-197
        // above — so this checks Crypt's layout and XOR, not AES itself.
        byte[] key = Hex("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] plaintext = Hex("6bc1bee22e409f96e93d7e117393172a");

        Span<byte> counterBlock = stackalloc byte[16];
        BinaryPrimitives.WriteUInt64LittleEndian(counterBlock[..8], 0xF0F1F2F3F4F5F6F7UL);
        BinaryPrimitives.WriteUInt64LittleEndian(counterBlock[8..], 1UL);

        byte[] keystream = counterBlock.ToArray();
        Aes128Ctr.EncryptBlock(key, keystream);

        byte[] expected = new byte[plaintext.Length];
        for (int i = 0; i < expected.Length; i++)
            expected[i] = (byte)(plaintext[i] ^ keystream[i]);

        Assert.Equal(expected, Aes128Ctr.Crypt(key, 0xF0F1F2F3F4F5F6F7UL, plaintext));
    }

    public static TheoryData<int> CtrLengths => new() { 0, 1, 15, 16, 17, 1000 };

    [Theory]
    [MemberData(nameof(CtrLengths))]
    public void Crypt_RoundTripsAcrossBlockBoundaries(int length)
    {
        byte[] key = Hex("000102030405060708090a0b0c0d0e0f");
        const ulong nonce = 0xDEADBEEFCAFEBABEUL;

        Random rng = new(20260901); // seeded: failures must reproduce
        byte[] data = new byte[length];
        rng.NextBytes(data);

        byte[] encrypted = Aes128Ctr.Crypt(key, nonce, data);
        byte[] decrypted = Aes128Ctr.Crypt(key, nonce, encrypted);

        Assert.Equal(data, decrypted);
        Assert.Equal(length, encrypted.Length);
    }

    [Fact]
    public void Crypt_DifferentNoncesYieldDifferentCiphertexts()
    {
        byte[] key = Hex("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] plaintext = Hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");

        byte[] first = Aes128Ctr.Crypt(key, 0x1111111111111111UL, plaintext);
        byte[] second = Aes128Ctr.Crypt(key, 0x2222222222222222UL, plaintext);

        Assert.NotEqual(first, second);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(15)]
    [InlineData(17)]
    public void Crypt_RejectsKeysThatAreNot128Bits(int keyLength)
    {
        Assert.Throws<ArgumentException>(() => Aes128Ctr.Crypt(new byte[keyLength], 0, []));
    }

    // ------------------------------------------------------------------ LZSS

    [Fact]
    public void Lzss_RoundTripsRandomDataDeterministically()
    {
        Random rng = new(0xC0FFEE);
        byte[] data = new byte[50_000];
        rng.NextBytes(data);

        byte[] compressed = Lzss.Compress(data);

        Assert.Equal(data, Lzss.Decompress(compressed));
        Assert.Equal(compressed, Lzss.Compress(data)); // identical input => identical stream
    }

    [Fact]
    public void Lzss_RoundTripsHighlyCompressibleData()
    {
        byte[] run = new byte[20_000];
        Array.Fill(run, (byte)'Z');

        byte[] runCompressed = Lzss.Compress(run);
        Assert.Equal(run, Lzss.Decompress(runCompressed));
        Assert.True(runCompressed.Length < run.Length / 2,
            $"expected strong compression, got {runCompressed.Length} bytes");

        byte[] phrase = Encoding.ASCII.GetBytes("The quick brown fox jumps over the lazy dog. ");
        byte[] repeated = Enumerable.Range(0, 500).SelectMany(_ => phrase).ToArray();

        Assert.Equal(repeated, Lzss.Decompress(Lzss.Compress(repeated)));
    }

    [Fact]
    public void Lzss_RoundTripsPatternsThatMaxOutMatches()
    {
        // "abcabcabc..." — a chain of maximal length-18 matches at distance 3 whose
        // copies overlap their own source.
        byte[] alternating = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("abc", 5_000)));
        Assert.Equal(alternating, Lzss.Decompress(Lzss.Compress(alternating)));

        // A 4096-byte period forces matches to reach the very edge of the window.
        Random rng = new(99);
        byte[] period = new byte[4096];
        rng.NextBytes(period);
        byte[] spanning = new byte[checked(period.Length * 8)];
        for (int i = 0; i < 8; i++)
            period.CopyTo(spanning, i * period.Length);

        Assert.Equal(spanning, Lzss.Decompress(Lzss.Compress(spanning)));
    }

    [Fact]
    public void Lzss_RoundTripsEdgeInputs()
    {
        // Empty input: just the 8-byte header announcing zero bytes, no tokens.
        byte[] empty = [];
        byte[] emptyCompressed = Lzss.Compress(empty);
        Assert.Equal(8, emptyCompressed.Length);
        Assert.Equal(empty, Lzss.Decompress(emptyCompressed));

        // Exactly 3 repeated bytes: no match of the minimum length 3 fits after the
        // first literal, so the encoder must emit plain literals (flag byte 0).
        byte[] three = [(byte)'x', (byte)'x', (byte)'x'];
        byte[] threeCompressed = Lzss.Compress(three);
        Assert.Equal(three, Lzss.Decompress(threeCompressed));
        Assert.Equal(0x00, threeCompressed[8]);
    }

    [Fact]
    public void Lzss_CompressEmitsTheDocumentedBitstream()
    {
        // Hand-decode Compress("aaaaaaaaaa") strictly per the format, byte by byte,
        // proving the encoder emits the specified bitstream rather than a private one.
        byte[] compressed = Lzss.Compress(Encoding.ASCII.GetBytes("aaaaaaaaaa"));

        // 8 header + 1 flag + 1 literal + 2-byte match token.
        Assert.Equal(12, compressed.Length);

        long header = BinaryPrimitives.ReadInt64LittleEndian(compressed);
        Assert.Equal(10L, header);

        // Flag byte 0x02: bit 0 (LSB-first) = 0 -> literal; bit 1 = 1 -> match;
        // bits 2..7 unused and zero.
        Assert.Equal(0x02, compressed[8]);

        // Token 1: literal 'a'.
        Assert.Equal((byte)'a', compressed[9]);

        // Token 2: match, little-endian uint16 at bytes 10..11.
        ushort token = BinaryPrimitives.ReadUInt16LittleEndian(compressed.AsSpan(10, 2));
        int offset = (token & 0x0FFF) + 1;
        int length = ((token >> 12) & 0x000F) + 3;
        Assert.Equal(1, offset); // copy from 1 byte back...
        Assert.Equal(9, length); // ...for 9 bytes, completing the 10 'a's

        // Replay the decode by hand: one literal seed, then the overlapping run.
        List<byte> decoded = [compressed[9]];
        int src = decoded.Count - offset;
        for (int i = 0; i < length; i++)
            decoded.Add(decoded[src + i]); // byte-by-byte forward: the run feeds itself

        Assert.Equal(Encoding.ASCII.GetBytes("aaaaaaaaaa"), decoded);
    }

    [Fact]
    public void Lzss_DecompressRejectsTruncatedStreams()
    {
        Random rng = new(7);
        byte[] data = new byte[1000];
        rng.NextBytes(data);
        byte[] compressed = Lzss.Compress(data);

        // The stream is exactly consumed, so trimming any bytes starves the decoder.
        Assert.Throws<InvalidOperationException>(
            () => Lzss.Decompress(compressed[..(compressed.Length - 2)]));

        // Shorter than the header itself.
        Assert.Throws<InvalidOperationException>(() => Lzss.Decompress(new byte[4]));

        // Flag byte promises a match, but the 2 token bytes are missing.
        Assert.Throws<InvalidOperationException>(
            () => Lzss.Decompress(Hex("0400000000000000" + "01")));
    }

    [Fact]
    public void Lzss_DecompressRejectsMatchesBeforeOutputStart()
    {
        // header=8, flags=0x01 (first token is a match), token bytes FF 00 -> 0x00FF:
        // offset = (0x00FF & 0x0FFF) + 1 = 256, but 0 bytes have been written.
        Assert.Throws<InvalidOperationException>(
            () => Lzss.Decompress(Hex("0800000000000000" + "01" + "FF00")));
    }

    [Fact]
    public void Lzss_DecompressRejectsImplausibleHeaders()
    {
        // A plain array (not stackalloc) so the span can be captured in the lambdas.
        byte[] header = new byte[8];

        BinaryPrimitives.WriteInt64LittleEndian(header, -1);
        Assert.Throws<InvalidOperationException>(() => Lzss.Decompress(header));

        BinaryPrimitives.WriteInt64LittleEndian(header, 256L * 1024 * 1024 + 1); // over the 256 MiB cap
        Assert.Throws<InvalidOperationException>(() => Lzss.Decompress(header));
    }
}
