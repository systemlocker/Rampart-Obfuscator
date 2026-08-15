using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Rampart.Codecs;

/// <summary>
/// AES-128 in CTR mode, built on the BCL's AES block primitive (ECB, no padding).
///
/// Counter block layout (16 bytes): bytes 0..7 hold the nonce and bytes 8..15 the
/// block counter, both little-endian ulongs; the counter starts at the caller's
/// initial value (default 1) and increments once per 16-byte block. Both halves are
/// little-endian so the runtime's x64 stubs can load each half with one scalar move.
///
/// Encryption and decryption are the same operation: XOR with the keystream.
/// </summary>
public static class Aes128Ctr
{
    private const int KeySizeBytes = 16;
    private const int BlockSizeBytes = 16;

    /// <summary>
    /// Encrypts or decrypts <paramref name="input"/> by XORing it with the keystream
    /// derived from <paramref name="key"/> and <paramref name="nonce"/>. The final
    /// partial block (if any) consumes only as many keystream bytes as it has input
    /// bytes. Returns an array of exactly <c>input.Length</c>.
    /// </summary>
    /// <exception cref="ArgumentException">key is not exactly 16 bytes.</exception>
    public static byte[] Crypt(ReadOnlySpan<byte> key, ulong nonce, ReadOnlySpan<byte> input, ulong initialCounter = 1)
    {
        if (key.Length != KeySizeBytes)
            throw new ArgumentException($"The AES-128 key must be exactly {KeySizeBytes} bytes (got {key.Length}).", nameof(key));

        byte[] output = new byte[input.Length];
        if (input.Length == 0)
            return output;

        using Aes aes = CreateEcbAes(key);
        using ICryptoTransform encryptor = aes.CreateEncryptor(); // one encryptor, reused for every block

        // Array-backed buffers because TransformBlock only offers the classic
        // (array, offset, count) signature; both are reused for every block.
        byte[] counterBlock = new byte[BlockSizeBytes];
        byte[] keystream = new byte[BlockSizeBytes];

        // The nonce occupies the low half for the whole message; only the counter
        // half changes between blocks.
        BinaryPrimitives.WriteUInt64LittleEndian(counterBlock.AsSpan(0, 8), nonce);

        ulong counter = initialCounter;
        int offset = 0;
        while (offset < input.Length)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(counterBlock.AsSpan(8, 8), counter);

            // ECB over a single fresh block is the raw AES permutation, which is all
            // CTR needs: keystream block i = AES(nonce || LE64(initialCounter + i)).
            encryptor.TransformBlock(counterBlock, 0, BlockSizeBytes, keystream, 0);

            int n = Math.Min(BlockSizeBytes, input.Length - offset);
            for (int i = 0; i < n; i++)
                output[offset + i] = (byte)(input[offset + i] ^ keystream[i]);

            offset += n;
            counter++;
        }

        return output;
    }

    /// <summary>
    /// Encrypts one 16-byte block in place (raw AES-ECB, no padding). Exposed for
    /// tests and for cross-checks against the hand-written assembly implementation.
    /// </summary>
    /// <exception cref="ArgumentException">key is not exactly 16 bytes, or
    /// <paramref name="block"/> is not exactly 16 bytes.</exception>
    public static void EncryptBlock(ReadOnlySpan<byte> key, Span<byte> block)
    {
        if (key.Length != KeySizeBytes)
            throw new ArgumentException($"The AES-128 key must be exactly {KeySizeBytes} bytes (got {key.Length}).", nameof(key));
        if (block.Length != BlockSizeBytes)
            throw new ArgumentException($"An AES block must be exactly {BlockSizeBytes} bytes (got {block.Length}).", nameof(block));

        using Aes aes = CreateEcbAes(key);
        using ICryptoTransform encryptor = aes.CreateEncryptor();

        // Round-trip through scratch rather than encrypting in place: TransformBlock
        // makes no promise about aliased input and output buffers.
        byte[] cipher = new byte[BlockSizeBytes];
        encryptor.TransformBlock(block.ToArray(), 0, BlockSizeBytes, cipher, 0);
        cipher.AsSpan().CopyTo(block);
    }

    /// <summary>An AES instance configured as a raw block cipher (ECB, no padding).</summary>
    private static Aes CreateEcbAes(ReadOnlySpan<byte> key)
    {
        Aes aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = key.ToArray(); // KeySize (128) is derived from the key length
        return aes;
    }
}
