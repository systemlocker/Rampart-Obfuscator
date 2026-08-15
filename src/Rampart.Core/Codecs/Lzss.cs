using System.Buffers.Binary;

namespace Rampart.Codecs;

/// <summary>
/// LZSS codec for the sections a protected binary carries compressed.
///
/// The bitstream layout is FIXED: a hand-written x64 stub decodes it at load time,
/// so nothing below may change:
///
/// <list type="bullet">
/// <item>Header: 8 bytes, little-endian int64 = decompressed length in bytes.</item>
/// <item>Body: groups of up to 8 tokens. Each group starts with one FLAG byte whose
/// bits are consumed LSB-first, so bit 0 describes the group's first token, bit 1 the
/// second, and so on; unused high bits of a final flag byte are zero.</item>
/// <item>Flag bit 0 (LITERAL): the next byte is copied verbatim to the output.</item>
/// <item>Flag bit 1 (MATCH): the next 2 bytes are a little-endian uint16 token,
/// decoded as offset = (token &amp; 0x0FFF) + 1 (1..4096 bytes behind the current
/// output position) and length = ((token >> 12) &amp; 0x000F) + 3 (3..18 bytes). The
/// match is copied forward one byte at a time, so the source window may overlap the
/// write position — that is how repeating runs are encoded.</item>
/// </list>
///
/// A match may only reference bytes already written to the output. Decoding stops as
/// soon as the announced output length is reached.
/// </summary>
public static class Lzss
{
    /// <summary>Size of the little-endian int64 decompressed-length header, in bytes.</summary>
    private const int HeaderSize = 8;

    /// <summary>Maximum distance a match may reach back; the offset field stores 1..4096.</summary>
    private const int WindowSize = 4096;

    /// <summary>Shortest encodable match; shorter runs would cost more bytes than a literal.</summary>
    private const int MinMatch = 3;

    /// <summary>Longest encodable match; the 4-bit length field stores (length - 3).</summary>
    private const int MaxMatch = 18;

    /// <summary>Match-finder table size (hash of 3 bytes to most recent position).
    /// Kept a power of two so the hash reduces to a mask.</summary>
    private const int HashTableSize = 4096;

    /// <summary>Upper bound the decoder accepts for the announced output length.</summary>
    private const long MaxDecompressedLength = 256L * 1024 * 1024;

    /// <summary>
    /// Compresses <paramref name="input"/> into the fixed LZSS bitstream described on
    /// the class. Greedy matcher: at each position the most recent same-hash candidate
    /// inside the 4096-byte window is tried, and a match is emitted only when it covers
    /// at least 3 bytes. Deterministic for identical input.
    /// </summary>
    public static byte[] Compress(ReadOnlySpan<byte> input)
    {
        // Worst case is all literals: one byte per token plus one shared flag byte per
        // 8 tokens, after the fixed header.
        byte[] output = new byte[HeaderSize + input.Length + (input.Length + 7) / 8];
        BinaryPrimitives.WriteInt64LittleEndian(output.AsSpan(0, HeaderSize), input.Length);

        // head[h] = most recent input position whose 3-byte hash is h (-1 = never seen).
        // One slot per hash is enough for a greedy matcher: a collided entry simply
        // fails the byte comparison and that token degrades to literals.
        int[] head = new int[HashTableSize];
        Array.Fill(head, -1);

        int outPos = HeaderSize;
        int flagPos = 0; // index of the flag byte shared by the current token group
        int flagBit = 8; // 0..7 within the flag byte; 8 forces a fresh flag byte
        int pos = 0;

        while (pos < input.Length)
        {
            if (flagBit == 8)
            {
                flagPos = outPos++;
                output[flagPos] = 0; // flag bits default to literal; matches set theirs
                flagBit = 0;
            }

            int matchLen = FindLongestMatch(input, pos, head, out int matchOffset);

            if (matchLen >= MinMatch)
            {
                // Pack the token: low 12 bits hold (offset - 1), high 4 bits hold
                // (length - 3). Both fields are biased to their minimum encodable
                // value so the usable ranges are 1..4096 and 3..18.
                ushort token = (ushort)(((matchOffset - 1) & 0x0FFF) | (((matchLen - MinMatch) & 0x000F) << 12));
                output[flagPos] |= (byte)(1 << flagBit);
                output[outPos++] = (byte)token;
                output[outPos++] = (byte)(token >> 8);

                // Register every position the match covers so later tokens can reach
                // into the freshly copied run; the table keeps the most recent one.
                int lastInsert = Math.Min(pos + matchLen - 1, input.Length - MinMatch);
                for (int i = pos; i <= lastInsert; i++)
                    head[Hash3(input, i)] = i;

                pos += matchLen;
            }
            else
            {
                output[outPos++] = input[pos];
                if (pos + MinMatch <= input.Length)
                    head[Hash3(input, pos)] = pos;
                pos++;
            }

            flagBit++;
        }

        Array.Resize(ref output, outPos);
        return output;
    }

    /// <summary>
    /// Decodes a stream produced by <see cref="Compress"/>; any encoder that follows
    /// the documented format decodes identically.
    /// </summary>
    /// <exception cref="InvalidOperationException">the stream is shorter than the
    /// 8-byte header, announces a negative or over-large (over 256 MiB) output length,
    /// ends before the announced output is complete, or contains a match that reaches
    /// back past the start of the output.</exception>
    public static byte[] Decompress(ReadOnlySpan<byte> input)
    {
        if (input.Length < HeaderSize)
            throw new InvalidOperationException("LZSS stream is too short to contain the 8-byte length header.");

        long outputLength = BinaryPrimitives.ReadInt64LittleEndian(input);
        if (outputLength < 0 || outputLength > MaxDecompressedLength)
            throw new InvalidOperationException($"LZSS stream announces an invalid output length of {outputLength} bytes.");

        byte[] output = new byte[outputLength];
        int outPos = 0;
        int inPos = HeaderSize;
        byte flagByte = 0;
        int flagBit = 8; // exhausted, so the loop reads a fresh flag byte before token 1

        while (outPos < output.Length)
        {
            if (flagBit == 8)
            {
                if (inPos >= input.Length)
                    throw new InvalidOperationException("LZSS stream ended prematurely: missing flag byte.");
                flagByte = input[inPos++];
                flagBit = 0;
            }

            // Flags are consumed LSB-first to match the encoder.
            if ((flagByte & (1 << flagBit)) == 0)
            {
                if (inPos >= input.Length)
                    throw new InvalidOperationException("LZSS stream ended prematurely: missing literal byte.");
                output[outPos++] = input[inPos++];
            }
            else
            {
                if (inPos + 2 > input.Length)
                    throw new InvalidOperationException("LZSS stream ended prematurely: missing match token.");

                ushort token = BinaryPrimitives.ReadUInt16LittleEndian(input.Slice(inPos, 2));
                inPos += 2;

                int offset = (token & 0x0FFF) + 1;
                int length = ((token >> 12) & 0x000F) + 3;

                if (offset > outPos)
                    throw new InvalidOperationException(
                        $"LZSS match at output position {outPos} reaches {offset} bytes back, before the start of the output.");

                // Copy forward one byte at a time: the source region can overlap the
                // write cursor (offset < length), and each copied byte immediately
                // becomes copyable source for the rest of the run. A match that would
                // overrun the announced length simply fills to the end — decoding
                // stops as soon as the announced length is reached (the encoder never
                // emits such a token).
                int src = outPos - offset;
                for (int i = 0; i < length && outPos < output.Length; i++)
                    output[outPos++] = output[src + i];
            }

            flagBit++;
        }

        return output;
    }

    /// <summary>Finds the best match for <paramref name="pos"/> reachable through the
    /// hash table, or 0 when no match of at least <see cref="MinMatch"/> bytes exists.</summary>
    private static int FindLongestMatch(ReadOnlySpan<byte> input, int pos, int[] head, out int matchOffset)
    {
        matchOffset = 0;

        int remaining = input.Length - pos;
        if (remaining < MinMatch)
            return 0;

        int candidate = head[Hash3(input, pos)];
        if (candidate < 0 || pos - candidate > WindowSize)
            return 0; // empty slot, or stale entry fallen out of the 4096-byte window

        // Extend as far as the bytes agree. The length cap keeps the token inside its
        // 4-bit field and guarantees a match never runs past the end of the input, so
        // the encoder never starts a token it cannot finish.
        int maxLen = Math.Min(MaxMatch, remaining);
        int len = 0;
        while (len < maxLen && input[candidate + len] == input[pos + len])
            len++;

        if (len < MinMatch)
            return 0;

        matchOffset = pos - candidate;
        return len;
    }

    // 3-byte position hash. Shifts of 10 and 5 fan the three bytes across the 12-bit
    // table index so each byte owns distinct bit groups; a plain XOR of the bytes
    // would collide heavily on alternating patterns like "ababab".
    private static int Hash3(ReadOnlySpan<byte> data, int pos) =>
        ((data[pos] << 10) ^ (data[pos + 1] << 5) ^ data[pos + 2]) & (HashTableSize - 1);
}
