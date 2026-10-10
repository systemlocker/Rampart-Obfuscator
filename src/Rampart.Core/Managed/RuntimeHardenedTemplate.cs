using System.Reflection;
using System.Security.Cryptography;

namespace Rampart.Managed;

// Injected only for the opt-in modern runtime. The application necessarily owns
// the decoding key: authentication detects payload changes, not a hostile owner
// who can replace both the helper and its data. No dynamic code is generated.
internal static class RuntimeHardenedTemplate
{
    internal static string Decode(string resource, int offset, int length, string key, ref string? cached)
    {
        var existing = cached;
        if (existing is not null) return existing;
        if (offset < 0 || length < 64 || (length - 48) % 16 != 0)
            throw new InvalidDataException("The protected payload is invalid.");
        var material = Convert.FromBase64String(key);
        if (material.Length != 64) throw new InvalidDataException("The protected payload key is invalid.");
        var encryptionKey = new byte[32]; var authenticationKey = new byte[32];
        Array.Copy(material, 0, encryptionKey, 0, 32);
        Array.Copy(material, 32, authenticationKey, 0, 32);
        Array.Clear(material, 0, material.Length);
        byte[]? plaintext = null;
        try
        {
            var bytes = new byte[length];
            using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resource)
                ?? throw new InvalidDataException("The protected payload is missing."))
            {
                if (offset > stream.Length - length) throw new InvalidDataException("The protected payload is truncated.");
                stream.Position = offset;
                var read = 0;
                while (read < bytes.Length)
                {
                    var count = stream.Read(bytes, read, bytes.Length - read);
                    if (count == 0) throw new InvalidDataException("The protected payload is truncated.");
                    read += count;
                }
            }
            // Authenticate the IV and ciphertext before decrypting. Compare every
            // tag byte; malformed padding must not become a separate first check.
            using (var mac = new HMACSHA256(authenticationKey))
            {
                var tag = mac.ComputeHash(bytes, 0, bytes.Length - 32);
                var difference = 0;
                for (var i = 0; i < 32; i++) difference |= tag[i] ^ bytes[bytes.Length - 32 + i];
                if (difference != 0) throw new InvalidDataException("The protected payload failed its integrity check.");
            }
            var iv = new byte[16]; Array.Copy(bytes, iv, 16);
            using (var algorithm = Aes.Create())
            {
                algorithm.Mode = CipherMode.CBC; algorithm.Padding = PaddingMode.PKCS7;
                using (var decryptor = algorithm.CreateDecryptor(encryptionKey, iv))
                    plaintext = decryptor.TransformFinalBlock(bytes, 16, bytes.Length - 48);
            }
            if (plaintext.Length % 2 != 0) throw new InvalidDataException("The protected payload is invalid.");
            var characters = new char[plaintext.Length / 2];
            for (var i = 0; i < characters.Length; i++) characters[i] = (char)(plaintext[i * 2] | plaintext[i * 2 + 1] << 8);
            // Preserve ldstr's interning, including empty strings and unpaired
            // surrogates. Both strings and decoded VM programs remain recoverable
            // in the process while in use; caching avoids decrypting on each call.
            existing = string.Intern(new string(characters));
            Array.Clear(characters, 0, characters.Length);
            cached = existing;
            return existing;
        }
        finally
        {
            Array.Clear(encryptionKey, 0, encryptionKey.Length);
            Array.Clear(authenticationKey, 0, authenticationKey.Length);
            if (plaintext is not null) Array.Clear(plaintext, 0, plaintext.Length);
        }
    }
}
