using System.Reflection;
using System.Security.Cryptography;

namespace Rampart.Managed;

// Injected only for the opt-in modern runtime. The application necessarily owns
// the decoding key: authentication detects payload changes, not a hostile owner
// who can replace both the helper and its data. No dynamic code is generated.
internal static class RuntimeHardenedTemplate
{
    internal static char[] DecodeProgram(string resource, int offset, int length, byte[] key)
    {
        byte[]? encryptionKey = null;
        byte[]? authenticationKey = null;
        byte[]? plaintext = null;
        try
        {
            if (offset < 0 || length < 64 || (length - 48) % 16 != 0)
                throw new InvalidDataException("The protected payload is invalid.");
            if (key is null || key.Length != 64)
                throw new InvalidDataException("The protected payload key is invalid.");
            encryptionKey = new byte[32]; authenticationKey = new byte[32];
            Array.Copy(key, 0, encryptionKey, 0, 32);
            Array.Copy(key, 32, authenticationKey, 0, 32);
            Array.Clear(key, 0, key.Length);
            var bytes = new byte[length];
            using (var stream = typeof(RuntimeHardenedTemplate).Assembly.GetManifestResourceStream(resource)
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
                using var decryptor = algorithm.CreateDecryptor(encryptionKey, iv);
                plaintext = decryptor.TransformFinalBlock(bytes, 16, bytes.Length - 48);
            }
            if (plaintext.Length % 2 != 0) throw new InvalidDataException("The protected payload is invalid.");
            var characters = new char[plaintext.Length / 2];
            for (var i = 0; i < characters.Length; i++) characters[i] = (char)(plaintext[i * 2] | plaintext[i * 2 + 1] << 8);
            return characters;
        }
        finally
        {
            if (key is not null) Array.Clear(key, 0, key.Length);
            if (encryptionKey is not null) Array.Clear(encryptionKey, 0, encryptionKey.Length);
            if (authenticationKey is not null) Array.Clear(authenticationKey, 0, authenticationKey.Length);
            if (plaintext is not null) Array.Clear(plaintext, 0, plaintext.Length);
        }
    }

    internal static string Decode(string resource, int offset, int length, byte[] key, bool intern, ref string? cached)
    {
        var existing = cached;
        if (existing is not null)
        {
            if (key is not null) Array.Clear(key, 0, key.Length);
            return existing;
        }
        byte[]? encryptionKey = null;
        byte[]? authenticationKey = null;
        byte[]? plaintext = null;
        try
        {
            if (offset < 0 || length < 64 || (length - 48) % 16 != 0)
                throw new InvalidDataException("The protected payload is invalid.");
            if (key is null || key.Length != 64)
                throw new InvalidDataException("The protected payload key is invalid.");
            encryptionKey = new byte[32]; authenticationKey = new byte[32];
            Array.Copy(key, 0, encryptionKey, 0, 32);
            Array.Copy(key, 32, authenticationKey, 0, 32);
            Array.Clear(key, 0, key.Length);
            var bytes = new byte[length];
            using (var stream = typeof(RuntimeHardenedTemplate).Assembly.GetManifestResourceStream(resource)
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
            // Preserve ldstr interning for user strings while keeping decoded VM
            // programs out of the process-wide string intern pool.
            var decoded = new string(characters);
            Array.Clear(characters, 0, characters.Length);
            existing = intern ? string.Intern(decoded) : decoded;
            cached = existing;
            return existing;
        }
        finally
        {
            if (key is not null) Array.Clear(key, 0, key.Length);
            if (encryptionKey is not null) Array.Clear(encryptionKey, 0, encryptionKey.Length);
            if (authenticationKey is not null) Array.Clear(authenticationKey, 0, authenticationKey.Length);
            if (plaintext is not null) Array.Clear(plaintext, 0, plaintext.Length);
        }
    }
}
