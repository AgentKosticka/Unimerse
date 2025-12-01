using System;
using System.IO;
using System.Security.Cryptography;
using UnimerseLib.Interfaces;

namespace UnimerseLib.Cryptography
{
    /// <summary>
    /// Implements <see cref="IKeyProtector"/> using PBKDF2 (SHA-256) to derive an AES-256-GCM key from a passphrase.
    /// Salt and nonce are stored alongside the ciphertext to support cross-platform use.
    /// </summary>
    public sealed class Pbkdf2AesKeyProtector : IKeyProtector
    {
        private const int SaltSize = 16; // 128-bit salt
        private const int NonceSize = 12; // 96-bit nonce recommended for AES-GCM
        private const int KeySize = 32; // 256-bit key
        private const int TagSize = 16; // 128-bit authentication tag

        private readonly string passphrase;
        private readonly int iterations;

        /// <summary>
        /// Creates a PBKDF2-backed protector configured with the supplied passphrase and iteration count.
        /// </summary>
        public Pbkdf2AesKeyProtector(string passphrase, int iterations = 100_000)
        {
            if (string.IsNullOrEmpty(passphrase))
            {
                throw new ArgumentException("Passphrase must be provided.", nameof(passphrase));
            }

            if (iterations <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(iterations), "Iterations must be positive.");
            }

            this.passphrase = passphrase;
            this.iterations = iterations;
        }

        /// <summary>
        /// Encrypts the plaintext bytes, prepending the salt, nonce, and authentication tag required for decryption.
        /// </summary>
        public byte[] Protect(byte[] plainData)
        {
            ArgumentNullException.ThrowIfNull(plainData);

            byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
            byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
            byte[] key = DeriveKey(salt);

            try
            {
                byte[] ciphertext = new byte[plainData.Length];
                byte[] tag = new byte[TagSize];

                using AesGcm aes = new(key, TagSize);
                aes.Encrypt(nonce, plainData, ciphertext, tag);

                using MemoryStream ms = new();
                using BinaryWriter writer = new(ms);

                writer.Write(SaltSize);
                writer.Write(salt);

                writer.Write(NonceSize);
                writer.Write(nonce);

                writer.Write(TagSize);
                writer.Write(tag);

                writer.Write(ciphertext.Length);
                writer.Write(ciphertext);

                return ms.ToArray();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }

        /// <summary>
        /// Decrypts data previously produced by <see cref="Protect"/>.
        /// </summary>
        public byte[] Unprotect(byte[] protectedData)
        {
            ArgumentNullException.ThrowIfNull(protectedData);

            using MemoryStream ms = new(protectedData);
            using BinaryReader reader = new(ms);

            byte[] salt = ReadFixedSection(reader, SaltSize, "salt");
            byte[] nonce = ReadFixedSection(reader, NonceSize, "nonce");
            byte[] tag = ReadFixedSection(reader, TagSize, "authentication tag");

            int ciphertextLength = reader.ReadInt32();
            if (ciphertextLength < 0)
            {
                throw new CryptographicException("Invalid ciphertext length in protected payload.");
            }
            byte[] ciphertext = reader.ReadBytes(ciphertextLength);
            if (ciphertext.Length != ciphertextLength)
            {
                throw new CryptographicException("Ciphertext truncated in protected payload.");
            }

            byte[] key = DeriveKey(salt);
            try
            {
                byte[] plaintext = new byte[ciphertext.Length];
                using AesGcm aes = new(key, TagSize);
                aes.Decrypt(nonce, ciphertext, tag, plaintext);
                return plaintext;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }

        /// <summary>
        /// Derives an AES key from the configured passphrase and provided salt.
        /// </summary>
        private byte[] DeriveKey(ReadOnlySpan<byte> salt)
        {
            byte[] saltBytes = salt.ToArray();
            using var pbkdf2 = new Rfc2898DeriveBytes(passphrase, saltBytes, iterations, HashAlgorithmName.SHA256);
            return pbkdf2.GetBytes(KeySize);
        }

        /// <summary>
        /// Reads a fixed-length component from the serialized payload and validates its size.
        /// </summary>
        private static byte[] ReadFixedSection(BinaryReader reader, int expectedLength, string componentName)
        {
            int length = reader.ReadInt32();
            if (length != expectedLength)
            {
                throw new CryptographicException($"Invalid {componentName} size in protected payload.");
            }

            byte[] data = reader.ReadBytes(length);
            if (data.Length != length)
            {
                throw new CryptographicException($"{char.ToUpperInvariant(componentName[0]) + componentName[1..]} truncated in protected payload.");
            }

            return data;
        }
    }
}
