using Spectre.Console;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using UnimerseLib.Interfaces;

namespace UnimerseLib.Cryptography
{
    /// <summary>
    /// Coordinates asymmetric key exchange and manages the AES-GCM session shared between peers.
    /// </summary>
    public class Cipher : IDisposable
    {
        private static RSA rsaOwn = RSA.Create();
        private readonly RSA rsaPeer;
        private readonly ECDiffieHellman ecdh;
        private AesGcm? sessionAes;
        private readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();

        public byte[]? aesKey;

        private readonly IKeyProtector keyProtector = null!;
        private readonly string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Unimerse", "rsa-key.dat");
        public bool storeRSAKey = false;

        private static byte[]? _rsaPublicKey;
        private byte[]? _ecdhPublicKey;
        private byte[]? _ecdhSignature;

        public static byte[] RSAPublicKey
        {
            get => _rsaPublicKey ??= rsaOwn!.ExportRSAPublicKey();
        }
        public byte[] ECDHPublicKey
        {
            get => _ecdhPublicKey ??= ecdh.PublicKey.ExportSubjectPublicKeyInfo();
        }
        public byte[] ECDHSignature
        {
            get => _ecdhSignature ??= SignData(ECDHPublicKey);
        }

        /// <summary>
        /// Signs the supplied data using the local RSA private key.
        /// </summary>
        public static byte[] SignData(byte[] data) => rsaOwn!.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        /// <summary>
        /// Verifies that the signature was produced by the remote peer's RSA private key.
        /// </summary>
        public bool VerifySignedData(byte[] data, byte[] signature) => rsaPeer.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        /// <summary>
        /// Initializes the cipher with platform-appropriate key protection and prepares asymmetric primitives.
        /// </summary>
        public Cipher(IKeyProtector? keyProtector = null, bool storeRSAKey = false)
        {
            this.storeRSAKey = storeRSAKey;

            this.keyProtector = ResolveKeyProtector(keyProtector);

            if (rsaOwn == null)
            {
                LoadOrCreateRSAKey();
            }

            rsaPeer = RSA.Create();
            ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        }

        /// <summary>
        /// Resolves the key protector to use for persisted RSA material, falling back to platform defaults.
        /// </summary>
        private static IKeyProtector ResolveKeyProtector(IKeyProtector? keyProtector)
        {
            if (keyProtector != null)
            {
                return keyProtector;
            }

            if (OperatingSystem.IsWindows())
            {
                return new WindowsKeyProtector();
            }

            string? passphrase = Environment.GetEnvironmentVariable("UNIMERSE_MASTER_PASSWORD");
            if (string.IsNullOrEmpty(passphrase))
            {
                throw new PlatformNotSupportedException(
                    "No IKeyProtector provided. Set the UNIMERSE_MASTER_PASSWORD environment variable or supply a custom IKeyProtector implementation.");
            }

            return new Pbkdf2AesKeyProtector(passphrase);
        }
        /// <summary>
        /// Loads an existing RSA key from disk when available or provisions a new one.
        /// </summary>
        private void LoadOrCreateRSAKey()
        {
            if (storeRSAKey && File.Exists(path))
            {
                try
                {
                    byte[] pkcs1Key = LoadPrivateKey(path);
                    rsaOwn = RSA.Create();
                    rsaOwn.ImportRSAPrivateKey(pkcs1Key, out _);
                    return;
                }
                catch
                {
                    // failed to load key: create new one
                }
            }

            rsaOwn = RSA.Create(2048);
            byte[] newPkcs1Key = rsaOwn.ExportRSAPrivateKey();

            if (storeRSAKey)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                SavePrivateKey(newPkcs1Key, path);
            }
        }
        /// <summary>
        /// Encrypts and writes the private key material using the configured protector.
        /// </summary>
        private void SavePrivateKey(byte[] pkcs1Key, string path)
        {
            byte[] protectedBytes = keyProtector.Protect(pkcs1Key);
            File.WriteAllBytes(path, protectedBytes);
        }

        /// <summary>
        /// Reads and decrypts persisted private key material from disk.
        /// </summary>
        private byte[] LoadPrivateKey(string path)
        {
            byte[] protectedBytes = File.ReadAllBytes(path);
            return keyProtector.Unprotect(protectedBytes);
        }

        /// <summary>
        /// Imports the remote peer's public material and derives a shared AES session key.
        /// </summary>
        public void SetPeerPublicKeys(byte[] rsaPublicKey, byte[] ecdhPublicKey, byte[] ecdhSignature)
        {
            rsaPeer.ImportRSAPublicKey(rsaPublicKey, out _);

            if (!VerifySignedData(ecdhPublicKey, ecdhSignature))
                throw new CryptographicException("ECDH public key signature verification failed.");

            using var peerEcdh = ECDiffieHellman.Create();
            peerEcdh.ImportSubjectPublicKeyInfo(ecdhPublicKey, out _);

            aesKey = ecdh.DeriveKeyFromHash(peerEcdh.PublicKey, HashAlgorithmName.SHA256);
            sessionAes = new AesGcm(aesKey, 16);
        }

        /// <summary>
        /// Encrypts the provided plaintext and packages nonce, tag, and ciphertext into a single envelope.
        /// </summary>
        public byte[] Encrypt(byte[] plaintext)
        {
            if (sessionAes == null) throw new InvalidOperationException("Peer public keys must be set before encryption.");

            byte[] ciphertext = Encrypt(plaintext, out byte[] nonce, out byte[] tag);

            using MemoryStream ms = new();
            using BinaryWriter writer = new(ms);

            writer.Write(ciphertext.Length + nonce.Length + tag.Length + 4 + 4 + 4); // total length

            writer.Write(nonce.Length);
            writer.Write(nonce);

            writer.Write(tag.Length);
            writer.Write(tag);

            writer.Write(ciphertext.Length);
            writer.Write(ciphertext);

            return ms.ToArray();
        }

        /// <summary>
        /// Unpacks the AES-GCM envelope and returns the decrypted plaintext.
        /// </summary>
        public byte[] Decrypt(byte[] encoded)
        {
            if (sessionAes == null) throw new InvalidOperationException("Peer public keys must be set before decryption.");

            using MemoryStream ms = new(encoded);
            using BinaryReader reader = new(ms);

            int totalLength = reader.ReadInt32();

            if (totalLength < 0)
            {
                throw new CryptographicException("Encrypted payload length header is invalid.");
            }

            int nonceLength = reader.ReadInt32();
            byte[] nonce = reader.ReadBytes(nonceLength);
            if (nonce.Length != nonceLength)
            {
                throw new CryptographicException("Encrypted payload nonce truncated.");
            }

            int tagLength = reader.ReadInt32();
            byte[] tag = reader.ReadBytes(tagLength);
            if (tag.Length != tagLength)
            {
                throw new CryptographicException("Encrypted payload authentication tag truncated.");
            }

            int ciphertextLength = reader.ReadInt32();
            byte[] ciphertext = reader.ReadBytes(ciphertextLength);
            if (ciphertext.Length != ciphertextLength)
            {
                throw new CryptographicException("Encrypted payload ciphertext truncated.");
            }

            // Validate that the payload matches the advertised length to guard against tampering.
            int expectedTotal = nonceLength + tagLength + ciphertextLength + (sizeof(int) * 3);
            if (totalLength != expectedTotal)
            {
                throw new CryptographicException("Encrypted payload length mismatch.");
            }

            return Decrypt(ciphertext, nonce, tag);
        }

        /// <summary>
        /// Performs the raw AES-GCM encryption using a fresh nonce and authentication tag.
        /// </summary>
        private byte[] Encrypt(byte[] plaintext, out byte[] nonce, out byte[] tag)
        {
            nonce = new byte[12];
            tag = new byte[16];
            rng.GetBytes(nonce);

            byte[] ciphertext = new byte[plaintext.Length];
            sessionAes!.Encrypt(nonce, plaintext, ciphertext, tag);

            return ciphertext;
        }

        /// <summary>
        /// Performs the raw AES-GCM decryption for a ciphertext, using the provided nonce and tag.
        /// </summary>
        private byte[] Decrypt(byte[] ciphertext, byte[] nonce, byte[] tag)
        {
            byte[] plaintext = new byte[ciphertext.Length];
            sessionAes!.Decrypt(nonce, ciphertext, tag, plaintext);
            return plaintext;
        }

        /// <summary>
        /// Releases cryptographic resources and suppresses finalization.
        /// </summary>
        public void Dispose()
        {
            ecdh.Dispose();
            rsaPeer.Dispose();
            sessionAes?.Dispose();
            rng.Dispose();

            GC.SuppressFinalize(this);
        }
    }
}
