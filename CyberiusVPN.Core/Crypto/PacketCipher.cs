using System.Security.Cryptography;

namespace CyberiusVPN.Core.Crypto;

/// <summary>
/// AES-256-GCM AEAD — шифрование пакетов.
/// Используем AES-GCM вместо ChaCha20-Poly1305 для кросс-платформенности:
/// ChaCha20 требует аппаратной поддержки на Windows (.NET не всегда находит провайдера).
/// AES-GCM работает везде — Windows, Linux, macOS.
/// </summary>
public sealed class PacketCipher : IDisposable
{
    private readonly AesGcm _cipher;
    private readonly byte[] _baseIv;
    private ulong           _counter;

    public PacketCipher(byte[] key, byte[] iv)
    {
        // AesGcm в .NET 8 принимает размер тега явно
        _cipher  = new AesGcm(key, AesGcm.TagByteSizes.MaxSize); // 16 байт тег
        _baseIv  = iv;
        _counter = 0;
    }

    /// <summary>
    /// Nonce = baseIv XOR counter (как в TLS 1.3)
    /// Гарантирует уникальность nonce для каждого пакета
    /// </summary>
    private byte[] BuildNonce(ulong counter)
    {
        var nonce        = (byte[])_baseIv.Clone();
        var counterBytes = BitConverter.GetBytes(counter);
        if (!BitConverter.IsLittleEndian)
            Array.Reverse(counterBytes);

        // XOR последних 8 байт IV с counter
        for (int i = 0; i < 8; i++)
            nonce[4 + i] ^= counterBytes[i];

        return nonce;
    }

    /// <summary>
    /// Шифруем IP пакет → возвращаем [ciphertext | 16-byte tag]
    /// </summary>
    public byte[] Encrypt(byte[] plaintext, byte[] aad)
    {
        var nonce      = BuildNonce(_counter++);
        var ciphertext = new byte[plaintext.Length];
        var tag        = new byte[16];

        _cipher.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        // [ciphertext | tag]
        var result = new byte[ciphertext.Length + 16];
        ciphertext.CopyTo(result, 0);
        tag.CopyTo(result, ciphertext.Length);
        return result;
    }

    /// <summary>
    /// Расшифровываем, проверяем GCM тег целостности
    /// </summary>
    public byte[] Decrypt(byte[] ciphertextWithTag, byte[] aad, ulong nonce)
    {
        var nonceBytes = BuildNonce(nonce);
        var ciphertext = ciphertextWithTag[..^16];
        var tag        = ciphertextWithTag[^16..];
        var plaintext  = new byte[ciphertext.Length];

        _cipher.Decrypt(nonceBytes, ciphertext, tag, plaintext, aad);
        return plaintext;
    }

    public void Dispose() => _cipher.Dispose();
}