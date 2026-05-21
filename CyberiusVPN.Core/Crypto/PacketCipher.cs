using System.Security.Cryptography;

namespace CyberiusVPN.Core.Crypto;

/// <summary>
/// AES-256-GCM AEAD шифр для защиты пакетов туннеля.
/// Обеспечивает конфиденциальность и аутентификацию одновременно.
/// Nonce строится как baseIV XOR counter (аналогично TLS 1.3)
/// для гарантии уникальности каждого пакета.
/// </summary>
public sealed class PacketCipher : IDisposable
{
    private readonly AesGcm _cipher;
    private readonly byte[] _baseIv;
    private ulong           _counter;

    /// <summary>
    /// Создаёт шифр с указанным ключом и базовым IV.
    /// </summary>
    /// <param name="key">Ключ AES-256 (32 байта).</param>
    /// <param name="iv">Базовый IV (12 байт), XOR-ится с счётчиком пакетов.</param>
    public PacketCipher(byte[] key, byte[] iv)
    {
        _cipher  = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
        _baseIv  = iv;
        _counter = 0;
    }

    /// <summary>
    /// Шифрует IP-пакет с аутентификацией.
    /// </summary>
    /// <param name="plaintext">Открытый IP-пакет.</param>
    /// <param name="aad">Дополнительные аутентифицированные данные (не шифруются).</param>
    /// <returns>Зашифрованный пакет с 16-байтным GCM тегом в конце.</returns>
    public byte[] Encrypt(byte[] plaintext, byte[] aad)
    {
        var nonce      = BuildNonce(_counter++);
        var ciphertext = new byte[plaintext.Length];
        var tag        = new byte[16];

        _cipher.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        var result = new byte[ciphertext.Length + 16];
        ciphertext.CopyTo(result, 0);
        tag.CopyTo(result, ciphertext.Length);
        return result;
    }

    /// <summary>
    /// Расшифровывает и проверяет аутентификационный тег.
    /// </summary>
    /// <param name="ciphertextWithTag">Зашифрованный пакет с тегом.</param>
    /// <param name="aad">Дополнительные аутентифицированные данные.</param>
    /// <param name="nonce">Счётчик пакета от отправителя.</param>
    /// <returns>Расшифрованный IP-пакет.</returns>
    /// <exception cref="CryptographicException">Если тег не совпал (пакет повреждён или подменён).</exception>
    public byte[] Decrypt(byte[] ciphertextWithTag, byte[] aad, ulong nonce)
    {
        var nonceBytes = BuildNonce(nonce);
        var ciphertext = ciphertextWithTag[..^16];
        var tag        = ciphertextWithTag[^16..];
        var plaintext  = new byte[ciphertext.Length];

        _cipher.Decrypt(nonceBytes, ciphertext, tag, plaintext, aad);
        return plaintext;
    }

    /// <summary>
    /// Строит уникальный nonce: baseIV XOR counter (как в TLS 1.3 RFC 8446).
    /// </summary>
    private byte[] BuildNonce(ulong counter)
    {
        var nonce        = (byte[])_baseIv.Clone();
        var counterBytes = BitConverter.GetBytes(counter);
        if (!BitConverter.IsLittleEndian)
            Array.Reverse(counterBytes);

        for (int i = 0; i < 8; i++)
            nonce[4 + i] ^= counterBytes[i];

        return nonce;
    }

    /// <inheritdoc/>
    public void Dispose() => _cipher.Dispose();
}