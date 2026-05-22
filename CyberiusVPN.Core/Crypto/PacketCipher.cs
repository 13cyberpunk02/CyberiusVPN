using System.Buffers;
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
    private readonly byte[] _nonceBuf = new byte[12]; // переиспользуем буфер nonce
    private ulong _counter;

    /// <summary>
    /// Создаёт шифр с указанным ключом и базовым IV.
    /// </summary>
    /// <param name="key">Ключ AES-256 (32 байта).</param>
    /// <param name="iv">Базовый IV (12 байт), XOR-ится с счётчиком пакетов.</param>
    public PacketCipher(byte[] key, byte[] iv)
    {
        _cipher = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
        _baseIv = iv;
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
        BuildNonce(_counter++);

        var ciphertext = ArrayPool<byte>.Shared.Rent(plaintext.Length);
        var tag = ArrayPool<byte>.Shared.Rent(16);

        try
        {
            _cipher.Encrypt(_nonceBuf, plaintext, ciphertext.AsSpan(0, plaintext.Length),
                tag.AsSpan(0, 16), aad);

            var result = new byte[plaintext.Length + 16];
            ciphertext.AsSpan(0, plaintext.Length).CopyTo(result);
            tag.AsSpan(0, 16).CopyTo(result.AsSpan(plaintext.Length));
            return result;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(ciphertext);
            ArrayPool<byte>.Shared.Return(tag);
        }
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
        BuildNonce(nonce);

        var ciphertextLen = ciphertextWithTag.Length - 16;
        var plaintext = new byte[ciphertextLen];

        // Span без копирования — указываем на существующий массив
        _cipher.Decrypt(_nonceBuf,
            ciphertextWithTag.AsSpan(0, ciphertextLen),
            ciphertextWithTag.AsSpan(ciphertextLen, 16),
            plaintext, aad);
        return plaintext;
    }

    /// <summary>
    /// Строит nonce прямо в _nonceBuf без аллокации.
    /// baseIV XOR counter — как в TLS 1.3.
    /// </summary>
    private void BuildNonce(ulong counter)
    {
        // Копируем baseIv в буфер
        _baseIv.AsSpan().CopyTo(_nonceBuf);

        // XOR с counter
        var counterBytes = BitConverter.GetBytes(counter);
        if (!BitConverter.IsLittleEndian)
            Array.Reverse(counterBytes);

        for (var i = 0; i < 8; i++)
            _nonceBuf[4 + i] ^= counterBytes[i];
    }

    /// <inheritdoc/>
    public void Dispose() => _cipher.Dispose();
}