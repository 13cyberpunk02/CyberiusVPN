using System.Security.Cryptography;
using CyberiusVPN.Core.Models;

namespace CyberiusVPN.Core.Crypto;

/// <summary>
/// HKDF (HMAC-based Key Derivation Function) — вывод сессионных ключей.
/// Из общего ECDH секрета и случайной соли выводятся два независимых
/// ключа шифрования и два IV для клиента и сервера.
/// </summary>
public static class KeyDerivation
{
    /// <summary>
    /// Выводит сессионные ключи из общего секрета и соли.
    /// Клиент использует ключи A для отправки, B для приёма.
    /// Сервер использует ключи B для отправки, A для приёма.
    /// </summary>
    /// <param name="sharedSecret">Общий ECDH секрет (32 байта).</param>
    /// <param name="salt">Случайная соль от сервера (32 байта).</param>
    /// <returns>Сессионные ключи для шифрования туннеля.</returns>
    public static SessionKeys DeriveSessionKeys(byte[] sharedSecret, byte[] salt)
    {
        var keyA = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret,
            outputLength: 32, salt: salt, info: "vpn-key-a"u8.ToArray());

        var keyB = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret,
            outputLength: 32, salt: salt, info: "vpn-key-b"u8.ToArray());

        var ivA = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret,
            outputLength: 12, salt: salt, info: "vpn-iv-a"u8.ToArray());

        var ivB = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret,
            outputLength: 12, salt: salt, info: "vpn-iv-b"u8.ToArray());

        // Клиент: Send=A, Recv=B
        return new SessionKeys(SendKey: keyA, RecvKey: keyB, SendIv: ivA, RecvIv: ivB);
    }
}