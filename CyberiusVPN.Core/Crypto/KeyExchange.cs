using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CyberiusVPN.Core.Crypto;

/// <summary>
/// X25519 Diffie-Hellman — обмен ключами.
/// Используется для выработки общего секрета между клиентом и сервером
/// без передачи приватных ключей по сети.
/// </summary>
public static class KeyExchange
{
    /// <summary>Генерирует новую пару ключей X25519.</summary>
    /// <returns>Кортеж (privateKey, publicKey), каждый по 32 байта.</returns>
    public static (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
    {
        var generator = new X25519KeyPairGenerator();
        generator.Init(new X25519KeyGenerationParameters(new SecureRandom()));
        var keyPair = generator.GenerateKeyPair();

        var privateKey = new byte[32];
        var publicKey  = new byte[32];

        ((X25519PrivateKeyParameters)keyPair.Private).Encode(privateKey, 0);
        ((X25519PublicKeyParameters)keyPair.Public).Encode(publicKey, 0);

        return (privateKey, publicKey);
    }

    /// <summary>
    /// Вычисляет общий секрет ECDH.
    /// Свойство: ECDH(privA, pubB) == ECDH(privB, pubA)
    /// </summary>
    /// <param name="privateKey">Приватный ключ локальной стороны (32 байта).</param>
    /// <param name="remotePublicKey">Публичный ключ удалённой стороны (32 байта).</param>
    /// <returns>Общий секрет 32 байта.</returns>
    public static byte[] ComputeSharedSecret(byte[] privateKey, byte[] remotePublicKey)
    {
        var agreement  = new X25519Agreement();
        var privParams = new X25519PrivateKeyParameters(privateKey, 0);
        agreement.Init(privParams);

        var pubParams = new X25519PublicKeyParameters(remotePublicKey, 0);
        var secret    = new byte[agreement.AgreementSize];
        agreement.CalculateAgreement(pubParams, secret, 0);
        return secret;
    }

    /// <summary>Кодирует ключ в Base64 строку для хранения в конфиге.</summary>
    public static string ToBase64(byte[] key) => Convert.ToBase64String(key);

    /// <summary>Декодирует ключ из Base64 строки.</summary>
    public static byte[] FromBase64(string key) => Convert.FromBase64String(key);
}