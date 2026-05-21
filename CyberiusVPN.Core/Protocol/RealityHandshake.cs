using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace CyberiusVPN.Core.Protocol;

/// <summary>
/// Reality-подобный механизм аутентификации.
///
/// Идея: клиент строит TLS ClientHello с fingerprint Chrome 120
/// и прячет auth-токен в поле legacy_session_id (32 байта).
/// Сервер читает session_id до TLS handshake и решает:
/// — наш клиент → VPN сессия
/// — чужой → форвард к реальному SNI домену (маскировка)
///
/// Auth-токен = HKDF(ECDH(clientPriv, serverPub), timestamp, "reality-auth-v1")
/// Окно проверки ±30 секунд для учёта рассинхрона часов.
/// </summary>
public sealed class RealityHandshake
{
    /// <summary>
    /// Строит 32-байтный auth-токен для вставки в session_id ClientHello.
    /// </summary>
    /// <param name="clientPrivateKey">Приватный ключ клиента (32 байта).</param>
    /// <param name="serverPublicKey">Публичный ключ сервера (32 байта).</param>
    /// <returns>32-байтный токен.</returns>
    public static byte[] BuildAuthToken(byte[] clientPrivateKey, byte[] serverPublicKey)
    {
        var sharedSecret = Crypto.KeyExchange.ComputeSharedSecret(clientPrivateKey, serverPublicKey);
        var timestamp    = BitConverter.GetBytes(DateTimeOffset.UtcNow.ToUnixTimeSeconds());

        return HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            ikm:          sharedSecret,
            outputLength: 32,
            salt:         timestamp,
            info:         "reality-auth-v1"u8.ToArray()
        );
    }

    /// <summary>
    /// Проверяет auth-токен на сервере с окном ±30 секунд.
    /// Использует константное время сравнения для защиты от timing-атак.
    /// </summary>
    /// <param name="token">Токен из session_id ClientHello.</param>
    /// <param name="serverPrivateKey">Приватный ключ сервера.</param>
    /// <param name="clientPublicKey">Публичный ключ клиента из key_share extension.</param>
    /// <returns>True если токен валиден.</returns>
    public static bool VerifyAuthToken(byte[] token, byte[] serverPrivateKey, byte[] clientPublicKey)
    {
        var sharedSecret = Crypto.KeyExchange.ComputeSharedSecret(serverPrivateKey, clientPublicKey);
        var now          = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        for (long delta = -30; delta <= 30; delta++)
        {
            var timestamp = BitConverter.GetBytes(now + delta);
            var expected  = HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                ikm:          sharedSecret,
                outputLength: 32,
                salt:         timestamp,
                info:         "reality-auth-v1"u8.ToArray()
            );

            if (CryptographicOperations.FixedTimeEquals(token, expected))
                return true;
        }
        return false;
    }
}