using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace CyberiusVPN.Core.Protocol;

/// <summary>
/// Reality-подобный handshake.
/// 
/// Идея:
/// 1. Клиент строит TLS ClientHello с fingerprint Chrome 120
/// 2. В поле session_id прячем зашифрованный auth-токен (X25519)
/// 3. Сервер смотрит на session_id:
///    - Наш токен  → обрабатывает как VPN
///    - Чужой      → форвардит на реальный SNI домен (microsoft.com и т.д.)
/// </summary>
public sealed class RealityHandshake(ILogger logger)
{
    private readonly ILogger _logger = logger;

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