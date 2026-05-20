using System.Security.Cryptography;
using CyberiusVPN.Core.Models;

namespace CyberiusVPN.Core.Crypto;

/// <summary>
/// HKDF — Key Derivation Function
/// </summary>
public static class KeyDerivation
{
    public static SessionKeys DeriveSessionKeys(byte[] sharedSecret, byte[] salt)
    {
        var sendKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret,
            outputLength: 32, salt: salt, info: "vpn-send-key"u8.ToArray());

        var recvKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret,
            outputLength: 32, salt: salt, info: "vpn-recv-key"u8.ToArray());

        // AES-GCM нужен 12-байтный IV
        var sendIv = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret,
            outputLength: 12, salt: salt, info: "vpn-send-iv"u8.ToArray());

        var recvIv = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret,
            outputLength: 12, salt: salt, info: "vpn-recv-iv"u8.ToArray());

        return new SessionKeys(sendKey, recvKey, sendIv, recvIv);
    }
}