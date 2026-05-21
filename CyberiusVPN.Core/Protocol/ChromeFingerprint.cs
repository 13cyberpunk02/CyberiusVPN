using Org.BouncyCastle.Tls;

namespace CyberiusVPN.Core.Protocol;

/// <summary>
/// Эталонный fingerprint TLS ClientHello Chrome 120.
/// DPI системы идентифицируют TLS клиентов по составу и порядку
/// cipher suites и extensions. Наш fingerprint неотличим от Chrome.
/// </summary>
public sealed class ChromeFingerprint
{
    /// <summary>Cipher suites Chrome 120 в точном порядке.</summary>
    public static readonly int[] CipherSuites =
    [
        CipherSuite.TLS_AES_128_GCM_SHA256,
        CipherSuite.TLS_AES_256_GCM_SHA384,
        CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
    ];

    /// <summary>Поддерживаемые эллиптические группы Chrome 120.</summary>
    public static readonly int[] SupportedGroups =
    [
        NamedGroup.x25519,
        NamedGroup.secp256r1,
        NamedGroup.secp384r1,
    ];
}