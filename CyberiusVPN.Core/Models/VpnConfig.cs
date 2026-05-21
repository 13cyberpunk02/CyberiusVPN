namespace CyberiusVPN.Core.Models;

/// <summary>Конфигурация VPN клиента.</summary>
/// <param name="ServerHost">Хост или IP VPN сервера.</param>
/// <param name="ServerPort">TCP порт сервера (обычно 443).</param>
/// <param name="ServerPublicKey">Base64 публичный ключ X25519 сервера.</param>
/// <param name="ClientPrivateKey">Base64 приватный ключ X25519 клиента (эфемерный, не хранится).</param>
/// <param name="SniDomain">SNI домен для маскировки TLS handshake (например www.microsoft.com).</param>
/// <param name="TunAddress">IP адрес TUN интерфейса клиента (например 10.8.0.2).</param>
/// <param name="TunMask">Маска подсети TUN интерфейса.</param>
/// <param name="Mtu">MTU TUN интерфейса.</param>
public record VpnConfig(
    string ServerHost,
    int    ServerPort,
    string ServerPublicKey,
    string ClientPrivateKey,
    string SniDomain,
    string TunAddress,
    string TunMask,
    int    Mtu = 1500
);