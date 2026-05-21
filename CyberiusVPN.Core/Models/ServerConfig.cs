namespace CyberiusVPN.Core.Models;

/// <summary>Конфигурация VPN сервера.</summary>
/// <param name="ListenPort">TCP порт для входящих подключений.</param>
/// <param name="PrivateKey">Base64 приватный ключ X25519 сервера.</param>
/// <param name="SniDomain">SNI домен — реальный HTTPS сайт для форвардинга неизвестных клиентов.</param>
/// <param name="TunAddress">IP адрес серверной стороны TUN (например 10.8.0.1).</param>
/// <param name="TunMask">Маска подсети TUN.</param>
/// <param name="Mtu">MTU TUN интерфейса.</param>
public record ServerConfig(
    int    ListenPort,
    string PrivateKey,
    string SniDomain,
    string TunAddress,
    string TunMask,
    int    Mtu = 1500
);