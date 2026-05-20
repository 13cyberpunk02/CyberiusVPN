namespace CyberiusVPN.Core.Models;

public record VpnConfig(
    string  ServerHost,
    int     ServerPort,
    string  ServerPublicKey,    // Base64 X25519 публичный ключ сервера
    string  ClientPrivateKey,   // Base64 X25519 приватный ключ клиента
    string  SniDomain,          // Домен для маскировки, например "www.microsoft.com"
    string  TunAddress,         // Например "10.8.0.2"
    string  TunMask,            // Например "255.255.255.0"
    int     Mtu = 1500
);