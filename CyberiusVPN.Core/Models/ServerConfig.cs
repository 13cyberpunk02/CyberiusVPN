namespace CyberiusVPN.Core.Models;

public record ServerConfig(
    int     ListenPort,
    string  PrivateKey,         // Base64 X25519 приватный ключ сервера
    string  SniDomain,          // Домен которому притворяемся
    string  TunAddress,         // Например "10.8.0.1"
    string  TunMask,            // Например "255.255.255.0"
    int     Mtu = 1500
);