using CyberiusVPN.Core.Crypto;
using CyberiusVPN.Core.Models;
using CyberiusVPN.Core.Transport;
using Microsoft.Extensions.Logging;

// ─── Генерация ключей ───────────────────────────────────────────────────────
if (args.Length > 0 && args[0] == "genkeys")
{
    var (priv, pub) = KeyExchange.GenerateKeyPair();
    Console.WriteLine($"Server Private: {KeyExchange.ToBase64(priv)}");
    Console.WriteLine($"Server Public:  {KeyExchange.ToBase64(pub)}");
    Console.WriteLine("→ Public key goes into client config (VPN_SERVER_PUBKEY)");
    return;
}

// ─── Конфиг ────────────────────────────────────────────────────────────────
var config = new ServerConfig(
    ListenPort: int.Parse(Environment.GetEnvironmentVariable("VPN_PORT")       ?? "443"),
    PrivateKey: Environment.GetEnvironmentVariable("VPN_SERVER_PRIVKEY")        ?? "",
    SniDomain:  Environment.GetEnvironmentVariable("VPN_SNI")                   ?? "www.microsoft.com",
    TunAddress: "10.8.0.1",
    TunMask:    "255.255.255.0"
);

// ─── Logging ────────────────────────────────────────────────────────────────
using var logFactory = LoggerFactory.Create(b =>
    b.AddConsole().SetMinimumLevel(
        args.Contains("--verbose") ? LogLevel.Trace : LogLevel.Information));

// ─── Запуск ─────────────────────────────────────────────────────────────────
var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

Console.WriteLine("CSharpVPN Server starting...");
Console.WriteLine($"Listen:  :{config.ListenPort}");
Console.WriteLine($"SNI:     {config.SniDomain}");
Console.WriteLine($"TUN:     {config.TunAddress}");

var server = new VpnServer(config, logFactory);
await server.RunAsync(cts.Token);