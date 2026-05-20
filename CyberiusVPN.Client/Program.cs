using CyberiusVPN.Core.Crypto;
using CyberiusVPN.Core.Models;
using CyberiusVPN.Core.Transport;
using Microsoft.Extensions.Logging;

// ─── Генерация ключей (запускается один раз) ───────────────────────────────
if (args.Length > 0 && args[0] == "genkeys")
{
    var (priv, pub) = KeyExchange.GenerateKeyPair();
    Console.WriteLine($"Private: {KeyExchange.ToBase64(priv)}");
    Console.WriteLine($"Public:  {KeyExchange.ToBase64(pub)}");
    return;
}

// ─── Конфиг ────────────────────────────────────────────────────────────────
var config = new VpnConfig(
    ServerHost:      Environment.GetEnvironmentVariable("VPN_SERVER")      ?? "your-server.com",
    ServerPort:      int.Parse(Environment.GetEnvironmentVariable("VPN_PORT") ?? "443"),
    ServerPublicKey: Environment.GetEnvironmentVariable("VPN_SERVER_PUBKEY") ?? "",
    ClientPrivateKey:Environment.GetEnvironmentVariable("VPN_CLIENT_PRIVKEY") ?? "",
    SniDomain:       Environment.GetEnvironmentVariable("VPN_SNI")         ?? "www.microsoft.com",
    TunAddress:      "10.8.0.2",
    TunMask:         "255.255.255.0"
);

// ─── Logging ────────────────────────────────────────────────────────────────
using var logFactory = LoggerFactory.Create(b =>
    b.AddConsole().SetMinimumLevel(
        args.Contains("--verbose") ? LogLevel.Trace : LogLevel.Information));

// ─── Запуск ─────────────────────────────────────────────────────────────────
var cts    = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

Console.WriteLine("CSharpVPN Client starting...");
Console.WriteLine($"Server: {config.ServerHost}:{config.ServerPort}");
Console.WriteLine($"SNI:    {config.SniDomain}");

var client = new VpnClient(config, logFactory);
await client.RunAsync(cts.Token);

Console.WriteLine("Disconnected.");