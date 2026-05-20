using System.Net.Sockets;
using System.Runtime.InteropServices;
using CyberiusVPN.Core.Crypto;
using CyberiusVPN.Core.Models;
using CyberiusVPN.Core.Protocol;
using CyberiusVPN.Core.Tun;
using Microsoft.Extensions.Logging;

namespace CyberiusVPN.Core.Transport;

/// <summary>
/// VPN Клиент.
/// 1. Подключается к серверу по TCP :443
/// 2. Делает TLS ClientHello с Chrome fingerprint + auth токен в session_id
/// 3. Открывает TUN интерфейс
/// 4. Запускает двунаправленный туннель
/// </summary>
public sealed class VpnClient
{
    private readonly VpnConfig      _config;
    private readonly ILogger        _logger;
    private readonly ILoggerFactory _loggerFactory;

    private readonly byte[] _clientPrivateKey;
    private readonly byte[] _clientPublicKey;
    private readonly byte[] _serverPublicKey;

    public VpnClient(VpnConfig config, ILoggerFactory loggerFactory)
    {
        _config        = config;
        _loggerFactory = loggerFactory;
        _logger        = loggerFactory.CreateLogger<VpnClient>();

        _clientPrivateKey = KeyExchange.FromBase64(config.ClientPrivateKey);
        _clientPublicKey  = X25519PublicFromPrivate(_clientPrivateKey);
        _serverPublicKey  = KeyExchange.FromBase64(config.ServerPublicKey);
    }

    public async Task RunAsync(CancellationToken ct)
    {
        _logger.LogInformation("Connecting to {Host}:{Port} (SNI: {Sni})",
            _config.ServerHost, _config.ServerPort, _config.SniDomain);

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await ConnectAndRunAsync(ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogWarning("Disconnected: {Msg}. Reconnecting in 5s...", ex.Message);
                await Task.Delay(5000, ct);
            }
        }
    }

    private async Task ConnectAndRunAsync(CancellationToken ct)
    {
        using var tcp = new TcpClient();
        tcp.NoDelay  = true;

        await tcp.ConnectAsync(_config.ServerHost, _config.ServerPort, ct);
        _logger.LogInformation("TCP connected");

        using var stream = tcp.GetStream();

        // 1. Строим auth токен
        var authToken = RealityHandshake.BuildAuthToken(_clientPrivateKey, _serverPublicKey);

        // 2. Делаем TLS-подобный handshake с Chrome fingerprint
        //    auth токен едет в session_id поле
        await SendRealityClientHelloAsync(stream, authToken, ct);

        // 3. Получаем соль для деривации ключей от сервера
        var salt = new byte[32];
        await ReadExactAsync(stream, salt, ct);

        // 4. Вычисляем ключи сессии
        var sharedSecret = KeyExchange.ComputeSharedSecret(_clientPrivateKey, _serverPublicKey);
        var keys         = KeyDerivation.DeriveSessionKeys(sharedSecret, salt);

        _logger.LogInformation("Session keys derived, opening TUN...");

        // 5. Открываем TUN
        var tun = new TunInterface(_loggerFactory.CreateLogger<TunInterface>());
        await tun.OpenAsync("vpn0", _config.TunAddress, _config.TunMask, _config.Mtu);

        // 6. Настраиваем маршруты
        SetupRoutes(_config.ServerHost, _config.TunAddress);

        // 7. Запускаем туннель
        var sessionId = (uint)Random.Shared.Next();
        var framer    = new VpnFramer(keys, sessionId, _logger);
        var tunnel    = new VpnTunnel(framer, tun, stream, _logger);

        _logger.LogInformation("VPN connected! Routing traffic through tunnel.");
        await tunnel.RunAsync(ct);

        await tun.DisposeAsync();
    }

    /// <summary>
    /// Отправляем TLS ClientHello с Chrome 120 fingerprint.
    /// Auth токен вшит в legacy_session_id (32 байта).
    ///
    /// Структура TLS ClientHello (упрощённо):
    /// Record Layer:    [16 03 01] [length 2B]
    /// Handshake:       [01] [length 3B]
    /// ClientHello:     [03 03] [random 32B] [session_id_len 1B] [session_id 32B] ...
    /// </summary>
    private async Task SendRealityClientHelloAsync(Stream stream, byte[] authToken, CancellationToken ct)
    {
        using var ms  = new MemoryStream();
        using var w   = new BinaryWriter(ms);

        // === ClientHello body ===
        using var helloMs = new MemoryStream();
        using var hw      = new BinaryWriter(helloMs);

        // Client version: TLS 1.2 (0x0303) — в TLS 1.3 реальная версия в extension
        hw.Write((byte)0x03);
        hw.Write((byte)0x03);

        // Random: 32 байта случайных данных (как настоящий браузер)
        var random = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(random);
        hw.Write(random);

        // Session ID = наш auth токен (32 байта)
        hw.Write((byte)32);
        hw.Write(authToken);

        // Cipher Suites (Chrome 120 порядок)
        var ciphers = ChromeFingerprint.CipherSuites;
        hw.Write((ushort)BSwap16((ushort)(ciphers.Length * 2 + 2)));
        hw.Write((ushort)BSwap16(0x00FF)); // GREASE
        foreach (var cs in ciphers)
            hw.Write((ushort)BSwap16((ushort)cs));

        // Compression: none
        hw.Write((byte)1);
        hw.Write((byte)0);

        // Extensions
        var exts = BuildExtensions(_config.SniDomain);
        hw.Write((ushort)BSwap16((ushort)exts.Length));
        hw.Write(exts);

        var helloBody = helloMs.ToArray();

        // === Handshake message ===
        using var hsMs = new MemoryStream();
        using var hsw  = new BinaryWriter(hsMs);

        hsw.Write((byte)0x01); // HandshakeType: ClientHello
        // 3-byte length
        hsw.Write((byte)((helloBody.Length >> 16) & 0xFF));
        hsw.Write((byte)((helloBody.Length >> 8) & 0xFF));
        hsw.Write((byte)(helloBody.Length & 0xFF));
        hsw.Write(helloBody);

        var hsData = hsMs.ToArray();

        // === TLS Record ===
        w.Write((byte)0x16);          // ContentType: Handshake
        w.Write((byte)0x03);          // Version: TLS 1.0 (для совместимости)
        w.Write((byte)0x01);
        w.Write((ushort)BSwap16((ushort)hsData.Length));
        w.Write(hsData);

        await stream.WriteAsync(ms.ToArray(), ct);
        _logger.LogDebug("ClientHello sent ({Bytes} bytes)", ms.Length);
    }

    private static byte[] BuildExtensions(string sni)
    {
        using var ms = new MemoryStream();
        using var w  = new BinaryWriter(ms);

        // SNI extension (type 0x0000)
        var sniBytes = System.Text.Encoding.ASCII.GetBytes(sni);
        w.Write(BSwap16(0x0000));
        var sniData = sniBytes.Length + 5;
        w.Write(BSwap16((ushort)sniData));
        w.Write(BSwap16((ushort)(sniBytes.Length + 3)));
        w.Write((byte)0x00); // host_name
        w.Write(BSwap16((ushort)sniBytes.Length));
        w.Write(sniBytes);

        // supported_versions: TLS 1.3 (extension type 0x002B)
        w.Write(BSwap16(0x002B));
        w.Write(BSwap16(0x0003));
        w.Write((byte)0x02);
        w.Write(BSwap16(0x0304)); // TLS 1.3

        // supported_groups: x25519, secp256r1, secp384r1 (0x000A)
        w.Write(BSwap16(0x000A));
        w.Write(BSwap16(0x0008));
        w.Write(BSwap16(0x0006));
        foreach (var g in ChromeFingerprint.SupportedGroups)
            w.Write(BSwap16((ushort)g));

        // signature_algorithms (0x000D)
        w.Write(BSwap16(0x000D));
        w.Write(BSwap16(0x0014));
        w.Write(BSwap16(0x0012));
        ushort[] sigAlgs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201];
        foreach (var s in sigAlgs) w.Write(BSwap16(s));

        // key_share: x25519 ephemeral public key (0x0033)
        var (_, ephPub) = KeyExchange.GenerateKeyPair();
        w.Write(BSwap16(0x0033));
        w.Write(BSwap16(0x0026));
        w.Write(BSwap16(0x0024));
        w.Write(BSwap16(0x001D)); // x25519
        w.Write(BSwap16(0x0020));
        w.Write(ephPub);

        return ms.ToArray();
    }

    private static void SetupRoutes(string serverHost, string tunAddress)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // Сначала удаляем старый маршрут если есть — игнорируем ошибку
            Run("route", $"delete {serverHost}");
            Run("route", "delete 0.0.0.0 mask 0.0.0.0");

            // Добавляем заново
            Run("route", $"add 0.0.0.0 mask 0.0.0.0 {tunAddress} metric 5");
        }
        else
        {
            Run("ip", "route del default dev vpn0 2>/dev/null || true");
            Run("ip", "route add default dev vpn0");
        }
    }

    private static void Run(string cmd, string args)
    {
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = cmd, Arguments = args,
            RedirectStandardOutput = true, UseShellExecute = false
        })?.WaitForExit();
    }

    private static async Task ReadExactAsync(Stream s, byte[] buf, CancellationToken ct)
    {
        int offset = 0;
        while (offset < buf.Length)
        {
            int read = await s.ReadAsync(buf.AsMemory(offset), ct);
            if (read == 0) throw new EndOfStreamException();
            offset += read;
        }
    }

    private static byte[] X25519PublicFromPrivate(byte[] priv)
    {
        var p   = new Org.BouncyCastle.Crypto.Parameters.X25519PrivateKeyParameters(priv, 0);
        var pub = p.GeneratePublicKey();
        var b   = new byte[32];
        pub.Encode(b, 0);
        return b;
    }

    private static ushort BSwap16(ushort v) =>
        (ushort)((v >> 8) | (v << 8));
}
