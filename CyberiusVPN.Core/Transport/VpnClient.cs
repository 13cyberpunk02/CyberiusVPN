using System.Net;
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
///
/// Процесс подключения:
/// 1. TCP connect к серверу
/// 2. Генерируем эфемерную пару ключей X25519
/// 3. Строим TLS ClientHello с Chrome 120 fingerprint:
///    — эфемерный публичный ключ → extension key_share
///    — auth-токен (X25519 + HKDF) → legacy_session_id
/// 4. Получаем соль от сервера (32 байта)
/// 5. ECDH(ephPriv, serverPub) + HKDF(salt) → сессионные ключи
/// 6. Открываем TUN интерфейс
/// 7. Двунаправленный туннель: TUN ↔ зашифрованный TCP
/// </summary>
public sealed class VpnClient
{
    private readonly VpnConfig      _config;
    private readonly ILogger        _logger;
    private readonly ILoggerFactory _loggerFactory;
    private readonly byte[]         _clientPrivateKey;
    private readonly byte[]         _serverPublicKey;

    /// <summary>
    /// Создаёт VPN клиент.
    /// </summary>
    /// <param name="config">Конфигурация подключения.</param>
    /// <param name="loggerFactory">Фабрика логгеров.</param>
    public VpnClient(VpnConfig config, ILoggerFactory loggerFactory)
    {
        _config           = config;
        _loggerFactory    = loggerFactory;
        _logger           = loggerFactory.CreateLogger<VpnClient>();
        _clientPrivateKey = KeyExchange.FromBase64(config.ClientPrivateKey);
        _serverPublicKey  = KeyExchange.FromBase64(config.ServerPublicKey);
    }

    /// <summary>
    /// Подключается к серверу и запускает туннель.
    /// При разрыве автоматически переподключается через 5 секунд.
    /// </summary>
    /// <param name="ct">Токен отмены.</param>
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

    /// <summary>Выполняет одну попытку подключения и работы туннеля.</summary>
    private async Task ConnectAndRunAsync(CancellationToken ct)
    {
        using var tcp = new TcpClient();
        tcp.NoDelay = true;

        await tcp.ConnectAsync(_config.ServerHost, _config.ServerPort, ct);
        _logger.LogInformation("TCP connected");

        using var stream = tcp.GetStream();

        try
        {
            // 1. Генерируем эфемерную пару ключей для этой сессии
            var (ephPrivKey, ephPubKey) = KeyExchange.GenerateKeyPair();

            // 2. Auth-токен (будет в session_id ClientHello)
            var authToken = RealityHandshake.BuildAuthToken(_clientPrivateKey, _serverPublicKey);

            // 3. Отправляем ClientHello с Chrome fingerprint
            await SendRealityClientHelloAsync(stream, authToken, ephPubKey, ct);

            // 4. Получаем соль от сервера
            var handshake  = new byte[36];
            await ReadExactAsync(stream, handshake, ct);
            var salt       = handshake[..32];
            var assignedIp = new System.Net.IPAddress(handshake[32..36]).ToString();
            _logger.LogInformation("Assigned IP: {Ip}", assignedIp);

            // 5. ECDH с эфемерным ключом → сессионные ключи
            var sharedSecret = KeyExchange.ComputeSharedSecret(ephPrivKey, _serverPublicKey);
            var keys         = KeyDerivation.DeriveSessionKeys(sharedSecret, salt);

            _logger.LogInformation("Session keys derived, opening TUN...");

            // 6. Открываем TUN интерфейс
            var tun = new TunInterface(_loggerFactory.CreateLogger<TunInterface>());
            await tun.OpenAsync("vpn0", assignedIp, _config.TunMask, _config.Mtu);

            // 7. Прописываем маршрут к серверу через реальный шлюз
            SetupRoutes(_config.ServerHost, assignedIp);

            // 8. Запускаем туннель
            var sessionId = (uint)Random.Shared.Next();
            var framer    = new VpnFramer(keys, sessionId, _logger);
            var tunnel    = new VpnTunnel(framer, tun, stream, _logger);

            _logger.LogInformation("VPN connected! Routing traffic through tunnel.");

            await tunnel.RunAsync(ct);
            await tun.DisposeAsync();
        }
        finally
        {
            // Восстанавливаем маршруты при любом выходе
            CleanupRoutes(_config.ServerHost);
        }
    }

    /// <summary>
    /// Строит и отправляет TLS ClientHello с Chrome 120 fingerprint.
    ///
    /// Структура ClientHello (упрощённо):
    /// TLS Record:  [16 03 01] [length]
    /// Handshake:   [01] [length 3B]
    /// ClientHello: [03 03] [random 32B] [session_id_len 1B=32] [session_id=authToken 32B] ...
    /// </summary>
    private async Task SendRealityClientHelloAsync(Stream stream, byte[] authToken,
        byte[] ephPubKey, CancellationToken ct)
    {
        using var ms = new System.IO.MemoryStream();
        using var w  = new System.IO.BinaryWriter(ms);

        // === ClientHello body ===
        using var helloMs = new System.IO.MemoryStream();
        using var hw      = new System.IO.BinaryWriter(helloMs);

        // Client version: TLS 1.2 (0x0303) — в TLS 1.3 реальная версия в extension
        hw.Write((byte)0x03);
        hw.Write((byte)0x03);

        // Random: 32 случайных байта (как у настоящего браузера)
        var random = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(random);
        hw.Write(random);

        // Session ID = auth-токен (32 байта) — наш механизм аутентификации
        hw.Write((byte)32);
        hw.Write(authToken);

        // Cipher Suites (Chrome 120 в точном порядке)
        var ciphers = ChromeFingerprint.CipherSuites;
        hw.Write(BSwap16((ushort)(ciphers.Length * 2 + 2)));
        hw.Write(BSwap16(0x00FF)); // GREASE
        foreach (var cs in ciphers)
            hw.Write(BSwap16((ushort)cs));

        // Compression: none
        hw.Write((byte)1);
        hw.Write((byte)0);

        // Extensions (SNI, supported_versions, supported_groups, sig_algs, key_share)
        var exts = BuildExtensions(_config.SniDomain, ephPubKey);
        hw.Write(BSwap16((ushort)exts.Length));
        hw.Write(exts);

        var helloBody = helloMs.ToArray();

        // === Handshake message ===
        using var hsMs = new System.IO.MemoryStream();
        using var hsw  = new System.IO.BinaryWriter(hsMs);

        hsw.Write((byte)0x01); // HandshakeType: ClientHello
        hsw.Write((byte)((helloBody.Length >> 16) & 0xFF));
        hsw.Write((byte)((helloBody.Length >> 8) & 0xFF));
        hsw.Write((byte)(helloBody.Length & 0xFF));
        hsw.Write(helloBody);

        var hsData = hsMs.ToArray();

        // === TLS Record ===
        w.Write((byte)0x16); // ContentType: Handshake
        w.Write((byte)0x03);
        w.Write((byte)0x01);
        w.Write(BSwap16((ushort)hsData.Length));
        w.Write(hsData);

        await stream.WriteAsync(ms.ToArray(), ct);
        _logger.LogDebug("ClientHello sent ({Bytes} bytes)", ms.Length);
    }

    /// <summary>
    /// Строит TLS extensions с переданным эфемерным публичным ключом в key_share.
    /// Ключ должен совпадать с тем, что используется для ECDH.
    /// </summary>
    private static byte[] BuildExtensions(string sni, byte[] ephPub)
    {
        using var ms = new System.IO.MemoryStream();
        using var w  = new System.IO.BinaryWriter(ms);

        // SNI extension (0x0000)
        var sniBytes = System.Text.Encoding.ASCII.GetBytes(sni);
        w.Write(BSwap16(0x0000));
        w.Write(BSwap16((ushort)(sniBytes.Length + 5)));
        w.Write(BSwap16((ushort)(sniBytes.Length + 3)));
        w.Write((byte)0x00); // host_name
        w.Write(BSwap16((ushort)sniBytes.Length));
        w.Write(sniBytes);

        // supported_versions: TLS 1.3 (0x002B)
        w.Write(BSwap16(0x002B));
        w.Write(BSwap16(0x0003));
        w.Write((byte)0x02);
        w.Write(BSwap16(0x0304));

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

        // key_share: эфемерный X25519 ключ (0x0033)
        // Этот же ключ используется для ECDH — они должны совпадать!
        w.Write(BSwap16(0x0033));
        w.Write(BSwap16(0x0026));
        w.Write(BSwap16(0x0024));
        w.Write(BSwap16(0x001D)); // x25519
        w.Write(BSwap16(0x0020));
        w.Write(ephPub);

        return ms.ToArray();
    }

    /// <summary>
    /// Прописывает маршрут к VPN серверу через реальный шлюз.
    /// Без этого трафик к серверу пойдёт через TUN и создаст петлю.
    /// </summary>
    private static void SetupRoutes(string serverHost, string assignedIp)
    {
        // Резолвим hostname в IP
        var serverIp = serverHost;
        try
        {
            var addresses = System.Net.Dns.GetHostAddresses(serverHost);
            if (addresses.Length > 0) serverIp = addresses[0].ToString();
        }
        catch { }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            var gw = GetDefaultGateway();
            if (string.IsNullOrEmpty(gw)) return;
            Console.WriteLine($"Default gateway: {gw}, server: {serverIp}");

            var ifIndex = GetInterfaceIndex("vpn0");
            Console.WriteLine($"vpn0 interface index: {ifIndex}");

            Run("route", $"delete {serverIp} mask 255.255.255.255");
            Run("route", $"add {serverIp} mask 255.255.255.255 {gw} metric 1");
            Run("route", "delete 0.0.0.0 mask 0.0.0.0 172.18.0.2");
            Run("route", "delete 0.0.0.0 mask 128.0.0.0");
            Run("route", "delete 128.0.0.0 mask 128.0.0.0");
            Run("route", $"add 0.0.0.0 mask 128.0.0.0 {assignedIp} IF {ifIndex} metric 1");
            Run("route", $"add 128.0.0.0 mask 128.0.0.0 {assignedIp} IF {ifIndex} metric 1");
            Run("netsh", "interface ip set dns \"vpn0\" static 8.8.8.8");
        }
        else // Linux
        {
            var defaultRoute = RunAndRead("ip", "route show default");
            var parts = defaultRoute.Split(' ');
            var gw    = parts.Length > 2 ? parts[2] : "";
            var iface = parts.Length > 4 ? parts[4] : "";

            Console.WriteLine($"Gateway: {gw} via {iface}, server: {serverIp}");

            Run("ip", $"route add {serverIp}/32 via {gw} dev {iface}");
            Run("ip", "route del default");
            Run("ip", "route add default dev vpn0");
            Run("bash", "-c \"echo 'nameserver 8.8.8.8' > /etc/resolv.conf\"");
        }
    }
    
    
    private static int GetInterfaceIndex(string interfaceName)
    {
        try
        {
            foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.Name.Equals(interfaceName, StringComparison.OrdinalIgnoreCase))
                {
                    var props = ni.GetIPProperties();
                    return props.GetIPv4Properties().Index;
                }
            }
        }
        catch
        {
            // ignored
        }

        return 0;
    }

    /// <summary>Удаляет добавленные маршруты при отключении.</summary>
    private static void CleanupRoutes(string serverHost)
    {
        var serverIp = serverHost;
        try
        {
            var addresses = System.Net.Dns.GetHostAddresses(serverHost);
            if (addresses.Length > 0) serverIp = addresses[0].ToString();
        }
        catch
        {
            // ignored
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Run("route", $"delete {serverIp} mask 255.255.255.255");
            Run("route", "delete 0.0.0.0 mask 128.0.0.0");
            Run("route", "delete 128.0.0.0 mask 128.0.0.0");
            Console.WriteLine("Routes restored.");
        }
        else // Linux
        {
            Run("ip", $"route del {serverIp}/32 2>/dev/null || true");
            Run("ip", "route del default dev vpn0 2>/dev/null || true");
            Run("systemctl", "restart NetworkManager");
            Console.WriteLine("Routes restored.");
        }
    }
    
    // Читает stdout команды
    private static string RunAndRead(string cmd, string args)
    {
        var psi = new System.Diagnostics.ProcessStartInfo(cmd, args)
        {
            RedirectStandardOutput = true,
            UseShellExecute = false
        };
        var p = System.Diagnostics.Process.Start(psi)!;
        var output = p.StandardOutput.ReadLine() ?? "";
        p.WaitForExit();
        return output;
    }

    /// <summary>Читает шлюз по умолчанию из таблицы маршрутизации Windows.</summary>
    private static string GetDefaultGateway()
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("route", "print 0.0.0.0")
            {
                RedirectStandardOutput = true,
                UseShellExecute        = false
            };
            var p      = System.Diagnostics.Process.Start(psi)!;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();

            foreach (var line in output.Split('\n'))
            {
                var parts = line.Trim().Split(
                    new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);

                if (parts.Length >= 3
                    && parts[0] == "0.0.0.0"
                    && parts[1] == "0.0.0.0"
                    && IPAddress.TryParse(parts[2], out _))
                    return parts[2];
            }
        }
        catch { }
        return "";
    }

    /// <summary>Читает ровно buf.Length байт из потока.</summary>
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

    /// <summary>Запускает системную команду без ожидания вывода.</summary>
    private static void Run(string cmd, string args)
    {
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName               = cmd,
            Arguments              = args,
            RedirectStandardOutput = true,
            RedirectStandardError  = true,
            UseShellExecute        = false
        })?.WaitForExit();
    }

    /// <summary>Меняет порядок байт 16-битного числа (big-endian для TLS).</summary>
    private static ushort BSwap16(ushort v) => (ushort)((v >> 8) | (v << 8));
}
