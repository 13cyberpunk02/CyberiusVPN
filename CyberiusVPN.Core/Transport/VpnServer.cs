using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using CyberiusVPN.Core.Crypto;
using CyberiusVPN.Core.Models;
using CyberiusVPN.Core.Tun;
using Microsoft.Extensions.Logging;

namespace CyberiusVPN.Core.Transport;

/// <summary>
/// VPN Сервер.
///
/// Логика Reality-подобного роутинга:
/// 1. Принимаем TCP соединение
/// 2. Читаем первые байты (ClientHello)
/// 3. Извлекаем session_id
/// 4. Проверяем auth токен (X25519)
///    - Наш клиент  → VPN сессия
///    - Чужой       → форвардим к реальному SNI домену (выглядим как обычный HTTPS)
/// </summary>
public sealed class VpnServer
{
    private readonly ServerConfig  _config;
    private readonly ILogger       _logger;
    private readonly ILoggerFactory _loggerFactory;

    // Хранилище активных сессий
    private readonly Dictionary<uint, VpnSession> _sessions = new();
    private readonly SemaphoreSlim                _lock     = new(1, 1);
    private int _nextClientIp = 2;

    // Ключи сервера
    private readonly byte[] _serverPrivateKey;
    private readonly byte[] _serverPublicKey;

    public VpnServer(ServerConfig config, ILoggerFactory loggerFactory)
    {
        _config        = config;
        _loggerFactory = loggerFactory;
        _logger        = loggerFactory.CreateLogger<VpnServer>();

        _serverPrivateKey = KeyExchange.FromBase64(config.PrivateKey);
        _serverPublicKey  = X25519PublicFromPrivate(_serverPrivateKey);
    }

    public async Task RunAsync(CancellationToken ct)
    {
        var endpoint = new IPEndPoint(IPAddress.Any, _config.ListenPort);
        var listener = new TcpListener(endpoint);
        listener.Start();

        _logger.LogInformation("Server listening on :{Port}", _config.ListenPort);
        _logger.LogInformation("SNI domain: {Sni}", _config.SniDomain);

        while (!ct.IsCancellationRequested)
        {
            var client = await listener.AcceptTcpClientAsync(ct);
            _ = HandleClientAsync(client, ct); // каждый клиент независимо
        }
    }

    private async Task HandleClientAsync(TcpClient tcp, CancellationToken ct)
    {
        var remote = tcp.Client.RemoteEndPoint;
        _logger.LogDebug("Connection from {Remote}", remote);

        try
        {
            using var stream = tcp.GetStream();

            // Читаем ClientHello сырыми байтами (до TLS handshake)
            var hello = await PeekClientHelloAsync(stream, ct);

            // Проверяем наш auth токен из session_id
            var (isOurClient, clientPublicKey) = CheckAuthToken(hello);

            if (isOurClient && clientPublicKey is not null)
            {
                _logger.LogInformation("VPN client authenticated from {Remote}", remote);
                await HandleVpnClientAsync(stream, clientPublicKey, ct);
            }
            else
            {
                // Чужой — форвардим к реальному домену
                _logger.LogDebug("Non-VPN client, forwarding to {Sni}", _config.SniDomain);
                await ForwardToRealServerAsync(stream, hello, ct);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug("Client {Remote} disconnected: {Msg}", remote, ex.Message);
        }
        finally
        {
            tcp.Dispose();
        }
    }

    /// <summary>
    /// Peek первые байты не двигая позицию стрима.
    /// TLS ClientHello: [0x16][0x03][0x01][len_hi][len_lo][0x01]...
    ///                   type  vers  vers  length             handshake_type=ClientHello
    /// session_id offset ≈ 43 байта от начала handshake
    /// </summary>
    private static async Task<byte[]> PeekClientHelloAsync(NetworkStream stream, CancellationToken ct)
    {
        // Читаем достаточно для TLS record header + ClientHello до session_id включительно
        var buf = new byte[512];
        int read = await stream.ReadAsync(buf.AsMemory(0, 512), ct);
        return buf[..read];
    }

    /// <summary>
    /// Извлекаем session_id из ClientHello и проверяем как auth токен
    /// </summary>
    private (bool isOurs, byte[]? clientPublicKey) CheckAuthToken(byte[] hello)
    {
        try
        {
            // TLS record: type(1) + version(2) + length(2) = 5 bytes
            // Handshake:  type(1) + length(3) = 4 bytes
            // ClientHello: version(2) + random(32) = 34 bytes → offset 5+4+34 = 43
            // session_id_len: 1 byte at offset 43
            // session_id: начинается с offset 44

            if (hello.Length < 76) return (false, null);

            // TLS ContentType должен быть 0x16 (handshake)
            if (hello[0] != 0x16) return (false, null);

            // HandshakeType должен быть 0x01 (ClientHello)
            if (hello[5] != 0x01) return (false, null);

            int sessionIdLen = hello[43];
            if (sessionIdLen != 32) return (false, null); // Наш токен всегда 32 байта

            var sessionId = hello[44..76]; // 32 байта auth токен

            // Проверяем что это наш токен
            // Для проверки нам нужен публичный ключ клиента —
            // он передаётся в TLS extension key_share (X25519)
            // В реальной реализации извлекаем его оттуда
            // Здесь для прототипа проверяем по HMAC с серверным ключом
            var isValid = VerifySessionIdToken(sessionId);
            return (isValid, isValid ? ExtractClientPublicKey(hello) : null);
        }
        catch
        {
            return (false, null);
        }
    }

    private bool VerifySessionIdToken(byte[] sessionId)
    {
        // Проверяем токен в окне ±30 секунд
        // Токен = HKDF(serverPrivKey XOR clientRandom, timestamp, "reality-auth-v1")
        // В прототипе — упрощённая проверка через первые 4 байта как magic
        // В полной реализации: извлечь ephemeral public key клиента из key_share,
        // вычислить shared secret, и проверить HKDF результат

        // Проверяем что первые байты похожи на наш токен
        // (полная реализация требует key_share парсинга)
        var magic = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(sessionId);
        return magic != 0; // placeholder — см. полную реализацию ниже
    }

    private byte[]? ExtractClientPublicKey(byte[] hello)
    {
        // Парсим TLS extensions для поиска key_share с X25519
        // В полной реализации: итерируем extensions после cipher suites
        return null; // placeholder
    }

    private async Task HandleVpnClientAsync(NetworkStream stream, byte[] clientPublicKey, CancellationToken ct)
    {
        var salt = new byte[32];
        RandomNumberGenerator.Fill(salt);
        await stream.WriteAsync(salt, ct);

        var sharedSecret = KeyExchange.ComputeSharedSecret(_serverPrivateKey, clientPublicKey);
        var keys         = KeyDerivation.DeriveSessionKeys(sharedSecret, salt);

        var clientIpNum = Interlocked.Increment(ref _nextClientIp);
        var tunName     = $"vpns{clientIpNum}";

        _logger.LogInformation("Opening TUN {Name}...", tunName); // ← добавь

        try  // ← добавь весь try/catch
        {
            var tun = new TunInterface(_loggerFactory.CreateLogger<TunInterface>());
            await tun.OpenAsync(tunName, _config.TunAddress, "255.255.255.0");

            var sessionId = (uint)Random.Shared.Next();
            var framer    = new VpnFramer(keys, sessionId, _logger);
            var tunnel    = new VpnTunnel(framer, tun, stream, _logger);

            _logger.LogInformation("Tunnel running for {Name}", tunName); // ← добавь

            await tunnel.RunAsync(ct);
            await tun.DisposeAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError("TUN/Tunnel error for {Name}: {Msg}", tunName, ex.Message); // ← добавь
            _logger.LogError("Stack: {Stack}", ex.StackTrace);
        }
    }

    /// <summary>
    /// Форвардим соединение к реальному HTTPS серверу.
    /// DPI видит: клиент подключился → получил реальный сертификат microsoft.com → обычный HTTPS
    /// </summary>
    private async Task ForwardToRealServerAsync(NetworkStream clientStream, byte[] buffered, CancellationToken ct)
    {
        using var real = new TcpClient();
        await real.ConnectAsync(_config.SniDomain, 443, ct);

        using var realStream = real.GetStream();

        // Отправляем буферизованный ClientHello реальному серверу
        await realStream.WriteAsync(buffered, ct);

        // Двунаправленный форвардинг
        await Task.WhenAll(
            CopyStreamAsync(clientStream, realStream, ct),
            CopyStreamAsync(realStream, clientStream, ct)
        );
    }

    private static async Task CopyStreamAsync(Stream from, Stream to, CancellationToken ct)
    {
        var buf = new byte[8192];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                int read = await from.ReadAsync(buf, ct);
                if (read == 0) break;
                await to.WriteAsync(buf.AsMemory(0, read), ct);
            }
        }
        catch { /* соединение закрыто */ }
    }

    private static byte[] RandomNumberGeneratorSalt()
    {
        var salt = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(salt);
        return salt;
    }

    private static byte[] X25519PublicFromPrivate(byte[] privateKey)
    {
        var priv = new Org.BouncyCastle.Crypto.Parameters.X25519PrivateKeyParameters(privateKey, 0);
        var pub  = priv.GeneratePublicKey();
        var bytes = new byte[32];
        pub.Encode(bytes, 0);
        return bytes;
    }
}