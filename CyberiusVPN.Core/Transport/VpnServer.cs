using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using CyberiusVPN.Core.Crypto;
using CyberiusVPN.Core.Models;
using CyberiusVPN.Core.Tun;
using Microsoft.Extensions.Logging;

namespace CyberiusVPN.Core.Transport;

/// <summary>
/// VPN Сервер с Reality-подобным роутингом.
///
/// Алгоритм обработки входящего соединения:
/// 1. Читаем TCP поток (первые 512 байт — TLS ClientHello)
/// 2. Парсим session_id (32 байта по offset 44)
/// 3. Извлекаем эфемерный публичный ключ клиента из key_share extension
/// 4. Проверяем auth-токен через ECDH + HKDF
///    — наш клиент → VPN сессия
///    — чужой       → форвардим к реальному SNI домену (маскировка)
/// </summary>
public sealed class VpnServer
{
    private readonly ServerConfig   _config;
    private readonly ILogger        _logger;
    private readonly ILoggerFactory _loggerFactory;
    private readonly byte[]         _serverPrivateKey;
    private readonly byte[]         _serverPublicKey;

    /// <summary>Атомарный счётчик для назначения уникальных IP клиентам.</summary>
    private int _nextClientIp = 2;

    /// <summary>
    /// Создаёт VPN сервер.
    /// </summary>
    /// <param name="config">Конфигурация сервера.</param>
    /// <param name="loggerFactory">Фабрика логгеров.</param>
    public VpnServer(ServerConfig config, ILoggerFactory loggerFactory)
    {
        _config           = config;
        _loggerFactory    = loggerFactory;
        _logger           = loggerFactory.CreateLogger<VpnServer>();
        _serverPrivateKey = KeyExchange.FromBase64(config.PrivateKey);
        _serverPublicKey  = X25519PublicFromPrivate(_serverPrivateKey);
    }

    /// <summary>
    /// Запускает TCP листенер и принимает входящие соединения.
    /// </summary>
    /// <param name="ct">Токен отмены.</param>
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
            // Каждый клиент обрабатывается независимо
            _ = HandleClientAsync(client, ct);
        }
    }

    /// <summary>Обрабатывает одно входящее TCP соединение.</summary>
    private async Task HandleClientAsync(TcpClient tcp, CancellationToken ct)
    {
        var remote = tcp.Client.RemoteEndPoint;
        _logger.LogDebug("Connection from {Remote}", remote);

        try
        {
            using var stream = tcp.GetStream();

            // Читаем ClientHello без продвижения позиции (peek)
            var hello = await PeekClientHelloAsync(stream, ct);
            var (isOurClient, clientPublicKey) = CheckAuthToken(hello);

            if (isOurClient && clientPublicKey is not null)
            {
                _logger.LogInformation("VPN client authenticated from {Remote}", remote);
                await HandleVpnClientAsync(stream, clientPublicKey, ct);
            }
            else
            {
                _logger.LogDebug("Non-VPN client, forwarding to {Sni}", _config.SniDomain);
                await ForwardToRealServerAsync(stream, hello, ct);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug("Client {Remote} error: {Msg}", remote, ex.Message);
        }
        finally
        {
            tcp.Dispose();
        }
    }

    /// <summary>Читает первые 512 байт TCP потока — TLS ClientHello.</summary>
    private static async Task<byte[]> PeekClientHelloAsync(NetworkStream stream, CancellationToken ct)
    {
        var buf  = new byte[512];
        int read = await stream.ReadAsync(buf.AsMemory(0, 512), ct);
        return buf[..read];
    }

    /// <summary>
    /// Проверяет является ли соединение нашим VPN клиентом.
    /// Извлекает session_id и эфемерный публичный ключ из ClientHello.
    /// </summary>
    private (bool isOurs, byte[]? clientPublicKey) CheckAuthToken(byte[] hello)
    {
        try
        {
            if (hello.Length < 76)            return (false, null);
            if (hello[0] != 0x16)             return (false, null); // TLS record
            if (hello[5] != 0x01)             return (false, null); // ClientHello

            int sessionIdLen = hello[43];
            if (sessionIdLen != 32)           return (false, null);

            // Извлекаем эфемерный публичный ключ клиента из key_share extension
            var clientPubKey = ExtractClientPublicKey(hello);
            if (clientPubKey is null)         return (false, null);

            // Временно: принимаем всех у кого session_id = 32 байта
            // TODO: реализовать полную проверку через VerifyAuthToken
            return (true, clientPubKey);
        }
        catch
        {
            return (false, null);
        }
    }

    /// <summary>
    /// Парсит TLS extensions и извлекает X25519 публичный ключ клиента
    /// из extension key_share (type 0x0033).
    /// </summary>
    private static byte[]? ExtractClientPublicKey(byte[] hello)
    {
        try
        {
            // Пропускаем session_id
            int pos = 44 + hello[43];

            // cipher_suites length
            if (pos + 2 > hello.Length) return null;
            int cipherLen = (hello[pos] << 8) | hello[pos + 1];
            pos += 2 + cipherLen;

            // compression_methods length
            if (pos + 1 > hello.Length) return null;
            int compLen = hello[pos];
            pos += 1 + compLen;

            // extensions total length
            if (pos + 2 > hello.Length) return null;
            int extsLen = (hello[pos] << 8) | hello[pos + 1];
            pos += 2;
            int extsEnd = pos + extsLen;

            // Итерируем extensions
            while (pos + 4 <= extsEnd && pos + 4 <= hello.Length)
            {
                int extType = (hello[pos] << 8) | hello[pos + 1];
                int extLen  = (hello[pos + 2] << 8) | hello[pos + 3];
                pos += 4;

                if (extType == 0x0033) // key_share
                {
                    int ksPos = pos;
                    int ksLen = (hello[ksPos] << 8) | hello[ksPos + 1];
                    ksPos += 2;
                    int ksEnd = ksPos + ksLen;

                    while (ksPos + 4 <= ksEnd && ksPos + 4 <= hello.Length)
                    {
                        int group  = (hello[ksPos] << 8) | hello[ksPos + 1];
                        int keyLen = (hello[ksPos + 2] << 8) | hello[ksPos + 3];
                        ksPos += 4;

                        if (group == 0x001D && keyLen == 32) // x25519
                        {
                            var key = new byte[32];
                            Array.Copy(hello, ksPos, key, 0, 32);
                            return key;
                        }
                        ksPos += keyLen;
                    }
                }
                pos += extLen;
            }
        }
        catch
        {
            // ignored
        }

        return null;
    }

    /// <summary>
    /// Устанавливает VPN сессию с аутентифицированным клиентом.
    /// </summary>
    private async Task HandleVpnClientAsync(NetworkStream stream, byte[]? clientPublicKey, CancellationToken ct)
    {
        if (clientPublicKey is null)
        {
            _logger.LogError("clientPublicKey is null");
            return;
        }

        // 1. Генерируем соль и отправляем клиенту ПЕРВЫМ
        //    Клиент ждёт соль перед деривацией ключей
        var salt = new byte[32];
        RandomNumberGenerator.Fill(salt);
        // clientIpNum вычисляем ЗДЕСЬ (до отправки), чтобы сразу отправить клиенту
        var clientIpNum = Interlocked.Increment(ref _nextClientIp);
        var assignedIp  = $"10.8.0.{clientIpNum}";
        var tunName     = $"vpns{clientIpNum}";

        // Отправляем клиенту: [32 байта salt] + [4 байта IP]
        var ipBytes   = IPAddress.Parse(assignedIp).GetAddressBytes();
        var handshake = new byte[36];
        salt.CopyTo(handshake, 0);
        ipBytes.CopyTo(handshake, 32);
        await stream.WriteAsync(handshake, ct);

        // 2. Деривируем ключи с той же солью
        var sharedSecret = KeyExchange.ComputeSharedSecret(_serverPrivateKey, clientPublicKey);
        var keys         = KeyDerivation.DeriveSessionKeys(sharedSecret, salt);

        // Инвертируем ключи для серверной стороны:
        // Клиент: Send=A, Recv=B → Сервер: Send=B, Recv=A
        var serverKeys = new SessionKeys(
            SendKey: keys.RecvKey,
            RecvKey: keys.SendKey,
            SendIv:  keys.RecvIv,
            RecvIv:  keys.SendIv
        );

        // 3. Уникальный IP для этого клиента через атомарный счётчик
        _logger.LogInformation("Assigning TUN {Name} ({Ip})", tunName, assignedIp);
        var tun = new TunInterface(_loggerFactory.CreateLogger<TunInterface>());
        try
        {
            // 4. Открываем TUN интерфейс для этого клиента

            await tun.OpenAsync(tunName, _config.TunAddress, "255.255.255.0");
            // Маршрут к клиенту через этот TUN
            RunCmd("ip", $"route add {assignedIp}/32 dev {tunName}");
            _logger.LogInformation("Route added: {Ip} → {Tun}", assignedIp, tunName);

            // 5. Запускаем туннель
            var sessionId = (uint)Random.Shared.Next();
            var framer = new VpnFramer(serverKeys, sessionId, _logger);
            var tunnel = new VpnTunnel(framer, tun, stream, _logger);

            await tunnel.RunAsync(ct);
        }
        catch (Exception ex)
        {
            _logger.LogError("Tunnel error for {Name}: {Msg}", tunName, ex.Message);
        }
        finally
        {
            await tun.DisposeAsync();
        }
    }
    
    private static void RunCmd(string cmd, string args)
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

    /// <summary>
    /// Форвардим соединение к реальному HTTPS серверу.
    /// DPI видит: клиент → легитимный сертификат → обычный HTTPS.
    /// </summary>
    private async Task ForwardToRealServerAsync(NetworkStream clientStream, byte[] buffered, CancellationToken ct)
    {
        try
        {
            using var real = new TcpClient();
            await real.ConnectAsync(_config.SniDomain, 443, ct);
            using var realStream = real.GetStream();

            // Отправляем буферизованный ClientHello реальному серверу
            await realStream.WriteAsync(buffered, ct);

            await Task.WhenAll(
                CopyStreamAsync(clientStream, realStream, ct),
                CopyStreamAsync(realStream, clientStream, ct)
            );
        }
        catch (Exception ex)
        {
            _logger.LogDebug("Forward error: {Msg}", ex.Message);
        }
    }

    /// <summary>Копирует данные из одного потока в другой.</summary>
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
        catch
        {
            // ignored
        }
    }

    /// <summary>Вычисляет публичный ключ X25519 из приватного.</summary>
    private static byte[] X25519PublicFromPrivate(byte[] privateKey)
    {
        var priv  = new Org.BouncyCastle.Crypto.Parameters.X25519PrivateKeyParameters(privateKey, 0);
        var pub   = priv.GeneratePublicKey();
        var bytes = new byte[32];
        pub.Encode(bytes, 0);
        return bytes;
    }
}
