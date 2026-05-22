using CyberiusVPN.Core.Models;
using CyberiusVPN.Core.Tun;
using Microsoft.Extensions.Logging;

namespace CyberiusVPN.Core.Transport;

/// <summary>
/// Двунаправленный VPN туннель: TUN интерфейс ↔ зашифрованный TCP поток.
///
/// Три параллельных задачи:
/// 1. Outbound: читает IP-пакеты из TUN, шифрует, отправляет на сервер
/// 2. Inbound:  получает кадры от сервера, расшифровывает, пишет в TUN
/// 3. Keepalive: каждые 25 секунд отправляет пустой пакет чтобы NAT не закрыл сессию
/// </summary>
public sealed class VpnTunnel
{
    private readonly ILogger _logger;
    private readonly VpnFramer _framer;
    private readonly ITunDriver _tun;
    private readonly Stream _transport;

    /// <summary>
    /// Создаёт туннель.
    /// </summary>
    /// <param name="framer">Framer для шифрования/расшифровки кадров.</param>
    /// <param name="tun">TUN интерфейс для чтения/записи IP-пакетов.</param>
    /// <param name="transport">TCP поток к удалённой стороне.</param>
    /// <param name="logger">Логгер.</param>
    public VpnTunnel(VpnFramer framer, ITunDriver tun, Stream transport, ILogger logger)
    {
        _framer = framer;
        _tun = tun;
        _transport = transport;
        _logger = logger;
    }

    /// <summary>
    /// Запускает все три задачи параллельно.
    /// Первая завершившаяся задача останавливает остальные.
    /// </summary>
    /// <param name="ct">Токен отмены.</param>
    public async Task RunAsync(CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        _logger.LogInformation("VPN tunnel started (session {Id:X8})", _framer.SessionId);

        try
        {
            await Task.WhenAny(
                PumpOutboundAsync(cts.Token),
                PumpInboundAsync(cts.Token),
                KeepaliveLoopAsync(cts.Token)
            );
        }
        finally
        {
            await cts.CancelAsync();
            _logger.LogInformation("VPN tunnel stopped");
        }
    }

    /// <summary>TUN → шифруем → сервер.</summary>
    private async Task PumpOutboundAsync(CancellationToken ct)
    {
        // Канал между читателем TUN и отправителем
        var channel = System.Threading.Channels.Channel.CreateBounded<byte[]>(
            new System.Threading.Channels.BoundedChannelOptions(32)
            {
                FullMode = System.Threading.Channels.BoundedChannelFullMode.DropOldest
            });

        // Читатель TUN — просто читает пакеты
        var reader = Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                var packet = await _tun.ReadPacketAsync(ct);
                if (packet.Length > 0)
                    await channel.Writer.WriteAsync(packet, ct);
            }
        }, ct);

        // Отправитель — шифрует и отправляет
        var sender = Task.Run(async () =>
        {
            await foreach (var packet in channel.Reader.ReadAllAsync(ct))
            {
                await _framer.SendPacketAsync(_transport, packet, PacketType.Data, ct);
            }
        }, ct);

        await Task.WhenAll(reader, sender);
    }

    /// <summary>Сервер → расшифровываем → TUN.</summary>
    private async Task PumpInboundAsync(CancellationToken ct)
    {
        // Channel между получателем TCP и записью в TUN
        var channel = System.Threading.Channels.Channel.CreateBounded<byte[]>(
            new System.Threading.Channels.BoundedChannelOptions(64)
            {
                FullMode = System.Threading.Channels.BoundedChannelFullMode.DropOldest
            });

        // Получатель — читает и расшифровывает из TCP
        var receiver = Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                var result = await _framer.ReceivePacketAsync(_transport, ct);
                if (result is null) break;

                var (type, payload) = result.Value;
                if (type == PacketType.Data && payload.Length > 0)
                    await channel.Writer.WriteAsync(payload, ct);
            }

            channel.Writer.TryComplete();
        }, ct);

        // Писатель — пишет в TUN
        var writer = Task.Run(async () =>
        {
            await foreach (var payload in channel.Reader.ReadAllAsync(ct))
            {
                await _tun.WritePacketAsync(payload, ct);
                _logger.LogTrace("← {Bytes} bytes", payload.Length);
            }
        }, ct);

        await Task.WhenAll(receiver, writer);
    }

    /// <summary>Keepalive каждые 25 секунд чтобы NAT не закрыл соединение.</summary>
    private async Task KeepaliveLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromSeconds(25), ct);
            await _framer.SendPacketAsync(_transport, Array.Empty<byte>(), PacketType.Keepalive, ct);
            _logger.LogTrace("↔ keepalive");
        }
    }
}