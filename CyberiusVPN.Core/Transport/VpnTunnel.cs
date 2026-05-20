using CyberiusVPN.Core.Models;
using Microsoft.Extensions.Logging;

namespace CyberiusVPN.Core.Transport;

/// <summary>
/// Пайплайн: TUN ↔ TCP туннель
/// Два параллельных цикла: TUN → сервер, сервер → TUN
/// </summary>
public sealed class VpnTunnel(VpnFramer framer, Tun.TunInterface tun, Stream transport, ILogger logger)
{
    public async Task RunAsync(CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        logger.LogInformation("VPN tunnel started (session {Id:X8})", framer.SessionId);

        try
        {
            // Запускаем три задачи, останавливаем все если одна упала
            var outbound  = PumpOutboundAsync(cts.Token);
            var inbound   = PumpInboundAsync(cts.Token);
            var keepalive = KeepaliveLoopAsync(cts.Token);

            // Первая завершившаяся задача останавливает остальные
            await Task.WhenAny(outbound, inbound, keepalive);
        }
        finally
        {
            await cts.CancelAsync();
            logger.LogInformation("VPN tunnel stopped");
        }
    }

    // TUN → шифруем → сервер
    private async Task PumpOutboundAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var packet = await tun.ReadPacketAsync(ct);
            if (packet.Length == 0) continue;

            await framer.SendPacketAsync(transport, packet, PacketType.Data, ct);
            logger.LogTrace("→ {Bytes} bytes", packet.Length);
        }
    }

    // сервер → расшифровываем → TUN
    private async Task PumpInboundAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var result = await framer.ReceivePacketAsync(transport, ct);
            if (result is null) break;

            var (type, payload) = result.Value;

            if (type == PacketType.Data)
            {
                await tun.WritePacketAsync(payload, ct);
                logger.LogTrace("← {Bytes} bytes", payload.Length);
            }
            // Keepalive — просто игнорируем, главное что пришёл
        }
    }

    // Keepalive каждые 25 сек чтобы NAT не закрыл соединение
    private async Task KeepaliveLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromSeconds(25), ct);
            await framer.SendPacketAsync(transport, Array.Empty<byte>(), PacketType.Keepalive, ct);
            logger.LogTrace("↔ keepalive");
        }
    }
}