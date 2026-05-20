using CyberiusVPN.Core.Models;

namespace CyberiusVPN.Core.Transport;

/// <summary>
/// Активная VPN сессия одного клиента на сервере.
/// Хранит состояние соединения: ключи, framer, статус.
/// </summary>
public sealed class VpnSession(uint sessionId, SessionKeys keys, VpnFramer framer) : IAsyncDisposable
{
    public uint        SessionId    { get; } = sessionId;
    public SessionKeys Keys         { get; } = keys;
    public VpnFramer   Framer       { get; } = framer;
    public DateTime    ConnectedAt  { get; } = DateTime.UtcNow;
    public bool        IsActive     { get; private set; } = true;

    // Статистика
    public long BytesSent     { get; set; }
    public long BytesReceived { get; set; }

    private readonly CancellationTokenSource _cts = new();

    public CancellationToken Token => _cts.Token;

    public void Stop()
    {
        IsActive = false;
        _cts.Cancel();
    }

    public async ValueTask DisposeAsync()
    {
        Stop();
        _cts.Dispose();
        await Task.CompletedTask;
    }

    public override string ToString() =>
        $"Session[{SessionId:X8}] since {ConnectedAt:HH:mm:ss} " +
        $"↑{BytesSent / 1024}KB ↓{BytesReceived / 1024}KB";
}
