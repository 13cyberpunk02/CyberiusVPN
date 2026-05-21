using CyberiusVPN.Core.Models;

namespace CyberiusVPN.Core.Transport;

/// <summary>
/// Активная VPN сессия одного клиента на сервере.
/// Хранит состояние подключения: ключи, framer, статистику.
/// </summary>
public sealed class VpnSession : IAsyncDisposable
{
    /// <summary>Уникальный идентификатор сессии.</summary>
    public uint SessionId { get; }

    /// <summary>Сессионные ключи шифрования.</summary>
    public SessionKeys Keys { get; }

    /// <summary>Framer для упаковки/распаковки кадров.</summary>
    public VpnFramer Framer { get; }

    /// <summary>Время установки соединения (UTC).</summary>
    public DateTime ConnectedAt { get; } = DateTime.UtcNow;

    /// <summary>Активна ли сессия.</summary>
    public bool IsActive { get; private set; } = true;

    /// <summary>Количество отправленных байт.</summary>
    public long BytesSent { get; set; }

    /// <summary>Количество полученных байт.</summary>
    public long BytesReceived { get; set; }

    private readonly CancellationTokenSource _cts = new();

    /// <summary>Токен отмены сессии.</summary>
    public CancellationToken Token => _cts.Token;

    /// <summary>
    /// Создаёт новую сессию.
    /// </summary>
    public VpnSession(uint sessionId, SessionKeys keys, VpnFramer framer)
    {
        SessionId = sessionId;
        Keys      = keys;
        Framer    = framer;
    }

    /// <summary>Останавливает сессию.</summary>
    public void Stop()
    {
        IsActive = false;
        _cts.Cancel();
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        Stop();
        _cts.Dispose();
        await Task.CompletedTask;
    }

    /// <inheritdoc/>
    public override string ToString() =>
        $"Session[{SessionId:X8}] since {ConnectedAt:HH:mm:ss} " +
        $"↑{BytesSent / 1024}KB ↓{BytesReceived / 1024}KB";
}
