using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace CyberiusVPN.Core.Tun;

/// <summary>
/// Кросс-платформенный TUN интерфейс.
/// Windows: WinTun API (тот же драйвер что у WireGuard, требует wintun.dll)
/// Linux:   /dev/net/tun через ioctl системный вызов
/// </summary>
public sealed class TunInterface : IAsyncDisposable
{
    private readonly ILogger _logger;
    private ITunDriver       _driver = null!;

    /// <summary>Имя сетевого интерфейса.</summary>
    public string Name    { get; private set; } = "";

    /// <summary>IP адрес интерфейса.</summary>
    public string Address { get; private set; } = "";

    /// <summary>MTU интерфейса.</summary>
    public int    Mtu     { get; private set; }

    /// <param name="logger">Логгер.</param>
    public TunInterface(ILogger logger) => _logger = logger;

    /// <summary>
    /// Открывает TUN интерфейс и настраивает IP адрес.
    /// </summary>
    /// <param name="name">Имя интерфейса (vpn0, vpns1 и т.д.).</param>
    /// <param name="address">IP адрес (например 10.8.0.2).</param>
    /// <param name="mask">Маска подсети (например 255.255.255.0).</param>
    /// <param name="mtu">MTU (по умолчанию 1500).</param>
    public async Task OpenAsync(string name, string address, string mask, int mtu = 1500)
    {
        Name    = name;
        Address = address;
        Mtu     = mtu;

        _driver = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? new WindowsTunDriver(_logger)
            : new LinuxTunDriver(_logger);

        await _driver.OpenAsync(name, address, mask, mtu);
        _logger.LogInformation("TUN interface {Name} opened: {Address}", name, address);
    }

    /// <summary>Читает следующий IP-пакет из TUN интерфейса.</summary>
    public Task<byte[]> ReadPacketAsync(CancellationToken ct)
        => _driver.ReadPacketAsync(ct);

    /// <summary>Записывает IP-пакет в TUN интерфейс.</summary>
    public Task WritePacketAsync(byte[] packet, CancellationToken ct)
        => _driver.WritePacketAsync(packet, ct);

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (_driver is IAsyncDisposable d) await d.DisposeAsync();
    }
}
