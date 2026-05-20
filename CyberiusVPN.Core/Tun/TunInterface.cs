using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace CyberiusVPN.Core.Tun;

/// <summary>
/// Кросс-платформенный TUN интерфейс.
/// Windows: WinTun (тот же драйвер что у WireGuard)
/// Linux:   /dev/net/tun через ioctl
/// </summary>
public sealed class TunInterface(ILogger logger) : IAsyncDisposable
{
    private          ITunDriver _driver = null!;

    public string Name       { get; private set; } = "";
    public string Address    { get; private set; } = "";
    public int    Mtu        { get; private set; }

    public async Task OpenAsync(string name, string address, string mask, int mtu = 1500)
    {
        Name    = name;
        Address = address;
        Mtu     = mtu;

        _driver = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? new WindowsTunDriver(logger)
            : new LinuxTunDriver(logger);

        await _driver.OpenAsync(name, address, mask, mtu);
        logger.LogInformation("TUN interface {Name} opened: {Address}", name, address);
    }

    public Task<byte[]> ReadPacketAsync(CancellationToken ct)  => _driver.ReadPacketAsync(ct);
    public Task         WritePacketAsync(byte[] packet, CancellationToken ct) => _driver.WritePacketAsync(packet, ct);

    public async ValueTask DisposeAsync()
    {
        if (_driver is IAsyncDisposable d) await d.DisposeAsync();
    }
}