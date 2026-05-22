using Microsoft.Extensions.Logging;

namespace CyberiusVPN.Core.Tun;

/// <summary>
/// Кросс-платформенный TUN интерфейс.
/// Драйвер либо создаётся автоматически по платформе,
/// либо передаётся явно (для Android — из VpnService).
/// </summary>
public sealed class TunInterface : ITunDriver
{
    private readonly ILogger     _logger;
    private readonly ITunDriver? _externalDriver;
    private ITunDriver           _driver = null!;

    public string Name    { get; private set; } = "";
    public string Address { get; private set; } = "";
    public int    Mtu     { get; private set; }

    public TunInterface(ILogger logger) => _logger = logger;

    public TunInterface(ILogger logger, ITunDriver driver)
    {
        _logger         = logger;
        _externalDriver = driver;
    }

    public async Task OpenAsync(string name, string address, string mask, int mtu = 1500)
    {
        Name    = name;
        Address = address;
        Mtu     = mtu;

        if (_externalDriver is not null)
        {
            _driver = _externalDriver;
        }
        else
        {
#if !ANDROID
            _driver = System.Runtime.InteropServices.RuntimeInformation
                .IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows)
                ? new WindowsTunDriver(_logger)
                : new LinuxTunDriver(_logger);
#else
            throw new InvalidOperationException(
                "На Android передайте ITunDriver явно через конструктор");
#endif
        }

        await _driver.OpenAsync(name, address, mask, mtu);
        _logger.LogInformation("TUN interface {Name} opened: {Address}", name, address);
    }

    public Task<byte[]> ReadPacketAsync(CancellationToken ct)
        => _driver.ReadPacketAsync(ct);

    public Task WritePacketAsync(byte[] packet, CancellationToken ct)
        => _driver.WritePacketAsync(packet, ct);

    public async ValueTask DisposeAsync()
    {
        if (_driver is IAsyncDisposable d) await d.DisposeAsync();
    }
}