using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace CyberiusVPN.Core.Tun;

/// <summary>
/// Linux TUN драйвер через /dev/net/tun.
/// Требует root или CAP_NET_ADMIN.
/// FileStream открывается в синхронном режиме (TUN fd не поддерживает overlapped I/O),
/// чтение/запись выполняются в Task.Run для не-блокирующей async работы.
/// </summary>
internal sealed class LinuxTunDriver : ITunDriver
{
    private readonly ILogger _logger;
    private FileStream?      _stream;

    [DllImport("libc", SetLastError = true)]
    private static extern int ioctl(int fd, uint request, ref IfReq ifr);

    [DllImport("libc", SetLastError = true)]
    private static extern int open([MarshalAs(UnmanagedType.LPStr)] string path, int flags);

    private const uint  TUNSETIFF  = 0x400454CA;
    private const short IFF_TUN    = 0x0001;
    private const short IFF_NO_PI  = 0x1000;
    private const int   O_RDWR     = 2;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    private struct IfReq
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
        public string Name;
        public short  Flags;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 22)]
        public byte[] Padding;
    }

    public LinuxTunDriver(ILogger logger) => _logger = logger;

    public Task OpenAsync(string name, string address, string mask, int mtu)
    {
        int fd = open("/dev/net/tun", O_RDWR);
        if (fd < 0)
            throw new IOException($"Cannot open /dev/net/tun (run as root?), errno={Marshal.GetLastWin32Error()}");

        var ifr = new IfReq
        {
            Name    = name,
            Flags   = IFF_TUN | IFF_NO_PI,
            Padding = new byte[22]
        };

        if (ioctl(fd, TUNSETIFF, ref ifr) < 0)
            throw new IOException($"ioctl TUNSETIFF failed: {Marshal.GetLastWin32Error()}");

        // Синхронный режим FileStream — TUN fd не поддерживает overlapped I/O
        var handle = new Microsoft.Win32.SafeHandles.SafeFileHandle(new IntPtr(fd), ownsHandle: true);
        _stream    = new FileStream(handle, FileAccess.ReadWrite, bufferSize: 4096, isAsync: false);

        ConfigureInterface(name, address, mask, mtu);

        _logger.LogInformation("Linux TUN {Name} configured", name);
        return Task.CompletedTask;
    }

    private static void ConfigureInterface(string name, string address, string mask, int mtu)
    {
        var prefixLen = MaskToCidr(mask);
        Run("ip", $"addr add {address}/{prefixLen} dev {name}");
        Run("ip", $"link set {name} mtu {mtu} up");
    }

    private static int MaskToCidr(string mask)
    {
        var bytes = IPAddress.Parse(mask).GetAddressBytes();
        int bits  = 0;
        foreach (var b in bytes)
            bits += System.Numerics.BitOperations.PopCount(b);
        return bits;
    }

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

    // Синхронное чтение в Task.Run — не блокирует thread pool
    public Task<byte[]> ReadPacketAsync(CancellationToken ct) => Task.Run(() =>
    {
        var buf  = new byte[65535];
        int read = _stream!.Read(buf, 0, buf.Length);
        return buf[..read];
    }, ct);

    public Task WritePacketAsync(byte[] packet, CancellationToken ct) => Task.Run(() =>
    {
        _stream!.Write(packet, 0, packet.Length);
        _stream.Flush();
    }, ct);

    public async ValueTask DisposeAsync()
    {
        if (_stream != null) await _stream.DisposeAsync();
    }
}