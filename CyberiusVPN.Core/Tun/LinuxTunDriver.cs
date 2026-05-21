using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace CyberiusVPN.Core.Tun;

internal sealed class LinuxTunDriver(ILogger logger) : ITunDriver
{
    private FileStream?      _stream;

    // P/Invoke для Linux ioctl
    [DllImport("libc", SetLastError = true)]
    private static extern int ioctl(int fd, uint request, ref IfReq ifr);

    [DllImport("libc", SetLastError = true)]
    private static extern int open([MarshalAs(UnmanagedType.LPStr)] string path, int flags);

    private const uint TUNSETIFF   = 0x400454CA;
    private const short IFF_TUN   = 0x0001;
    private const short IFF_NO_PI = 0x1000;  // без packet info заголовка
    private const int O_RDWR      = 2;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    private struct IfReq
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
        public string Name;
        public short  Flags;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 22)]
        public byte[] Padding;
    }

    public Task OpenAsync(string name, string address, string mask, int mtu)
    {
        int fd = open("/dev/net/tun", O_RDWR);
        if (fd < 0)
            throw new IOException($"Cannot open /dev/net/tun. Run as root? errno={Marshal.GetLastWin32Error()}");

        var ifr = new IfReq
        {
            Name    = name,
            Flags   = IFF_TUN | IFF_NO_PI,
            Padding = new byte[22]
        };

        if (ioctl(fd, TUNSETIFF, ref ifr) < 0)
            throw new IOException($"ioctl TUNSETIFF failed: {Marshal.GetLastWin32Error()}");

        // SafeFileHandle из fd
        var handle  = new Microsoft.Win32.SafeHandles.SafeFileHandle(new IntPtr(fd), ownsHandle: true);
        _stream     = new FileStream(handle, FileAccess.ReadWrite, bufferSize: 4096, isAsync: false);

        // Настраиваем IP адрес через ip команду
        ConfigureInterface(name, address, mask, mtu);

        logger.LogInformation("Linux TUN {Name} configured", name);
        return Task.CompletedTask;
    }

    private static void ConfigureInterface(string name, string address, string mask, int mtu)
    {
        // Вычисляем prefix length из маски
        var prefixLen = MaskToCidr(mask);

        RunCommand("ip", $"addr add {address}/{prefixLen} dev {name}");
        RunCommand("ip", $"link set {name} mtu {mtu} up");
    }

    private static int MaskToCidr(string mask)
    {
        var bytes = IPAddress.Parse(mask).GetAddressBytes();
        int bits  = 0;
        foreach (var b in bytes)
            bits += System.Numerics.BitOperations.PopCount(b);
        return bits;
    }

    private static void RunCommand(string cmd, string args)
    {
        var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName  = cmd, Arguments = args,
            RedirectStandardOutput = true, RedirectStandardError = true
        })!;
        p.WaitForExit();
    }

    public Task<byte[]> ReadPacketAsync(CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var buf  = new byte[65535];
            int read = _stream!.Read(buf, 0, buf.Length);
            return buf[..read];
        }, ct);
    }

    public Task WritePacketAsync(byte[] packet, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            _stream!.Write(packet, 0, packet.Length);
            _stream.Flush();
        }, ct);
    }

    public async ValueTask DisposeAsync()
    {
        if (_stream != null) await _stream.DisposeAsync();
    }
}