using System.Diagnostics;
using System.Net;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;

namespace CyberiusVPN.Core.Tun;

/// <summary>
/// Linux TUN драйвер через /dev/net/tun.
/// Требует root или CAP_NET_ADMIN.
/// FileStream открывается в синхронном режиме (TUN fd не поддерживает overlapped I/O),
/// чтение/запись выполняются в Task.Run для не-блокирующей async работы.
/// </summary>
internal sealed class LinuxTunDriver(ILogger logger) : ITunDriver
{
    private FileStream? _stream;
    private string _name = "";

    [DllImport("libc", SetLastError = true)]
    private static extern int ioctl(int fd, uint request, ref IfReq ifr);

    [DllImport("libc", SetLastError = true)]
    private static extern int open([MarshalAs(UnmanagedType.LPStr)] string path, int flags);

    private const uint TUNSETIFF = 0x400454CA;
    private const short IFF_TUN = 0x0001;
    private const short IFF_NO_PI = 0x1000;
    private const int O_RDWR = 2;

    private readonly byte[] _readBuffer = new byte[65535];
    private readonly byte[] _writeBuffer = new byte[65535];

    // Один channel для чтения — без WriterLoop, пишем напрямую
    private readonly Channel<(byte[] data, int length)> _readChannel =
        Channel.CreateBounded<(byte[], int)>(
            new BoundedChannelOptions(128)
            {
                FullMode = BoundedChannelFullMode.DropOldest
            });

    // Для записи — SemaphoreSlim вместо channel
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private Thread? _readerThread;
    private readonly CancellationTokenSource _cts = new();

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    private struct IfReq
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
        public string Name;
        public short Flags;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 22)]
        public byte[] Padding;
    }

    public Task OpenAsync(string name, string address, string mask, int mtu)
    {
        _name = name;
        var fd = open("/dev/net/tun", O_RDWR);
        if (fd < 0)
            throw new IOException($"Cannot open /dev/net/tun, errno={Marshal.GetLastWin32Error()}");

        var ifr = new IfReq { Name = name, Flags = IFF_TUN | IFF_NO_PI, Padding = new byte[22] };
        if (ioctl(fd, TUNSETIFF, ref ifr) < 0)
            throw new IOException($"ioctl TUNSETIFF failed: {Marshal.GetLastWin32Error()}");

        var handle = new Microsoft.Win32.SafeHandles.SafeFileHandle(new IntPtr(fd), ownsHandle: true);
        _stream = new FileStream(handle, FileAccess.ReadWrite, bufferSize: 1, isAsync: false);

        ConfigureInterface(name, address, mask, mtu);

        _readerThread = new Thread(ReaderLoop)
        {
            IsBackground = true,
            Name = $"TUN-Reader-{name}"
        };
        _readerThread.Start();

        logger.LogInformation("Linux TUN {Name} configured", name);
        return Task.CompletedTask;
    }

    private void ReaderLoop()
    {
        while (!_cts.Token.IsCancellationRequested)
        {
            try
            {
                int read = _stream!.Read(_readBuffer.AsSpan());
                if (read <= 0) continue;

                // Аллоцируем только если channel не переполнен
                if (_readChannel.Writer.TryWrite((_readBuffer[..read], read)))
                    continue;

                // Channel переполнен — пропускаем пакет (drop)
            }
            catch (Exception ex) when (!_cts.Token.IsCancellationRequested)
            {
                logger.LogWarning("TUN read error: {Msg}", ex.Message);
                break;
            }
        }
        _readChannel.Writer.TryComplete();
    }

    public async Task<byte[]> ReadPacketAsync(CancellationToken ct)
    {
        var (data, _) = await _readChannel.Reader.ReadAsync(ct);
        return data;
    }

    // Запись напрямую без WriterLoop и channel — меньше overhead
    public async Task WritePacketAsync(byte[] packet, CancellationToken ct)
    {
        await _writeLock.WaitAsync(ct);
        try
        {
            await Task.Run(() => _stream!.Write(packet, 0, packet.Length), ct);
        }
        finally
        {
            _writeLock.Release();
        }
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
        int bits = 0;
        foreach (var b in bytes)
            bits += System.Numerics.BitOperations.PopCount(b);
        return bits;
    }

    private static void Run(string cmd, string args) =>
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = cmd,
            Arguments = args,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        })?.WaitForExit();

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();
        if (_stream != null) await _stream.DisposeAsync();
        if (!string.IsNullOrEmpty(_name))
            Run("ip", $"link del {_name}");
    }
}