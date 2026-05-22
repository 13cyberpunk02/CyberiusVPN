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

    // Постоянный буфер чтения — не аллоцируем на каждый пакет
    private readonly byte[] _readBuffer = new byte[65535];

    // Channel для передачи пакетов из фонового потока в async pipeline
    private readonly Channel<byte[]> _readChannel =
        Channel.CreateBounded<byte[]>(
            new BoundedChannelOptions(256)
            {
                FullMode = System.Threading.Channels.BoundedChannelFullMode.DropOldest
            });

    private Thread? _readerThread;
    private CancellationTokenSource _cts = new();

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

        var ifr = new IfReq
        {
            Name = name,
            Flags = IFF_TUN | IFF_NO_PI,
            Padding = new byte[22]
        };

        if (ioctl(fd, TUNSETIFF, ref ifr) < 0)
            throw new IOException($"ioctl TUNSETIFF failed: {Marshal.GetLastWin32Error()}");

        // bufferSize: 1 отключает внутренний буфер FileStream
        // TUN устройство нельзя читать через буферизованный поток
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

    /// <summary>
    /// Постоянный цикл чтения в отдельном потоке.
    /// Блокирующий Read не мешает async pipeline — он в своём потоке.
    /// </summary>
    private void ReaderLoop()
    {
        while (!_cts.Token.IsCancellationRequested)
        {
            try
            {
                // Читаем напрямую через Span без внутреннего буфера
                int read = _stream!.Read(_readBuffer.AsSpan());
                if (read <= 0) continue;

                var packet = new byte[read];
                Buffer.BlockCopy(_readBuffer, 0, packet, 0, read);
                _readChannel.Writer.TryWrite(packet);
            }
            catch (Exception ex) when (!_cts.Token.IsCancellationRequested)
            {
                logger.LogWarning("TUN read error: {Msg}", ex.Message);
                break;
            }
        }

        _readChannel.Writer.TryComplete();
    }

    /// <summary>
    /// Async чтение из channel — не блокирует thread pool.
    /// </summary>
    public async Task<byte[]> ReadPacketAsync(CancellationToken ct)
    {
        return await _readChannel.Reader.ReadAsync(ct);
    }

    public Task WritePacketAsync(byte[] packet, CancellationToken ct) => Task.Run(() =>
    {
        _stream!.Write(packet, 0, packet.Length);
        // Убираем Flush — TUN не буферизует, Flush лишний syscall
    }, ct);

    private static void ConfigureInterface(string name, string address, string mask, int mtu)
    {
        var prefixLen = MaskToCidr(mask);
        Run("ip", $"addr add {address}/{prefixLen} dev {name}");
        Run("ip", $"link set {name} mtu {mtu} up");
    }

    private static int MaskToCidr(string mask)
    {
        var bytes = IPAddress.Parse(mask).GetAddressBytes();
        var bits = 0;
        foreach (var b in bytes)
            bits += BitOperations.PopCount(b);
        return bits;
    }

    private static void Run(string cmd, string args)
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = cmd,
            Arguments = args,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        })?.WaitForExit();
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();
        if (_stream != null) await _stream.DisposeAsync();
        if (!string.IsNullOrEmpty(_name))
            Run("ip", $"link del {_name}");
    }
}