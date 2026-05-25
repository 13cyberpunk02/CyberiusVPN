using System.Buffers;
using System.Net;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;

namespace CyberiusVPN.Core.Tun;

internal sealed class LinuxTunDriver(ILogger logger) : ITunDriver
{
    private FileStream? _stream;
    private string      _name = "";

    [DllImport("libc", SetLastError = true)]
    private static extern int ioctl(int fd, uint request, ref IfReq ifr);

    [DllImport("libc", SetLastError = true)]
    private static extern int open([MarshalAs(UnmanagedType.LPStr)] string path, int flags);

    private const uint  TUNSETIFF = 0x400454CA;
    private const short IFF_TUN   = 0x0001;
    private const short IFF_NO_PI = 0x1000;
    private const int   O_RDWR    = 2;

    private readonly byte[] _readBuffer = new byte[65535];

    // Channel для чтения из TUN
    private readonly Channel<(byte[] data, int length)> _readChannel =
        Channel.CreateBounded<(byte[], int)>(
            new BoundedChannelOptions(128)
            {
                FullMode = BoundedChannelFullMode.DropOldest
            });

    // Channel для записи в TUN — отдельный поток без Task.Run
    private readonly Channel<byte[]> _writeChannel =
        Channel.CreateBounded<byte[]>(
            new BoundedChannelOptions(256)
            {
                FullMode = BoundedChannelFullMode.DropOldest
            });

    private Thread?                      _readerThread;
    private Thread?                      _writerThread;
    private readonly CancellationTokenSource _cts = new();

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
        _name = name;
        var fd = open("/dev/net/tun", O_RDWR);
        if (fd < 0)
            throw new IOException($"Cannot open /dev/net/tun, errno={Marshal.GetLastWin32Error()}");

        var ifr = new IfReq { Name = name, Flags = IFF_TUN | IFF_NO_PI, Padding = new byte[22] };
        if (ioctl(fd, TUNSETIFF, ref ifr) < 0)
            throw new IOException($"ioctl TUNSETIFF failed: {Marshal.GetLastWin32Error()}");

        var handle = new Microsoft.Win32.SafeHandles.SafeFileHandle(new IntPtr(fd), ownsHandle: true);
        _stream    = new FileStream(handle, FileAccess.ReadWrite, bufferSize: 1, isAsync: false);

        ConfigureInterface(name, address, mask, mtu);

        _readerThread = new Thread(ReaderLoop)
        {
            IsBackground = true,
            Name         = $"TUN-Reader-{name}"
        };
        _readerThread.Start();

        _writerThread = new Thread(WriterLoop)
        {
            IsBackground = true,
            Name         = $"TUN-Writer-{name}"
        };
        _writerThread.Start();

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

                var pooled = ArrayPool<byte>.Shared.Rent(read);
                Buffer.BlockCopy(_readBuffer, 0, pooled, 0, read);

                if (!_readChannel.Writer.TryWrite((pooled, read)))
                    ArrayPool<byte>.Shared.Return(pooled);
            }
            catch (Exception ex) when (!_cts.Token.IsCancellationRequested)
            {
                logger.LogWarning("TUN read error: {Msg}", ex.Message);
                break;
            }
        }
        _readChannel.Writer.TryComplete();
    }

    private void WriterLoop()
    {
        while (!_cts.Token.IsCancellationRequested)
        {
            try
            {
                if (_writeChannel.Reader.TryRead(out var packet))
                {
                    _stream!.Write(packet, 0, packet.Length);
                }
                else
                {
                    // Блокируем поток пока нет данных — не жжём CPU
                    _writeChannel.Reader.WaitToReadAsync(_cts.Token)
                        .AsTask().GetAwaiter().GetResult();
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) when (!_cts.Token.IsCancellationRequested)
            {
                logger.LogWarning("TUN write error: {Msg}", ex.Message);
                break;
            }
        }
    }

    public async Task<byte[]> ReadPacketAsync(CancellationToken ct)
    {
        var (pooled, length) = await _readChannel.Reader.ReadAsync(ct);
        var result = new byte[length];
        Buffer.BlockCopy(pooled, 0, result, 0, length);
        ArrayPool<byte>.Shared.Return(pooled);
        return result;
    }

    // Без Task.Run — просто кладём в channel, WriterLoop запишет
    public Task WritePacketAsync(byte[] packet, CancellationToken ct)
    {
        _writeChannel.Writer.TryWrite(packet);
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
            bits += BitOperations.PopCount(b);
        return bits;
    }

    private static void Run(string cmd, string args) =>
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName               = cmd,
            Arguments              = args,
            RedirectStandardOutput = true,
            RedirectStandardError  = true,
            UseShellExecute        = false
        })?.WaitForExit();

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();
        if (_stream != null) await _stream.DisposeAsync();
        if (!string.IsNullOrEmpty(_name))
            Run("ip", $"link del {_name}");
    }
}