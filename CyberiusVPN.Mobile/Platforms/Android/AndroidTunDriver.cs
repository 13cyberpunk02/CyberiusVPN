using Android.Net;
using Android.OS;
using CyberiusVPN.Core.Tun;
using System.Threading.Channels;

namespace CyberiusVPN.Mobile.Platforms.Android;


/// <summary>
/// Android TUN драйвер через VpnService.Builder.
/// Файловый дескриптор TUN получается от Android VpnService,
/// чтение/запись через ParcelFileDescriptor.
/// </summary>
public sealed class AndroidTunDriver : ITunDriver
{
    private readonly VpnService _vpnService;
    private ParcelFileDescriptor? _tunFd;
    private Stream? _tunStream;
    private readonly byte[] _readBuffer = new byte[65535];
    private readonly Channel<byte[]> _readChannel;
    private readonly Channel<byte[]> _writeChannel;
    private Thread? _readerThread;
    private Thread? _writerThread;
    private readonly CancellationTokenSource _cts = new();

    public AndroidTunDriver(VpnService vpnService)
    {
        _vpnService = vpnService;

        _readChannel = Channel.CreateBounded<byte[]>(
            new BoundedChannelOptions(256)
            {
                FullMode = BoundedChannelFullMode.DropOldest
            });

        _writeChannel = Channel.CreateBounded<byte[]>(
            new BoundedChannelOptions(256)
            {
                FullMode = BoundedChannelFullMode.DropOldest
            });
    }

    public Task OpenAsync(string name, string address, string mask, int mtu)
    {
        var builder = new VpnService.Builder(_vpnService)
            .SetSession("CyberiusVPN")
            .AddAddress(address, 24)
            .SetMtu(mtu)
            .SetBlocking(true)
            .AddDnsServer("8.8.8.8")
            .AddDnsServer("8.8.4.4");

        // Весь трафик через VPN — два маршрута покрывают 0.0.0.0/0
        builder.AddRoute("0.0.0.0", 1);
        builder.AddRoute("128.0.0.0", 1);

        // Исключаем адрес сервера чтобы не было петли
        // Android 21+ поддерживает AddDisallowedApplication
        // но проще исключить через AllowBypass
        builder.AllowBypass();

        _tunFd = builder.Establish()
            ?? throw new InvalidOperationException("Establish() вернул null");

        var fd = _tunFd.DetachFd();

        var safeHandle = new Microsoft.Win32.SafeHandles.SafeFileHandle(
            new IntPtr(fd), ownsHandle: true);

        _tunStream = new FileStream(
            safeHandle,
            FileAccess.ReadWrite,
            bufferSize: 1,
            isAsync: false);

        _readerThread = new Thread(ReaderLoop)
        {
            IsBackground = true,
            Name = "AndroidTUN-Reader"
        };
        _readerThread.Start();

        _writerThread = new Thread(WriterLoop)
        {
            IsBackground = true,
            Name = "AndroidTUN-Writer"
        };
        _writerThread.Start();

        return Task.CompletedTask;
    }

    private void ReaderLoop()
    {
        while (!_cts.Token.IsCancellationRequested)
        {
            try
            {
                int read = _tunStream!.Read(_readBuffer.AsSpan());
                if (read <= 0) continue;

                var packet = new byte[read];
                Buffer.BlockCopy(_readBuffer, 0, packet, 0, read);
                _readChannel.Writer.TryWrite(packet);
            }
            catch (Exception) when (!_cts.Token.IsCancellationRequested)
            {
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
                // Блокируем поток пока нет пакетов — без spin loop
                if (_writeChannel.Reader.TryRead(out var packet))
                {
                    _tunStream!.Write(packet, 0, packet.Length);
                }
                else
                {
                    // Ждём следующего пакета без сжигания CPU
                    var waitTask = _writeChannel.Reader.WaitToReadAsync(_cts.Token).AsTask();
                    waitTask.GetAwaiter().GetResult();
                }
            }
            catch (System.OperationCanceledException) { break; }
            catch (Exception) when (!_cts.Token.IsCancellationRequested) { break; }
        }
    }

    public async Task<byte[]> ReadPacketAsync(CancellationToken ct)
        => await _readChannel.Reader.ReadAsync(ct);

    public Task WritePacketAsync(byte[] packet, CancellationToken ct)
    {
        _writeChannel.Writer.TryWrite(packet);
        return Task.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();
        _tunStream?.Dispose();
    }
}