using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace CyberiusVPN.Core.Tun;

// ─────────────────────────────────────────────────────────────────────────────
// WINDOWS: WinTun API
// Скачать wintun.dll: https://www.wintun.net/
// Требует запуска от Администратора
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Windows TUN драйвер через WinTun API.
/// wintun.dll должен находиться рядом с исполняемым файлом.
/// Требует прав Администратора.
/// </summary>
internal sealed class WindowsTunDriver(ILogger logger) : ITunDriver
{
    [DllImport("wintun.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr WintunCreateAdapter(
        [MarshalAs(UnmanagedType.LPWStr)] string name,
        [MarshalAs(UnmanagedType.LPWStr)] string tunnelType,
        ref Guid requestedGuid);

    [DllImport("wintun.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr WintunStartSession(IntPtr adapter, uint capacity);

    [DllImport("wintun.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr WintunAllocateSendPacket(IntPtr session, uint packetSize);

    [DllImport("wintun.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void WintunSendPacket(IntPtr session, IntPtr packet);

    [DllImport("wintun.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr WintunReceivePacket(IntPtr session, out uint packetSize);

    [DllImport("wintun.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void WintunReleaseReceivePacket(IntPtr session, IntPtr packet);

    [DllImport("wintun.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr WintunGetReadWaitEvent(IntPtr session);

    [DllImport("wintun.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void WintunEndSession(IntPtr session);

    [DllImport("wintun.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void WintunCloseAdapter(IntPtr adapter);

    [DllImport("kernel32.dll")]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    private const uint WINTUN_MIN_RING_CAPACITY = 0x20000; // 128 KB

    private IntPtr _adapter;
    private IntPtr _session;
    private IntPtr _waitEvent;

    public Task OpenAsync(string name, string address, string mask, int mtu)
    {
        var guid = Guid.NewGuid();
        _adapter = WintunCreateAdapter(name, "VPN", ref guid);
        if (_adapter == IntPtr.Zero)
            throw new Exception("WintunCreateAdapter failed. Is wintun.dll present? Run as Administrator?");

        _session   = WintunStartSession(_adapter, WINTUN_MIN_RING_CAPACITY);
        _waitEvent = WintunGetReadWaitEvent(_session);

        ConfigureInterface(name, address, mask, mtu);

        logger.LogInformation("Windows WinTun {Name} configured", name);
        return Task.CompletedTask;
    }

    private static void ConfigureInterface(string name, string address, string mask, int mtu)
    {
        Run("netsh", $"interface ip set address name=\"{name}\" static {address} {mask}");
        Run("netsh", $"interface ipv4 set subinterface \"{name}\" mtu={mtu} store=persistent");
    }

    private static void Run(string cmd, string args)
    {
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName               = cmd,
            Arguments              = args,
            RedirectStandardOutput = true,
            UseShellExecute        = false
        })?.WaitForExit();
    }

    public Task<byte[]> ReadPacketAsync(CancellationToken ct) => Task.Run(() =>
    {
        while (!ct.IsCancellationRequested)
        {
            var ptr = WintunReceivePacket(_session, out uint size);
            if (ptr != IntPtr.Zero)
            {
                var data = new byte[size];
                Marshal.Copy(ptr, data, 0, (int)size);
                WintunReleaseReceivePacket(_session, ptr);
                return data;
            }
            WaitForSingleObject(_waitEvent, 100);
        }
        ct.ThrowIfCancellationRequested();
        return Array.Empty<byte>();
    }, ct);

    public Task WritePacketAsync(byte[] packet, CancellationToken ct) => Task.Run(() =>
    {
        var ptr = WintunAllocateSendPacket(_session, (uint)packet.Length);
        if (ptr == IntPtr.Zero) return; // ring buffer полон — пропускаем
        Marshal.Copy(packet, 0, ptr, packet.Length);
        WintunSendPacket(_session, ptr);
    }, ct);

    public ValueTask DisposeAsync()
    {
        if (_session  != IntPtr.Zero) WintunEndSession(_session);
        if (_adapter  != IntPtr.Zero) WintunCloseAdapter(_adapter);
        return ValueTask.CompletedTask;
    }
}