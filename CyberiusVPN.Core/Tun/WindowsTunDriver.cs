using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace CyberiusVPN.Core.Tun;

// ─────────────────────────────────────────────
// WINDOWS: WinTun API
// Скачать wintun.dll: https://www.wintun.net/
// ─────────────────────────────────────────────
internal sealed class WindowsTunDriver(ILogger logger) : ITunDriver
{
    // WinTun P/Invoke
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

    private const uint WINTUN_MIN_RING_CAPACITY = 0x20000;   // 128 KB

    private IntPtr _adapter;
    private IntPtr _session;
    private IntPtr _waitEvent;

    public Task OpenAsync(string name, string address, string mask, int mtu)
    {
        var guid     = Guid.NewGuid();
        _adapter     = WintunCreateAdapter(name, "VPN", ref guid);
        if (_adapter == IntPtr.Zero)
            throw new Exception("WintunCreateAdapter failed. Is wintun.dll present? Run as Administrator?");

        _session   = WintunStartSession(_adapter, WINTUN_MIN_RING_CAPACITY);
        _waitEvent = WintunGetReadWaitEvent(_session);

        // Настраиваем IP через netsh
        ConfigureInterface(name, address, mask, mtu);

        logger.LogInformation("Windows WinTun {Name} configured", name);
        return Task.CompletedTask;
    }

    private static void ConfigureInterface(string name, string address, string mask, int mtu)
    {
        RunCommand("netsh", $"interface ip set address name=\"{name}\" static {address} {mask}");
        RunCommand("netsh", $"interface ipv4 set subinterface \"{name}\" mtu={mtu} store=persistent");
    }

    private static void RunCommand(string cmd, string args)
    {
        var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = cmd, Arguments = args,
            RedirectStandardOutput = true, RedirectStandardError = true,
            UseShellExecute = false
        })!;
        p.WaitForExit();
    }

    public unsafe Task<byte[]> ReadPacketAsync(CancellationToken ct)
    {
        return Task.Run(() =>
        {
            // Ждём пакет через WinTun event
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
                // Ждём event вместо busy loop
                WaitForSingleObject(_waitEvent, 100);
            }
            ct.ThrowIfCancellationRequested();
            return Array.Empty<byte>();
        }, ct);
    }

    public unsafe Task WritePacketAsync(byte[] packet, CancellationToken ct)
    {
        var ptr = WintunAllocateSendPacket(_session, (uint)packet.Length);
        if (ptr == IntPtr.Zero)
            return Task.CompletedTask; // ring buffer полный — пропускаем пакет

        Marshal.Copy(packet, 0, ptr, packet.Length);
        WintunSendPacket(_session, ptr);
        return Task.CompletedTask;
    }

    [DllImport("kernel32.dll")]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    public ValueTask DisposeAsync()
    {
        if (_session  != IntPtr.Zero) WintunEndSession(_session);
        if (_adapter  != IntPtr.Zero) WintunCloseAdapter(_adapter);
        return ValueTask.CompletedTask;
    }
}