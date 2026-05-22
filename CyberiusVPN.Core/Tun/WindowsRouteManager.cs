using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace CyberiusVPN.Core.Tun;

/// <summary>Windows реализация управления маршрутами через route/netsh.</summary>
public sealed class WindowsRouteManager : IRouteManager
{
    public void Setup(string serverIp, string assignedIp, string tunName)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;

        var gw = GetDefaultGateway();
        if (string.IsNullOrEmpty(gw)) return;
        Console.WriteLine($"Default gateway: {gw}, server: {serverIp}");

        var ifIndex = GetInterfaceIndex(tunName);
        Console.WriteLine($"{tunName} interface index: {ifIndex}");

        Run("route", $"delete {serverIp} mask 255.255.255.255");
        Run("route", $"add {serverIp} mask 255.255.255.255 {gw} metric 1");
        Run("route", "delete 0.0.0.0 mask 0.0.0.0 172.18.0.2");
        Run("route", "delete 0.0.0.0 mask 128.0.0.0");
        Run("route", "delete 128.0.0.0 mask 128.0.0.0");
        Run("route", $"add 0.0.0.0 mask 128.0.0.0 {assignedIp} IF {ifIndex} metric 1");
        Run("route", $"add 128.0.0.0 mask 128.0.0.0 {assignedIp} IF {ifIndex} metric 1");
        Run("netsh", $"interface ip set dns \"{tunName}\" static 8.8.8.8");
    }

    public void Cleanup(string serverIp)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;

        Run("route", $"delete {serverIp} mask 255.255.255.255");
        Run("route", "delete 0.0.0.0 mask 128.0.0.0");
        Run("route", "delete 128.0.0.0 mask 128.0.0.0");
        Console.WriteLine("Routes restored.");
    }

    private static string GetDefaultGateway()
    {
        try
        {
            var psi = new ProcessStartInfo("route", "print 0.0.0.0")
            {
                RedirectStandardOutput = true,
                UseShellExecute        = false
            };
            var p      = Process.Start(psi)!;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();

            foreach (var line in output.Split('\n'))
            {
                var parts = line.Trim().Split(
                    [' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
                if (parts is ["0.0.0.0", "0.0.0.0", _, ..]
                    && IPAddress.TryParse(parts[2], out _))
                    return parts[2];
            }
        }
        catch
        {
            // ignored
        }

        return "";
    }

    private static int GetInterfaceIndex(string name)
    {
        try
        {
            foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                    return ni.GetIPProperties().GetIPv4Properties().Index;
            }
        }
        catch
        {
            // ignored
        }

        return 0;
    }

    private static void Run(string cmd, string args) =>
        Process.Start(new ProcessStartInfo()
        {
            FileName               = cmd,
            Arguments              = args,
            RedirectStandardOutput = true,
            RedirectStandardError  = true,
            UseShellExecute        = false
        })?.WaitForExit();
}