using System.Diagnostics;
using System.Runtime.InteropServices;

namespace CyberiusVPN.Core.Tun;

/// <summary>Linux реализация управления маршрутами через ip route.</summary>
public sealed class LinuxRouteManager : IRouteManager
{
    private string _savedGateway = "";
    private string _savedIface   = "";

    public void Setup(string serverIp, string assignedIp, string tunName)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) return;

        var defaultRoute = RunAndRead("ip", "route show default");
        var parts = defaultRoute.Split(' ');
        _savedGateway = parts.Length > 2 ? parts[2] : "";
        _savedIface   = parts.Length > 4 ? parts[4] : "";

        Console.WriteLine($"Gateway: {_savedGateway} via {_savedIface}, server: {serverIp}");

        Run("ip", $"route add {serverIp}/32 via {_savedGateway} dev {_savedIface}");
        Run("ip", "route del default");
        Run("ip", $"route add default dev {tunName}");
        Run("bash", "-c \"echo 'nameserver 8.8.8.8' > /etc/resolv.conf\"");
    }

    public void Cleanup(string serverIp)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) return;

        Run("ip", $"route del {serverIp}/32 2>/dev/null || true");
        Run("ip", "route del default dev vpn0 2>/dev/null || true");

        if (!string.IsNullOrEmpty(_savedGateway) && !string.IsNullOrEmpty(_savedIface))
        {
            Run("ip", $"route add default via {_savedGateway} dev {_savedIface}");
            Console.WriteLine($"Default route restored: via {_savedGateway} dev {_savedIface}");
        }
        else
        {
            Run("systemctl", "restart NetworkManager");
        }
        Console.WriteLine("Routes restored.");
    }

    private static string RunAndRead(string cmd, string args)
    {
        var psi = new ProcessStartInfo(cmd, args)
        {
            RedirectStandardOutput = true,
            UseShellExecute = false
        };
        var p = Process.Start(psi)!;
        var output = p.StandardOutput.ReadLine() ?? "";
        p.WaitForExit();
        return output;
    }

    private static void Run(string cmd, string args) =>
        Process.Start(new ProcessStartInfo
        {
            FileName               = cmd,
            Arguments              = args,
            RedirectStandardOutput = true,
            RedirectStandardError  = true,
            UseShellExecute        = false
        })?.WaitForExit();
}