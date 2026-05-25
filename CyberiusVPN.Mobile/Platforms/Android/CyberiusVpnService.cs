using Android.App;
using Android.Content;
using Android.Net;
using CyberiusVPN.Core.Models;
using CyberiusVPN.Core.Transport;
using Microsoft.Extensions.Logging;

namespace CyberiusVPN.Mobile.Platforms.Android;

/// <summary>
/// Android VPN сервис. Запускается в фоне и управляет туннелем.
/// </summary>
[Service(
    Permission = "android.permission.BIND_VPN_SERVICE",
    Exported = false,
    ForegroundServiceType = global::Android.Content.PM.ForegroundService.TypeSpecialUse)]
[IntentFilter(["android.net.VpnService"])]
public class CyberiusVpnService : VpnService
{
    public const string ActionStart = "CyberiusVPN.START";
    public const string ActionStop = "CyberiusVPN.STOP";
    public const string ExtraServer = "server";
    public const string ExtraPort = "port";
    public const string ExtraPubKey = "pubkey";
    public const string ExtraPrivKey = "privkey";
    public const string ExtraSni = "sni";

    private CancellationTokenSource? _cts;
    private Task? _vpnTask;

    public override StartCommandResult OnStartCommand(
        Intent? intent, StartCommandFlags flags, int startId)
    {
        if (intent?.Action == ActionStop)
        {
            StopVpn();
            return StartCommandResult.NotSticky;
        }

        // Читаем параметры подключения из Intent
        var server = intent?.GetStringExtra(ExtraServer) ?? "";
        var port = intent?.GetIntExtra(ExtraPort, 3443) ?? 3443;
        var pubKey = intent?.GetStringExtra(ExtraPubKey) ?? "";
        var privKey = intent?.GetStringExtra(ExtraPrivKey) ?? "";
        var sni = intent?.GetStringExtra(ExtraSni) ?? "www.microsoft.com";

        StartVpn(server, port, pubKey, privKey, sni);
        return StartCommandResult.Sticky;
    }

    private void StartVpn(string server, int port,
                          string pubKey, string privKey, string sni)
    {
        _cts = new CancellationTokenSource();

        // Foreground уведомление — Android требует для фоновых сервисов
        var notification = BuildNotification();
        StartForeground(1, notification,
            global::Android.Content.PM.ForegroundService.TypeSpecialUse);

        _vpnTask = Task.Run(async () =>
        {
            try
            {
                var config = new VpnConfig(
                    ServerHost: server,
                    ServerPort: port,
                    ServerPublicKey: pubKey,
                    ClientPrivateKey: privKey,
                    SniDomain: sni,
                    TunAddress: "10.8.0.2", // будет заменён IP от сервера
                    TunMask: "255.255.255.0"
                );

                using var logFactory = LoggerFactory.Create(b =>
                    b.AddDebug().SetMinimumLevel(LogLevel.Information));

                // Android управляет маршрутами через VpnService.Builder —
                // IRouteManager не нужен
                var tunDriver = new AndroidTunDriver(this);
                var client = new VpnClient(config, logFactory,
                    routeManager: null,
                    tunDriver: tunDriver,
                    protectSocket: fd => Protect(fd));

                await client.RunAsync(_cts.Token);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                Console.WriteLine($"VPN error: {ex.Message}");
            }
            finally
            {
                StopForeground(StopForegroundFlags.Remove);
                StopSelf();
            }
        }, _cts.Token);
    }

    private void StopVpn()
    {
        _cts?.Cancel();
        StopForeground(StopForegroundFlags.Remove);
        StopSelf();
    }

    private Notification BuildNotification()
    {
        const string channelId = "cyberius_vpn";

        var manager = (NotificationManager?)
            GetSystemService(NotificationService);

        // Создаём канал уведомлений (Android 8+)
        var channel = new NotificationChannel(
            channelId, "CyberiusVPN", NotificationImportance.Low);
        manager?.CreateNotificationChannel(channel);

        return new Notification.Builder(this, channelId)
            .SetContentTitle("CyberiusVPN")
            .SetContentText("VPN подключён")
            .SetSmallIcon(Resource.Mipmap.appicon)
            .SetOngoing(true)
            .Build()!;
    }

    public override void OnDestroy()
    {
        _cts?.Cancel();
        base.OnDestroy();
    }
}