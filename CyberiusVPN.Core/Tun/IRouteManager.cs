namespace CyberiusVPN.Core.Tun;

/// <summary>
/// Интерфейс управления маршрутами.
/// Реализация зависит от платформы:
/// Windows — route/netsh команды
/// Linux   — ip route команды  
/// Android — VpnService.Builder (маршруты задаются до старта туннеля)
/// </summary>
public interface IRouteManager
{
    /// <summary>Настраивает маршруты после подключения VPN.</summary>
    void Setup(string serverIp, string assignedIp, string tunName);

    /// <summary>Восстанавливает маршруты после отключения VPN.</summary>
    void Cleanup(string serverIp);
}