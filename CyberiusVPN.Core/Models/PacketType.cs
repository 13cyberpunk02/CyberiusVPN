namespace CyberiusVPN.Core.Models;

/// <summary>Тип пакета протокола туннеля.</summary>
public enum PacketType : byte
{
    /// <summary>Начальное рукопожатие (зарезервировано).</summary>
    Handshake      = 0x01,
    /// <summary>Ответ на рукопожатие (зарезервировано).</summary>
    HandshakeReply = 0x02,
    /// <summary>Зашифрованный IP-пакет данных.</summary>
    Data           = 0x03,
    /// <summary>Keepalive — поддержание NAT-сессии активной.</summary>
    Keepalive      = 0x04,
    /// <summary>Уведомление о разрыве соединения.</summary>
    Disconnect     = 0x05,
}