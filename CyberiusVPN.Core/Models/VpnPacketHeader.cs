namespace CyberiusVPN.Core.Models;

/// <summary>
/// Заголовок кадра протокола туннеля.
/// Формат: [4] Magic | [1] Type | [4] SessionId | [4] PayloadLen | [N] Ciphertext+Tag
/// </summary>
public record VpnPacketHeader(
    uint       Magic,
    PacketType Type,
    uint       SessionId,
    ulong      Nonce
)
{
    /// <summary>Магическое число для идентификации протокола.</summary>
    public const uint MagicValue = 0xC5_A3_F1_0E;

    /// <summary>Размер заголовка в байтах: Magic(4) + Type(1) + SessionId(4) + PayloadLen(4).</summary>
    public const int HeaderSize = 4 + 1 + 4 + 4;

    /// <summary>Размер GCM аутентификационного тега.</summary>
    public const int TagSize = 16;
}