namespace CyberiusVPN.Core.Models;

/// <summary>
/// Заголовок пакета нашего протокола
/// [4] Magic | [1] Type | [4] SessionId | [8] Nonce | [N] Payload | [16] Tag
/// </summary>
public record VpnPacketHeader(
    uint      Magic,
    PacketType Type,
    uint      SessionId,
    ulong     Nonce
)
{
    public const uint   MagicValue  = 0xC5_A3_F1_0E; // случайное, не похоже на известные протоколы
    public const int    HeaderSize  = 4 + 1 + 4 + 8; // 17 байт
    public const int    TagSize     = 16;
}