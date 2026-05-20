namespace CyberiusVPN.Core.Models;

public enum PacketType : byte
{
    Handshake       = 0x01,
    HandshakeReply  = 0x02,
    Data            = 0x03,
    Keepalive       = 0x04,
    Disconnect      = 0x05,
}