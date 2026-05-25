using System.Buffers;
using System.Buffers.Binary;
using CyberiusVPN.Core.Crypto;
using CyberiusVPN.Core.Models;
using Microsoft.Extensions.Logging;

namespace CyberiusVPN.Core.Transport;

public sealed class VpnFramer
{
    private readonly ILogger      _logger;
    private readonly PacketCipher _sendCipher;
    private readonly PacketCipher _recvCipher;
    private ulong                 _recvNonce = 0;

    // Статические AAD — нет аллокации на каждый пакет
    private static readonly byte[] AadData     = [(byte)PacketType.Data];
    private static readonly byte[] AadKeepalive = [(byte)PacketType.Keepalive];

    // Переиспользуемый буфер заголовка
    private readonly byte[] _headerBuf = new byte[VpnPacketHeader.HeaderSize];

    public uint SessionId { get; }

    public VpnFramer(SessionKeys keys, uint sessionId, ILogger logger)
    {
        _logger     = logger;
        SessionId   = sessionId;
        _sendCipher = new PacketCipher(keys.SendKey, keys.SendIv);
        _recvCipher = new PacketCipher(keys.RecvKey, keys.RecvIv);
    }

    public async Task SendPacketAsync(Stream stream, byte[] ipPacket,
        PacketType type, CancellationToken ct)
    {
        var aad       = GetAad(type);
        var encrypted = _sendCipher.Encrypt(ipPacket, aad);

        // Строим frame с аренданным буфером из пула
        var frameSize = VpnPacketHeader.HeaderSize + encrypted.Length;
        var frameBuf  = ArrayPool<byte>.Shared.Rent(frameSize);
        try
        {
            var span = frameBuf.AsSpan(0, frameSize);
            BinaryPrimitives.WriteUInt32BigEndian(span.Slice(0, 4), VpnPacketHeader.MagicValue);
            span[4] = (byte)type;
            BinaryPrimitives.WriteUInt32BigEndian(span.Slice(5, 4), SessionId);
            BinaryPrimitives.WriteInt32BigEndian(span.Slice(9, 4),  encrypted.Length);
            encrypted.AsSpan().CopyTo(span.Slice(13));

            await stream.WriteAsync(frameBuf.AsMemory(0, frameSize), ct);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(frameBuf);
        }
    }

    public async Task<(PacketType type, byte[] payload)?> ReceivePacketAsync(
        Stream stream, CancellationToken ct)
    {
        // Переиспользуем буфер заголовка — нет аллокации
        if (!await ReadExactAsync(stream, _headerBuf, ct)) return null;

        var span      = _headerBuf.AsSpan();
        var magic     = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(0, 4));
        var type      = (PacketType)span[4];
        var payloadLen= BinaryPrimitives.ReadInt32BigEndian(span.Slice(9, 4));

        if (magic != VpnPacketHeader.MagicValue)
        {
            _logger.LogWarning("Invalid magic: {Magic:X8}", magic);
            return null;
        }

        if (payloadLen is < 16 or > 65535 + 16)
        {
            _logger.LogWarning("Invalid payload length: {Len}", payloadLen);
            return null;
        }

        // Арендуем буфер из пула вместо new byte[]
        var encryptedBuf = ArrayPool<byte>.Shared.Rent(payloadLen);
        try
        {
            if (!await ReadExactAsync(stream, encryptedBuf, payloadLen, ct)) return null;

            var aad   = GetAad(type);
            var nonce = _recvNonce++;

            // Расшифровываем с точным срезом нужной длины
            var payload = _recvCipher.Decrypt(
                encryptedBuf.AsSpan(0, payloadLen), aad, nonce);
            return (type, payload);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Decrypt failed: {Msg}", ex.Message);
            return null;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(encryptedBuf);
        }
    }

    // Статические AAD — нет аллокации
    private static byte[] GetAad(PacketType type) => type switch
    {
        PacketType.Data      => AadData,
        PacketType.Keepalive => AadKeepalive,
        _                    => [(byte)type]
    };

    private static async Task<bool> ReadExactAsync(
        Stream stream, byte[] buf, CancellationToken ct)
    {
        int offset = 0;
        while (offset < buf.Length)
        {
            int read = await stream.ReadAsync(buf.AsMemory(offset), ct);
            if (read == 0) return false;
            offset += read;
        }
        return true;
    }

    // Перегрузка с явной длиной — для арендованных буферов из пула
    private static async Task<bool> ReadExactAsync(
        Stream stream, byte[] buf, int length, CancellationToken ct)
    {
        int offset = 0;
        while (offset < length)
        {
            int read = await stream.ReadAsync(buf.AsMemory(offset, length - offset), ct);
            if (read == 0) return false;
            offset += read;
        }
        return true;
    }
}