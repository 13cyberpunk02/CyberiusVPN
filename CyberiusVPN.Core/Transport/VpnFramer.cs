using System.Buffers.Binary;
using CyberiusVPN.Core.Crypto;
using CyberiusVPN.Core.Models;
using Microsoft.Extensions.Logging;

namespace CyberiusVPN.Core.Transport;

/// <summary>
/// Упаковка/распаковка пакетов нашего протокола поверх TCP стрима.
///
/// Формат кадра:
/// [4] Magic | [1] Type | [4] SessionId | [4] PayloadLen | [N] Ciphertext+Tag
/// </summary>
public sealed class VpnFramer(SessionKeys keys, uint sessionId, ILogger logger)
{
    private readonly PacketCipher _sendCipher = new(keys.SendKey, keys.SendIv);
    private readonly PacketCipher _recvCipher = new(keys.RecvKey, keys.RecvIv);
    private ulong                 _recvNonce = 0;

    public uint SessionId { get; } = sessionId;

    // ── Span работа вынесена в синхронные методы ─────────────────────────────
    // CS4012: Span<byte> нельзя использовать в async методах напрямую

    /// <summary>
    /// Собираем кадр синхронно (Span-friendly), потом async отправляем
    /// </summary>
    private byte[] BuildFrame(byte[] encrypted, PacketType type)
    {
        // [4] Magic | [1] Type | [4] SessionId | [4] PayloadLen | [N] payload
        var frame = new byte[4 + 1 + 4 + 4 + encrypted.Length];
        var span  = frame.AsSpan();

        BinaryPrimitives.WriteUInt32BigEndian(span.Slice(0, 4), VpnPacketHeader.MagicValue);
        span[4] = (byte)type;
        BinaryPrimitives.WriteUInt32BigEndian(span.Slice(5, 4), SessionId);
        BinaryPrimitives.WriteInt32BigEndian(span.Slice(9, 4),  encrypted.Length);
        encrypted.CopyTo(span.Slice(13));

        return frame;
    }

    /// <summary>
    /// Парсим заголовок синхронно (Span-friendly)
    /// </summary>
    private static (uint magic, PacketType type, uint sessionId, int payloadLen)
        ParseHeader(byte[] header)
    {
        var span      = header.AsSpan();
        var magic     = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(0, 4));
        var type      = (PacketType)span[4];
        var sessionId = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(5, 4));
        var payloadLen= BinaryPrimitives.ReadInt32BigEndian(span.Slice(9, 4));
        return (magic, type, sessionId, payloadLen);
    }

    private static byte[] BuildAad(PacketType type, uint sessionId)
    {
        var aad = new byte[5];
        aad[0]  = (byte)type;
        BinaryPrimitives.WriteUInt32BigEndian(aad.AsSpan(1), sessionId);
        return aad;
    }

    // ── Async методы — только I/O, никаких Span ───────────────────────────────

    /// <summary>
    /// Шифруем и отправляем IP-пакет
    /// </summary>
    public async Task SendPacketAsync(Stream stream, byte[] ipPacket,
        PacketType type, CancellationToken ct)
    {
        // Вся работа со Span — синхронно до await
        var aad       = BuildAad(type, SessionId);
        var encrypted = _sendCipher.Encrypt(ipPacket, aad);
        var frame     = BuildFrame(encrypted, type);

        // Только чистый async I/O
        await stream.WriteAsync(frame, ct);
    }

    /// <summary>
    /// Читаем и расшифровываем следующий кадр
    /// </summary>
    public async Task<(PacketType type, byte[] payload)?> ReceivePacketAsync(
        Stream stream, CancellationToken ct)
    {
        // 1. Читаем заголовок (async I/O)
        var headerBuf = new byte[4 + 1 + 4 + 4]; // 13 байт
        if (!await ReadExactAsync(stream, headerBuf, ct)) return null;

        // 2. Парсим синхронно (Span — вне async контекста через отдельный метод)
        var (magic, type, sessionId, payloadLen) = ParseHeader(headerBuf);

        if (magic != VpnPacketHeader.MagicValue)
        {
            logger.LogWarning("Invalid magic: {Magic:X8}", magic);
            return null;
        }

        if (payloadLen is < 16 or > 65535 + 16)
        {
            logger.LogWarning("Invalid payload length: {Len}", payloadLen);
            return null;
        }

        // 3. Читаем зашифрованный payload (async I/O)
        var encrypted = new byte[payloadLen];
        if (!await ReadExactAsync(stream, encrypted, ct)) return null;

        // 4. Расшифровываем синхронно
        try
        {
            var aad     = BuildAad(type, sessionId);
            var nonce   = _recvNonce++;
            var payload = _recvCipher.Decrypt(encrypted, aad, nonce);
            return (type, payload);
        }
        catch (Exception ex)
        {
            logger.LogWarning("Decrypt failed: {Msg}", ex.Message);
            return null;
        }
    }

    private static async Task<bool> ReadExactAsync(Stream stream, byte[] buf, CancellationToken ct)
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
}