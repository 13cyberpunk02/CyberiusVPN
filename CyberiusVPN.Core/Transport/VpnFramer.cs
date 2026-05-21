using System.Buffers.Binary;
using CyberiusVPN.Core.Crypto;
using CyberiusVPN.Core.Models;
using Microsoft.Extensions.Logging;

namespace CyberiusVPN.Core.Transport;

/// <summary>
/// Упаковка и распаковка кадров протокола туннеля поверх TCP.
///
/// Формат кадра:
/// [4 байта] Magic (0xC5A3F10E)
/// [1 байт]  PacketType
/// [4 байта] SessionId
/// [4 байта] PayloadLen (длина зашифрованного payload включая GCM тег)
/// [N байт]  Ciphertext + 16-байтный GCM тег
/// </summary>
public sealed class VpnFramer
{
    private readonly ILogger      _logger;
    private readonly PacketCipher _sendCipher;
    private readonly PacketCipher _recvCipher;
    private ulong                 _recvNonce = 0;

    /// <summary>SessionId этого framer'а (используется в исходящих кадрах).</summary>
    public uint SessionId { get; }

    /// <summary>
    /// Создаёт framer с сессионными ключами.
    /// </summary>
    /// <param name="keys">Ключи шифрования сессии.</param>
    /// <param name="sessionId">Идентификатор сессии.</param>
    /// <param name="logger">Логгер.</param>
    public VpnFramer(SessionKeys keys, uint sessionId, ILogger logger)
    {
        _logger     = logger;
        SessionId   = sessionId;
        _sendCipher = new PacketCipher(keys.SendKey, keys.SendIv);
        _recvCipher = new PacketCipher(keys.RecvKey, keys.RecvIv);
    }

    /// <summary>
    /// Шифрует IP-пакет и отправляет кадр в TCP поток.
    /// Span-операции выполняются синхронно до await (CS4012).
    /// </summary>
    /// <param name="stream">TCP поток.</param>
    /// <param name="ipPacket">Сырой IP-пакет.</param>
    /// <param name="type">Тип пакета.</param>
    /// <param name="ct">Токен отмены.</param>
    public async Task SendPacketAsync(Stream stream, byte[] ipPacket,
        PacketType type, CancellationToken ct)
    {
        // Span-операции синхронно до первого await
        var aad       = BuildAad(type);
        var encrypted = _sendCipher.Encrypt(ipPacket, aad);
        var frame     = BuildFrame(encrypted, type);

        await stream.WriteAsync(frame, ct);
    }

    /// <summary>
    /// Читает и расшифровывает следующий кадр из TCP потока.
    /// </summary>
    /// <param name="stream">TCP поток.</param>
    /// <param name="ct">Токен отмены.</param>
    /// <returns>Тип и расшифрованный payload, или null если соединение закрыто.</returns>
    public async Task<(PacketType type, byte[] payload)?> ReceivePacketAsync(
        Stream stream, CancellationToken ct)
    {
        // Читаем заголовок кадра
        var headerBuf = new byte[VpnPacketHeader.HeaderSize];
        if (!await ReadExactAsync(stream, headerBuf, ct)) return null;

        // Парсим заголовок синхронно (Span вне async контекста)
        var (magic, type, _, payloadLen) = ParseHeader(headerBuf);

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

        // Читаем зашифрованный payload
        var encrypted = new byte[payloadLen];
        if (!await ReadExactAsync(stream, encrypted, ct)) return null;

        // Расшифровываем синхронно
        try
        {
            var aad     = BuildAad(type);
            var nonce   = _recvNonce++;
            var payload = _recvCipher.Decrypt(encrypted, aad, nonce);
            return (type, payload);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Decrypt failed: {Msg}", ex.Message);
            return null;
        }
    }

    // ── Вспомогательные синхронные методы (Span-friendly) ─────────────────

    /// <summary>Собирает кадр из зашифрованного payload.</summary>
    private byte[] BuildFrame(byte[] encrypted, PacketType type)
    {
        var frame = new byte[VpnPacketHeader.HeaderSize + encrypted.Length];
        var span  = frame.AsSpan();

        BinaryPrimitives.WriteUInt32BigEndian(span.Slice(0, 4), VpnPacketHeader.MagicValue);
        span[4] = (byte)type;
        BinaryPrimitives.WriteUInt32BigEndian(span.Slice(5, 4), SessionId);
        BinaryPrimitives.WriteInt32BigEndian(span.Slice(9, 4),  encrypted.Length);
        encrypted.CopyTo(span.Slice(13));

        return frame;
    }

    /// <summary>Парсит заголовок кадра.</summary>
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

    /// <summary>
    /// Строит AAD (Additional Authenticated Data) для GCM.
    /// Содержит только тип пакета — аутентифицируется, но не шифруется.
    /// </summary>
    private static byte[] BuildAad(PacketType type) => [(byte)type];

    /// <summary>Читает ровно buf.Length байт из потока.</summary>
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