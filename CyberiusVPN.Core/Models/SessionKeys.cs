namespace CyberiusVPN.Core.Models;

/// <summary>
/// Сессионные ключи шифрования для одного направления.
/// SendKey/SendIv используются для исходящих пакетов,
/// RecvKey/RecvIv — для входящих.
/// </summary>
public record SessionKeys(
    byte[] SendKey,
    byte[] RecvKey,
    byte[] SendIv,
    byte[] RecvIv
);