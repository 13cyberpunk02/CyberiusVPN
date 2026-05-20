namespace CyberiusVPN.Core.Models;

public record SessionKeys(
    byte[] SendKey,
    byte[] RecvKey,
    byte[] SendIv,
    byte[] RecvIv
);