namespace CyberiusVPN.Core.Tun;

internal interface ITunDriver : IAsyncDisposable
{
    Task         OpenAsync(string name, string address, string mask, int mtu);
    Task<byte[]> ReadPacketAsync(CancellationToken ct);
    Task         WritePacketAsync(byte[] packet, CancellationToken ct);
}