using Org.BouncyCastle.Tls;

namespace CyberiusVPN.Core.Protocol;

/// <summary>
/// Фейковая TLS сессия — только для передачи auth токена в поле legacy_session_id ClientHello.
/// </summary>
internal sealed class FakeSession(byte[] sessionId) : TlsSession
{
    public byte[]  SessionID   => sessionId;
    public bool    IsResumable => false;
    public void    Invalidate() { }

    public SessionParameters? ExportSessionParameters() => null;
}