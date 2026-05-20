using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace CyberiusVPN.Core.Protocol;

/// <summary>
/// TLS клиент с Chrome fingerprint + auth токен в session_id.
/// Наследует DefaultTlsClient (BouncyCastle) и переопределяет нужные методы.
/// </summary>
public sealed class RealityTlsClient(BcTlsCrypto crypto, string sniDomain, byte[] authToken) : DefaultTlsClient(crypto)
{
    public override int[] GetCipherSuites() => ChromeFingerprint.CipherSuites;

    protected override IList<ServerName> GetSniServerNames()
        => [new ServerName(NameType.host_name,
            System.Text.Encoding.ASCII.GetBytes(sniDomain))];

    /// <summary>
    /// Прячем auth токен в legacy_session_id (32 байта).
    /// В TLS 1.3 это поле игнорируется обычным TLS сервером,
    /// но наш VPN-сервер читает его ДО TLS handshake через сырой peek.
    /// </summary>
    public override TlsSession GetSessionToResume()
        => new FakeSession(authToken);

    /// <summary>
    /// Обязательный абстрактный метод из AbstractTlsClient.
    /// Возвращаем анонимную аутентификацию — мы аутентифицируемся
    /// через session_id токен, а не через клиентский TLS сертификат.
    /// </summary>
    public override TlsAuthentication GetAuthentication()
        => new AnonymousTlsAuthentication();
}