using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace CyberiusVPN.Core.Protocol;

/// <summary>
/// TLS клиент BouncyCastle с Chrome 120 fingerprint.
/// Переопределяет cipher suites, SNI и session_id для вставки auth-токена.
/// </summary>
public sealed class RealityTlsClient : DefaultTlsClient
{
    private readonly string _sniDomain;
    private readonly byte[] _authToken;

    /// <param name="crypto">BouncyCastle криптопровайдер.</param>
    /// <param name="sniDomain">SNI домен для маскировки (например www.microsoft.com).</param>
    /// <param name="authToken">32-байтный auth-токен для session_id.</param>
    public RealityTlsClient(BcTlsCrypto crypto, string sniDomain, byte[] authToken)
        : base(crypto)
    {
        _sniDomain = sniDomain;
        _authToken = authToken;
    }

    /// <inheritdoc/>
    public override int[] GetCipherSuites() => ChromeFingerprint.CipherSuites;

    /// <inheritdoc/>
    protected override IList<ServerName> GetSniServerNames()
        => [new ServerName(NameType.host_name,
            System.Text.Encoding.ASCII.GetBytes(_sniDomain))];

    /// <summary>
    /// Возвращает фейковую сессию с auth-токеном в качестве session_id.
    /// В TLS 1.3 поле legacy_session_id игнорируется TLS-стеком,
    /// но наш сервер читает его до handshake из сырого TCP потока.
    /// </summary>
    public override TlsSession GetSessionToResume()
        => new FakeSession(_authToken);

    /// <summary>
    /// Анонимная аутентификация — мы аутентифицируемся через X25519 токен,
    /// а не через клиентский TLS сертификат.
    /// </summary>
    public override TlsAuthentication GetAuthentication()
        => new AnonymousTlsAuthentication();
}