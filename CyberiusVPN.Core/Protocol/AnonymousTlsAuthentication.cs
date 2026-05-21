using Org.BouncyCastle.Tls;

namespace CyberiusVPN.Core.Protocol;

/// <summary>
/// Анонимная TLS аутентификация. Принимает любой серверный сертификат —
/// проверка подлинности сервера выполняется через X25519 общий секрет.
/// </summary>
internal sealed class AnonymousTlsAuthentication : TlsAuthentication
{
    /// <summary>Принимаем любой серверный сертификат без проверки цепочки.</summary>
    public void NotifyServerCertificate(TlsServerCertificate serverCertificate) { }

    /// <summary>Клиентский сертификат не нужен.</summary>
    public TlsCredentials? GetClientCredentials(CertificateRequest certificateRequest) => null;
}