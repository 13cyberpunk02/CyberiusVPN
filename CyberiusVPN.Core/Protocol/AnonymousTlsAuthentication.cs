using Org.BouncyCastle.Tls;

namespace CyberiusVPN.Core.Protocol;

/// <summary>
/// Анонимная TLS аутентификация клиента.
/// Принимает любой серверный сертификат (мы его не проверяем стандартно —
/// наша аутентификация идёт через X25519 токен).
/// </summary>
internal sealed class AnonymousTlsAuthentication : TlsAuthentication
{
    /// <summary>
    /// Проверка серверного сертификата.
    /// В реальном браузере здесь идёт chain validation.
    /// Для нашего туннеля принимаем любой — сервер аутентифицируется через X25519.
    /// </summary>
    public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
    {
        // Намеренно не проверяем — аутентификация через X25519 токен
    }

    /// <summary>
    /// Клиентский сертификат не нужен — аутентифицируемся через session_id токен.
    /// </summary>
    public TlsCredentials? GetClientCredentials(CertificateRequest certificateRequest)
        => null;
}