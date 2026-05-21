# CyberiusVPN

VPN с Reality-подобным handshake на C# / .NET 10.

## Архитектура

```
[Windows/Linux Client]
       │
       ├── TUN интерфейс (WinTun / /dev/net/tun)
       │
       └── TCP :443 ──── TLS ClientHello (Chrome 120 fingerprint)
                                  │
                         [Linux VPS Server]
                                  │
                    ┌─────────────┴──────────────┐
               Наш клиент?                   Чужой?
               (session_id = auth-token)          │
                    │                       Форвард к SNI домену
               VPN сессия                  (маскировка)
```

## Криптография

| Компонент        | Алгоритм                  |
|------------------|---------------------------|
| Key exchange     | X25519 (BouncyCastle)     |
| KDF              | HKDF-SHA256 (.NET 10)      |
| Шифрование       | AES-256-GCM (.NET 10)      |
| TLS fingerprint  | Chrome 120 (ручная сборка)|
| Auth токен       | X25519 + HKDF + timestamp |

## Быстрый старт

### 1. Требования

- .NET 10 SDK
- Linux сервер (VPS): root, Docker
- Windows клиент: Администратор, wintun.dll

### 2. Генерация ключей (на сервере)

```bash
dotnet run --project CyberiusVPN.Server -- genkeys
# Server Private: <base64>  ← только для сервера (в .env)
# Server Public:  <base64>  ← передать клиенту
```

```bash
dotnet run --project CyberiusVPN.Client -- genkeys
# Private: <base64>  ← в VPN_CLIENT_PRIVKEY
# Public:  <base64>  ← опционально на сервер
```

### 3. Сервер через Docker

```bash
# Создать .env
echo 'VPN_SERVER_PRIVKEY=<base64>' > .env

# TUN + IP forwarding
mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 600 /dev/net/tun
echo 1 > /proc/sys/net/ipv4/ip_forward
IFACE=$(ip route | grep default | awk '{print $5}')
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $IFACE -j MASQUERADE

# Запуск
docker compose up -d
```

### 4. Клиент (Windows, PowerShell от Администратора)

```powershell
# Положить wintun.dll рядом с проектом
# https://www.wintun.net/

$env:VPN_SERVER       = "your-vps-ip"
$env:VPN_PORT         = "3443"
$env:VPN_SERVER_PUBKEY  = "<server_public_key>"
$env:VPN_CLIENT_PRIVKEY = "<client_private_key>"
$env:VPN_SNI          = "www.microsoft.com"

dotnet run --project CyberiusVPN.Client -- --verbose
```

### 5. Клиент (Linux)

```bash
export VPN_SERVER="your-vps-ip"
export VPN_PORT="3443"
export VPN_SERVER_PUBKEY="<base64>"
export VPN_CLIENT_PRIVKEY="<base64>"
export VPN_SNI="www.microsoft.com"

sudo dotnet run --project CyberiusVPN.Client -- --verbose
```

### 6. Проверка

```bash
# Должен показать IP сервера, а не домашний
curl ifconfig.me
```

## Структура проекта

```
CyberiusVPN/
├── CyberiusVPN.Core/
│   ├── Crypto/
│   │   └── CryptoLayer.cs       X25519, HKDF, AES-GCM
│   ├── Protocol/
│   │   └── RealityHandshake.cs  Chrome fingerprint, auth-токен
│   ├── Transport/
│   │   ├── VpnTunnel.cs         Кадрирование, двунаправленный пайплайн
│   │   ├── VpnServer.cs         Сервер + Reality роутинг
│   │   ├── VpnClientCore.cs     Клиент + ClientHello builder
│   │   └── VpnSession.cs        Состояние сессии
│   ├── Tun/
│   │   └── TunInterface.cs      Linux /dev/net/tun + Windows WinTun
│   └── Models/
│       └── VpnModels.cs         Конфиги, типы пакетов
├── CyberiusVPN.Client/Program.cs
├── CyberiusVPN.Server/Program.cs
├── Dockerfile
└── docker-compose.yml
```

## Известные ограничения

- Маршрутизация на клиенте (Windows) прописывает только маршрут к серверу,
  но не перенаправляет весь трафик через туннель — нужно доработать SetupRoutes
- Проверка auth-токена на сервере упрощена (TODO в CheckAuthToken)
- Нет IPv6 поддержки
