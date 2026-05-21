#!/bin/bash
# CyberiusVPN — скрипт быстрого деплоя на VPS
# Использование: bash setup.sh
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }

# ── 1. Проверка окружения ────────────────────────────────────────────────────
log "Checking environment..."

[[ $EUID -ne 0 ]] && err "Run as root: sudo bash setup.sh"

command -v docker        &>/dev/null || err "Docker not found. Install: curl -fsSL https://get.docker.com | sh"
command -v docker-compose &>/dev/null || COMPOSE="docker compose" || COMPOSE="docker-compose"
COMPOSE=${COMPOSE:-"docker compose"}

# Проверяем что /dev/net/tun существует
if [[ ! -e /dev/net/tun ]]; then
    warn "/dev/net/tun not found, creating..."
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200
    chmod 600 /dev/net/tun
fi

log "/dev/net/tun OK"

# ── 2. Генерация ключей ──────────────────────────────────────────────────────
log "Generating server keys..."

# Запускаем сервер в режиме genkeys
KEYS=$(docker compose run --rm vpn-server genkeys 2>/dev/null || \
       dotnet run --project CyberiusVPN.Server -- genkeys 2>/dev/null)

SERVER_PRIVKEY=$(echo "$KEYS" | grep "Server Private:" | awk '{print $3}')
SERVER_PUBKEY=$(echo "$KEYS"  | grep "Server Public:"  | awk '{print $3}')

if [[ -z "$SERVER_PRIVKEY" ]]; then
    warn "Could not auto-generate keys. Generate manually:"
    echo "  dotnet run --project CyberiusVPN.Server -- genkeys"
    echo ""
    read -p "Paste Server Private Key: " SERVER_PRIVKEY
    read -p "Paste Server Public Key:  " SERVER_PUBKEY
fi

log "Server Public Key: ${SERVER_PUBKEY}"

# Сохраняем в .env
cat > .env << EOF
VPN_SERVER_PRIVKEY=${SERVER_PRIVKEY}
EOF

log ".env created with private key"

# ── 3. IP forwarding ─────────────────────────────────────────────────────────
log "Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

# NAT чтобы трафик клиентов выходил в интернет через основной интерфейс
IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
log "Main interface: $IFACE"

iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$IFACE" -j MASQUERADE 2>/dev/null || true
log "NAT rule added"

# ── 4. Сборка и запуск ───────────────────────────────────────────────────────
log "Building Docker image..."
$COMPOSE build

log "Starting server..."
$COMPOSE up -d

sleep 2

# ── 5. Статус ────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "Server is running!"
echo ""
echo "  Server Public Key (дай клиенту):"
echo "  ${SERVER_PUBKEY}"
echo ""
echo "  Logs: docker compose logs -f"
echo "  Stop: docker compose down"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── 6. Инструкция для клиента ────────────────────────────────────────────────
VPS_IP=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_VPS_IP")

echo "Запуск клиента (на твоей машине):"
echo ""
echo "  # Сначала генерируй клиентские ключи:"
echo "  dotnet run --project CyberiusVPN.Client -- genkeys"
echo ""
echo "  # Затем подключайся:"
echo "  export VPN_SERVER=\"${VPS_IP}\""
echo "  export VPN_PORT=\"443\""
echo "  export VPN_SERVER_PUBKEY=\"${SERVER_PUBKEY}\""
echo "  export VPN_CLIENT_PRIVKEY=\"<твой_приватный_ключ>\""
echo "  export VPN_SNI=\"www.microsoft.com\""
echo ""
echo "  sudo dotnet run --project CyberiusVPN.Client -- --verbose"
