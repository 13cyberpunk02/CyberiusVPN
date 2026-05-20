#!/bin/bash
# Локальное тестирование без VPS — сервер и клиент на одной машине
# Требует: .NET 8 SDK, root права (для TUN)
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

[[ $EUID -ne 0 ]] && echo "Run as root!" && exit 1

# ── Генерация ключей ─────────────────────────────────────────────────────────
log "Generating server keys..."
SERVER_KEYS=$(dotnet run --project CyberiusVPN.Server -- genkeys)
SERVER_PRIVKEY=$(echo "$SERVER_KEYS" | grep "Private:" | awk '{print $3}')
SERVER_PUBKEY=$(echo "$SERVER_KEYS"  | grep "Public:"  | awk '{print $3}')

log "Generating client keys..."
CLIENT_KEYS=$(dotnet run --project CyberiusVPN.Client -- genkeys)
CLIENT_PRIVKEY=$(echo "$CLIENT_KEYS" | grep "Private:" | awk '{print $2}')

echo ""
log "Keys generated OK"
log "Server pub: $SERVER_PUBKEY"

# ── Запуск сервера в фоне ────────────────────────────────────────────────────
log "Starting server on :9443 (localhost)..."

export VPN_PORT=9443
export VPN_SERVER_PRIVKEY="$SERVER_PRIVKEY"
export VPN_SNI="www.microsoft.com"

dotnet run --project CyberiusVPN.Server &
SERVER_PID=$!

# Даём серверу время стартовать
sleep 3
log "Server PID: $SERVER_PID"

# ── Запуск клиента ───────────────────────────────────────────────────────────
log "Starting client..."

export VPN_SERVER="127.0.0.1"
export VPN_PORT=3443
export VPN_SERVER_PUBKEY="$SERVER_PUBKEY"
export VPN_CLIENT_PRIVKEY="$CLIENT_PRIVKEY"
export VPN_SNI="www.microsoft.com"

dotnet run --project CyberiusVPN.Client -- --verbose &
CLIENT_PID=$!

log "Client PID: $CLIENT_PID"

# ── Ждём Ctrl+C ──────────────────────────────────────────────────────────────
echo ""
warn "Press Ctrl+C to stop both server and client"
echo ""

trap "log 'Stopping...'; kill $SERVER_PID $CLIENT_PID 2>/dev/null; exit 0" INT TERM

wait $CLIENT_PID
kill $SERVER_PID 2>/dev/null
