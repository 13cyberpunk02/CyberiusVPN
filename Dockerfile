FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Копируем проекты
COPY CyberiusVPN.Core/CyberiusVPN.Core.csproj       CyberiusVPN.Core/
COPY CyberiusVPN.Server/CyberiusVPN.Server.csproj   CyberiusVPN.Server/

# Восстанавливаем зависимости
RUN dotnet restore CyberiusVPN.Server/CyberiusVPN.Server.csproj

# Копируем исходники и билдим
COPY CyberiusVPN.Core/   CyberiusVPN.Core/
COPY CyberiusVPN.Server/ CyberiusVPN.Server/

RUN dotnet publish CyberiusVPN.Server/CyberiusVPN.Server.csproj \
    -c Release -o /app --no-restore

# ── Runtime образ (минимальный) ──────────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/runtime:10.0
WORKDIR /app

# Нужен ip и iproute2 для настройки TUN интерфейса
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /app .

EXPOSE 3443

ENTRYPOINT ["dotnet", "CyberiusVPN.Server.dll"]
