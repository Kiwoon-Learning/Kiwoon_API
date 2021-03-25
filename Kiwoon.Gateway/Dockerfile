#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:5.0-buster-slim AS base
WORKDIR /app
EXPOSE 8888

FROM mcr.microsoft.com/dotnet/sdk:5.0-buster-slim AS build
WORKDIR /src
COPY ["Kiwoon.Gateway/Kiwoon.Gateway.csproj", "Kiwoon.Gateway/"]
COPY ["Kiwoon.Gateway.Domain/Kiwoon.Gateway.Domain.csproj", "Kiwoon.Gateway.Domain/"]
COPY ["SharedModels.Domain/SharedModels.Domain.csproj", "SharedModels.Domain/"]
RUN dotnet restore "Kiwoon.Gateway/Kiwoon.Gateway.csproj"
COPY . .
WORKDIR "/src/Kiwoon.Gateway"
RUN dotnet build "Kiwoon.Gateway.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Kiwoon.Gateway.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
ENV ASPNETCORE_URLS=http://+:8888
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Kiwoon.Gateway.dll"]