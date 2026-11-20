# BECETTI SECURITY cloud API — production image (non-root, health-checked).
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY Becetti.Security.Api.csproj ./Becetti.Security.Api/
RUN dotnet restore ./Becetti.Security.Api/Becetti.Security.Api.csproj
COPY . ./Becetti.Security.Api/
WORKDIR /src/Becetti.Security.Api
RUN dotnet publish -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app ./
RUN useradd --create-home --uid 10001 becetti && chown -R becetti:becetti /app
USER becetti
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
ENV DOTNET_RUNNING_IN_CONTAINER=true
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- http://localhost:8080/health || exit 1
ENTRYPOINT ["dotnet", "Becetti.Security.Api.dll"]
