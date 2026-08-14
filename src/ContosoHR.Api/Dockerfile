FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

COPY Directory.Build.props .
COPY src/ContosoHR.Api/ContosoHR.Api.csproj src/ContosoHR.Api/
COPY src/ContosoHR.Assistant/ContosoHR.Assistant.csproj src/ContosoHR.Assistant/
COPY src/ContosoHR.Assistant.Security/ContosoHR.Assistant.Security.csproj src/ContosoHR.Assistant.Security/
COPY src/ContosoHR.Data/ContosoHR.Data.csproj src/ContosoHR.Data/
RUN dotnet restore src/ContosoHR.Api/ContosoHR.Api.csproj

COPY src/ src/
RUN dotnet publish src/ContosoHR.Api/ContosoHR.Api.csproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime
WORKDIR /app
COPY --from=build /app .

ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

USER $APP_UID
ENTRYPOINT ["dotnet", "ContosoHR.Api.dll"]
