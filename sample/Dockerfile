FROM microsoft/dotnet:2.2-aspnetcore-runtime AS base
WORKDIR /app
EXPOSE 5080

FROM microsoft/dotnet:2.2-sdk AS build
WORKDIR /src
COPY ["sample.csproj", "./"]
RUN dotnet restore "./sample.csproj"
COPY . .
WORKDIR "/src/."
RUN dotnet build "sample.csproj" -c Release -o /app

FROM build AS publish
RUN dotnet publish "sample.csproj" -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "sample.dll"]
