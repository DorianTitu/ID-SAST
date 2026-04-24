FROM mcr.microsoft.com/dotnet/sdk:8.0 AS builder

WORKDIR /build

COPY csharp-analyzer/CSharpAnalyzer.csproj .
COPY csharp-analyzer/CSharpASTAnalyzer.cs .
RUN dotnet publish -c Release -o /publish --self-contained=false

FROM mcr.microsoft.com/dotnet/runtime:8.0

WORKDIR /app

COPY --from=builder /publish .

EXPOSE 5003

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
  CMD curl --fail http://localhost:5003/health || exit 1

ENTRYPOINT ["dotnet", "CSharpAnalyzer.dll"]

ENTRYPOINT ["dotnet", "CSharpAnalyzer.dll"]

ENV PORT=5003
ENTRYPOINT ["dotnet", "CSharpAnalyzer.dll"]
