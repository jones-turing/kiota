FROM mcr.microsoft.com/dotnet/sdk:10.0

WORKDIR /src
COPY . .

# Build once during image build (fast container runs after that)
RUN dotnet restore ./kiota.slnx \
 && dotnet build ./kiota.slnx -c Release -p:TreatWarningsAsErrors=false --no-restore

# Inline entrypoint (no external file)
RUN cat > /usr/local/bin/entrypoint.sh <<'SH' \
 && chmod +x /usr/local/bin/entrypoint.sh
#!/usr/bin/env bash
set -euo pipefail

cd /src
KIOTA_DLL="/src/src/kiota/bin/Release/net10.0/kiota.dll"

# If first arg is "test", run tests
if [[ "${1:-}" == "test" ]]; then
  shift
  dotnet test tests/Kiota.Builder.Tests/Kiota.Builder.Tests.csproj -c Release --no-build --no-restore "$@"
  dotnet test tests/Kiota.Tests/Kiota.Tests.csproj -c Release --no-build --no-restore "$@"
  exit 0
fi

if [[ $# -eq 0 ]]; then
  exec dotnet "$KIOTA_DLL" --help
fi

exec dotnet "$KIOTA_DLL" "$@"
SH
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh && chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]