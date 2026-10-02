# Native AOT build of the proxy on a distroless-style base.
#
#   docker build -t mcp-guardrails .
#
# Base images are pinned by digest, for the same reason ci.yml pins actions by
# SHA: a tag is mutable, so whoever controls it could change what this file
# builds without a commit here. The digests are multi-arch manifest lists, so one
# pin serves linux/amd64 and linux/arm64. The tag in the comment says what the
# digest was when it was pinned; bump both together.
#
# Each architecture is compiled natively (no --platform=$BUILDPLATFORM): Native
# AOT cross-compiles between architectures only with a target sysroot installed,
# and building per platform keeps this file simple. buildx under emulation, or a
# native runner per arch, both work.

# mcr.microsoft.com/dotnet/sdk:10.0-noble-aot - the SDK plus clang and the
# native libraries the AOT linker needs, which the plain SDK image lacks.
FROM mcr.microsoft.com/dotnet/sdk@sha256:96f3b7d45f53eb05990f05b89ce61c4e23d07a5098521c2f20b018630e34f298 AS build

# Set by buildx/BuildKit to amd64 or arm64.
ARG TARGETARCH
WORKDIR /src

# Project files first, sources second: restore is the slow, network-bound step,
# and this ordering lets Docker reuse its layer until a dependency changes.
#
# -p:RuntimeIdentifier, not `restore -r`: the -r switch sets the plural
# RuntimeIdentifiers, so the csproj's "AOT when a RID is set" condition stays
# false, the ILCompiler package is never restored, and a --no-restore publish
# then quietly produces a trimmed JIT build instead of a native binary.
COPY global.json Directory.Build.props ./
COPY src/McpGuardrails.Core/McpGuardrails.Core.csproj src/McpGuardrails.Core/
COPY src/McpGuardrails.Cli/McpGuardrails.Cli.csproj src/McpGuardrails.Cli/
RUN case "$TARGETARCH" in \
      amd64) echo linux-x64 > /tmp/rid ;; \
      arm64) echo linux-arm64 > /tmp/rid ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
 && dotnet restore src/McpGuardrails.Cli -p:RuntimeIdentifier="$(cat /tmp/rid)"

COPY src/ src/
# README, LICENSE and NOTICE are referenced by the project as package content.
COPY README.md LICENSE NOTICE ./
RUN dotnet publish src/McpGuardrails.Cli \
      --configuration Release \
      --runtime "$(cat /tmp/rid)" \
      --no-restore \
      --output /out \
 && rm -f /out/*.pdb /out/*.dbg

# mcr.microsoft.com/dotnet/runtime-deps:10.0-noble-chiseled - only the native
# libraries a self-contained .NET binary links against. No shell, no package
# manager, and a non-root `app` user (uid 1654) already defined.
FROM mcr.microsoft.com/dotnet/runtime-deps@sha256:18d4848091a40d13dbfdd6a8340c1657dc3e2f2d7fa2f042e9d162e68669dbc9 AS runtime

# Writable locations for the audit log and the default sandbox. The chiseled
# image has no shell, so they cannot be created at runtime by a RUN step -
# point them at paths the non-root user owns instead.
ENV GUARDRAILS_AUDIT=/home/app/.mcp-guardrails/audit.jsonl \
    GUARDRAILS_SANDBOX=/tmp/guardrails-sandbox

COPY --from=build --chown=root:root --chmod=0755 /out/McpGuardrails.Cli /usr/local/bin/mcp-guardrails
# SQLite for daily budgets is a native library Native AOT does not link in; it
# is loaded from beside the binary, and without it a daily cap fails at startup.
COPY --from=build --chown=root:root --chmod=0755 /out/libe_sqlite3.so /usr/local/bin/libe_sqlite3.so

# Numeric, so Kubernetes' runAsNonRoot can verify it without resolving a name.
USER 1654

# stdio is the transport: run with `docker run -i` so stdin stays open.
ENTRYPOINT ["/usr/local/bin/mcp-guardrails"]
