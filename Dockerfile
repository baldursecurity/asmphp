# syntax=docker/dockerfile:1
###############################################################################
# asm-recon — attack-surface recon in a container
#
#   Stage 1 (builder): compile/fetch the Go + Rust recon tools
#   Stage 2 (runtime): slim Python image with just the binaries + the script
#
# Nothing to install on the host except Docker. Build once, run anywhere.
###############################################################################

# ---- versions (override with --build-arg) ---------------------------------
ARG GO_VERSION=1.23
ARG HTTPX_VERSION=v1.6.10
ARG NAABU_VERSION=v2.3.3
ARG SUBFINDER_VERSION=v2.6.7
ARG FINDOMAIN_VERSION=10.0.1
ARG INSTALL_AMASS=false

# =============================================================================
# Stage 1 — builder
# =============================================================================
FROM golang:${GO_VERSION}-bookworm AS builder

# libpcap-dev is required to build naabu; unzip for the findomain release zip.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap-dev unzip curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG HTTPX_VERSION
ARG NAABU_VERSION
ARG SUBFINDER_VERSION
ARG INSTALL_AMASS

ENV GOBIN=/out GOFLAGS=-trimpath CGO_ENABLED=1
RUN mkdir -p /out

# ProjectDiscovery tools + assetfinder
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION} \
 && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION} \
 && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION} \
 && go install github.com/tomnomnom/assetfinder@latest

# amass is large; opt in with --build-arg INSTALL_AMASS=true
RUN if [ "$INSTALL_AMASS" = "true" ]; then \
        go install github.com/owasp-amass/amass/v4/...@latest ; \
    fi

# findomain — fetch the prebuilt release binary for the target arch
ARG FINDOMAIN_VERSION
ARG TARGETARCH
RUN set -eux; \
    case "$TARGETARCH" in \
        amd64)  FD_ASSET="findomain-linux.zip" ;; \
        arm64)  FD_ASSET="findomain-aarch64.zip" ;; \
        *)      echo "unsupported arch: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    base="https://github.com/Findomain/Findomain/releases"; \
    url="${base}/download/${FINDOMAIN_VERSION}/${FD_ASSET}"; \
    echo "Downloading $url"; \
    curl -fsSL -o /tmp/findomain.zip "$url" \
      || curl -fsSL -o /tmp/findomain.zip "${base}/latest/download/${FD_ASSET}"; \
    unzip -o /tmp/findomain.zip -d /out; \
    chmod +x /out/findomain; \
    /out/findomain --version || true

# =============================================================================
# Stage 2 — runtime
# =============================================================================
FROM python:3.12-slim-bookworm AS runtime

# libpcap0.8 = naabu runtime dep; ca-certificates for TLS to the passive APIs.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && update-ca-certificates

# Copy every recon binary from the builder into PATH
COPY --from=builder /out/ /usr/local/bin/

# The script itself (pure stdlib — no pip install needed)
COPY asm_recon.py /app/asm_recon.py

# Run as a non-root user. naabu CONNECT scan + httpx work fine unprivileged.
RUN useradd --create-home --uid 1000 recon \
    && mkdir -p /data && chown recon:recon /data
USER recon

# Outputs land here; mount a host directory onto /data to collect them.
WORKDIR /data

ENTRYPOINT ["python3", "/app/asm_recon.py"]
CMD ["--help"]
