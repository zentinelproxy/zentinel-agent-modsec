# syntax=docker/dockerfile:1.4

# Zentinel ModSecurity Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY zentinel-modsec-agent /zentinel-modsec-agent

LABEL org.opencontainers.image.title="Zentinel ModSecurity Agent" \
      org.opencontainers.image.description="Zentinel ModSecurity Agent for Zentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/zentinelproxy/zentinel-agent-modsec"

ENV RUST_LOG=info,zentinel_modsec_agent=debug \
    SOCKET_PATH=/var/run/zentinel/modsec.sock

USER nonroot:nonroot

ENTRYPOINT ["/zentinel-modsec-agent"]
