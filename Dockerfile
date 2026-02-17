# syntax=docker/dockerfile:1.4

# Zentinel SOAP Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY zentinel-agent-soap /zentinel-agent-soap

LABEL org.opencontainers.image.title="Zentinel SOAP Agent" \
      org.opencontainers.image.description="Zentinel SOAP Agent for Zentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/zentinelproxy/zentinel-agent-soap"

ENV RUST_LOG=info,zentinel_agent_soap=debug \
    SOCKET_PATH=/var/run/zentinel/soap.sock

USER nonroot:nonroot

ENTRYPOINT ["/zentinel-agent-soap"]
