# syntax=docker/dockerfile:1.4

# Sentinel SOAP Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY sentinel-agent-soap /sentinel-agent-soap

LABEL org.opencontainers.image.title="Sentinel SOAP Agent" \
      org.opencontainers.image.description="Sentinel SOAP Agent for Sentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/raskell-io/sentinel-agent-soap"

ENV RUST_LOG=info,sentinel_agent_soap=debug \
    SOCKET_PATH=/var/run/sentinel/soap.sock

USER nonroot:nonroot

ENTRYPOINT ["/sentinel-agent-soap"]
