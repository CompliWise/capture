# Capture agent image — Debian runtime for update-ca-certificates and /etc/compliwise volumes.
FROM golang:1.25-alpine AS builder
COPY . /app
RUN cd /app && go build -o capture ./cmd/capture

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/capture /usr/bin/capture
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

VOLUME ["/etc/compliwise", "/usr/local/share/ca-certificates"]
ENV GIN_MODE=release
ENV PORT=59232
EXPOSE 59232
STOPSIGNAL SIGINT
ENTRYPOINT ["/entrypoint.sh"]
