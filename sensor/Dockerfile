# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /src

RUN apk add --no-cache ca-certificates git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s -X main.version=2.0.0" \
    -o /sensor ./cmd/sensor

# ── Runtime stage (minimal) ────────────────────────────────────────────────────
FROM scratch

COPY --from=builder /sensor /sensor
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Cert storage volume
VOLUME ["/etc/otrap/sensor/certs"]

# OT protocol ports (no management port exposed)
EXPOSE 102 502 80 443

HEALTHCHECK --interval=30s --timeout=5s \
    CMD ["/sensor", "--health-check"]

ENTRYPOINT ["/sensor"]
