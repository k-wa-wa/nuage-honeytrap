# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /app

RUN apk add --no-cache ca-certificates curl

# Download MaxMind GeoLite2-ASN database for offline IP enrichment
RUN curl -sSL -o GeoLite2-ASN.mmdb https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-ASN.mmdb

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o honeytrap ./cmd/honeytrap

# Runtime stage
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/GeoLite2-ASN.mmdb /etc/GeoLite2-ASN.mmdb
COPY --from=builder /app/honeytrap /honeytrap

USER 10001:10001

EXPOSE 2222 8080 5432

ENTRYPOINT ["/honeytrap"]
