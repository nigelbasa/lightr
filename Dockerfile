# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o lightr ./cmd/lightr

# Runtime stage
FROM alpine:3.19

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN adduser -D -u 1000 lightr

# Copy binary from builder
COPY --from=builder /app/lightr /usr/local/bin/lightr

# Create data directories
RUN mkdir -p /app/data /app/data/blobs /app/data/keys /app/data/certs && \
    chown -R lightr:lightr /app

# Switch to non-root user
USER lightr

# Expose ports
# HTTP API
EXPOSE 8080
# SMTP
EXPOSE 2525
# IMAP
EXPOSE 1143

# Volume for persistent data
VOLUME ["/app/data"]

# Default config file location
ENV LIGHTR_CONFIG=/app/lightr.yaml

# Entrypoint
ENTRYPOINT ["lightr"]
CMD ["serve", "--config", "/app/lightr.yaml"]
