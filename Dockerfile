# Multi-stage Dockerfile for Vulnora

# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    git \
    make \
    gcc \
    musl-dev \
    protobuf-dev \
    protoc

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN make build-all

# Runtime stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    curl \
    openssl \
    sqlite

# Create non-root user
RUN addgroup -g 1001 vulnora && \
    adduser -D -s /bin/sh -u 1001 -G vulnora vulnora

# Create directories
RUN mkdir -p /app/data /app/logs /app/certs /app/plugins /app/tmp && \
    chown -R vulnora:vulnora /app

# Copy binaries from builder
COPY --from=builder /app/bin/vulnora /usr/local/bin/vulnora
COPY --from=builder /app/bin/vulnora-agent /usr/local/bin/vulnora-agent
COPY --from=builder /app/bin/vulnora-cli /usr/local/bin/vulnora-cli

# Copy configuration and assets
COPY --chown=vulnora:vulnora configs/ /app/configs/
COPY --chown=vulnora:vulnora assets/ /app/assets/

# Set working directory
WORKDIR /app

# Switch to non-root user
USER vulnora

# Expose ports
EXPOSE 8080 8081 8443 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8081/health || exit 1

# Default command
CMD ["vulnora", "--config", "/app/configs/docker.yaml"]
