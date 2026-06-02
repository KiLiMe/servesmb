# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies  
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN make build

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 smbserver && \
    adduser -u 1000 -G smbserver -s /bin/sh -D smbserver

# Create directories
RUN mkdir -p /app/shares /app/config && \
    chown -R smbserver:smbserver /app

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/servesmb .

# Copy configuration
COPY --from=builder /app/example-config.json ./config/

# Change ownership
RUN chown smbserver:smbserver /app/servesmb

# Switch to non-root user
USER smbserver

# Expose SMB port
EXPOSE 445

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD netstat -ln | grep :445 || exit 1

# Default command
CMD ["./servesmb", "-config", "./config/example-config.json"]