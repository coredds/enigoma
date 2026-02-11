# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o enigoma ./cmd/enigoma

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1000 enigoma && \
    adduser -D -u 1000 -G enigoma enigoma

WORKDIR /home/enigoma

# Copy binary from builder
COPY --from=builder /app/enigoma /usr/local/bin/enigoma
COPY --from=builder /app/schemas /home/enigoma/schemas

# Set ownership
RUN chown -R enigoma:enigoma /home/enigoma

# Switch to non-root user
USER enigoma

# Set entrypoint
ENTRYPOINT ["enigoma"]
CMD ["--help"]
