# ==========================================
# Stage 1: Build the Stealth Proxy
# ==========================================
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache openssl bash git

WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY . .

ARG REMOTE_SERVER_URL="https://127.0.0.1:30001"

RUN set -ex; \
    SECRET=$(openssl rand -base64 32); \
    openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 3650 -nodes -subj "/CN=cloudflare.com"; \
    CGO_ENABLED=0 go build -ldflags "-s -w -X 'main.ProxySecret=$SECRET'" -o server_bin server/server.go; \
    CGO_ENABLED=0 go build -ldflags "-s -w -X 'main.ProxySecret=$SECRET' -X 'main.RemoteServerURL=${REMOTE_SERVER_URL}'" -o client_bin client/client.go;

# ==========================================
# Stage 2: Download Shadowsocks
# ==========================================
FROM alpine:latest AS ss-builder
RUN apk add --no-cache wget tar xz
WORKDIR /ss
# Use the MUSL version for Alpine compatibility
RUN wget https://github.com/shadowsocks/shadowsocks-rust/releases/download/v1.24.0/shadowsocks-v1.24.0.x86_64-unknown-linux-musl.tar.xz -O ss.tar.xz && \
    tar -xf ss.tar.xz

# ==========================================
# Stage 3: Final "All-in-One" Image
# ==========================================
FROM alpine:latest

WORKDIR /app

# Copy Go binaries and certs
COPY --from=builder /app/server_bin /app/server
COPY --from=builder /app/client_bin /app/client
COPY --from=builder /app/server.crt /app/server.crt
COPY --from=builder /app/server.key /app/server.key
COPY --from=builder /app/ssserver-config.json /app/ssserver-config.json

# Copy Shadowsocks server
COPY --from=ss-builder /ss/ssserver /app/ssserver

EXPOSE 30001

# Start BOTH Shadowsocks and the Stealth Server
CMD ["sh", "-c", "/app/ssserver -c /app/ssserver-config.json & /app/server"]
