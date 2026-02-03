# CyxChat Server - Bootstrap + Relay
# Build: docker build -t cyxchat-server .
# Run: docker run -d -p 7777:7777/udp --name cyxchat-server cyxchat-server

FROM alpine:3.19 AS builder

RUN apk add --no-cache gcc musl-dev libsodium-dev libsodium-static

WORKDIR /build
COPY cyxchat-server.c .

# Link libsodium statically for the runtime image
RUN gcc -O2 -Wall -o cyxchat-server cyxchat-server.c -lsodium -static

# Runtime image
FROM alpine:3.19

WORKDIR /app
COPY --from=builder /build/cyxchat-server .

# Create queue directory for offline message storage
RUN mkdir -p /var/lib/cyxchat/queue

EXPOSE 7777/udp

ENTRYPOINT ["./cyxchat-server"]
CMD ["7777"]
