# CyxChat Server - Bootstrap + Relay
# Build: docker build -t cyxchat-server .
# Run: docker run -d -p 7777:7777/udp --name cyxchat-server cyxchat-server

FROM alpine:3.19 AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /build
COPY cyxchat-server.c .

RUN gcc -O2 -Wall -o cyxchat-server cyxchat-server.c

# Runtime image
FROM alpine:3.19

RUN apk add --no-cache libgcc

WORKDIR /app
COPY --from=builder /build/cyxchat-server .

EXPOSE 7777/udp

ENTRYPOINT ["./cyxchat-server"]
CMD ["7777"]
