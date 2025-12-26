/*
 * CyxWiz Protocol - Consensus Test Client
 *
 * Sends a validation request to test consensus voting between daemons.
 */

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET socket_t;
#define close_socket closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
typedef int socket_t;
#define close_socket close
#endif

/* Message types */
#define CYXWIZ_MSG_VALIDATION_REQ 0x63

/* Validation request (simplified) */
#pragma pack(push, 1)
typedef struct {
    uint8_t type;
    uint8_t round_id[8];
    uint8_t validation_type;
    uint8_t target_data[64];
    uint8_t committee_seed[8];
} validation_req_t;
#pragma pack(pop)

int main(int argc, char *argv[])
{
    int port = 7777;

    if (argc > 1) {
        port = atoi(argv[1]);
    }

    printf("Consensus Test Client\n");
    printf("=====================\n\n");

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif

    /* Create UDP socket */
    socket_t sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        fprintf(stderr, "socket() failed\n");
        return 1;
    }

    /* Build validation request */
    validation_req_t req;
    memset(&req, 0, sizeof(req));
    req.type = CYXWIZ_MSG_VALIDATION_REQ;

    /* Generate random round ID */
    for (int i = 0; i < 8; i++) {
        req.round_id[i] = (uint8_t)(rand() & 0xFF);
    }

    req.validation_type = 0x01; /* Job validation */

    /* Fill target data with test values */
    memset(req.target_data, 0x42, 64);

    /* Committee seed */
    for (int i = 0; i < 8; i++) {
        req.committee_seed[i] = (uint8_t)(rand() & 0xFF);
    }

    printf("Sending validation request...\n");
    printf("  Round ID: ");
    for (int i = 0; i < 8; i++) {
        printf("%02x", req.round_id[i]);
    }
    printf("\n");

    /* Send to bootstrap which will relay to all peers */
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr);

    int sent = sendto(sock, (const char *)&req, sizeof(req), 0,
                      (struct sockaddr *)&dest, sizeof(dest));

    if (sent > 0) {
        printf("  Sent %d bytes to 127.0.0.1:%d\n", sent, port);
    } else {
        printf("  Send failed\n");
    }

    /* Also send directly to daemon ports if known */
    /* Try common ephemeral port ranges */
    for (int p = 64925; p <= 64930; p++) {
        dest.sin_port = htons((uint16_t)p);
        sendto(sock, (const char *)&req, sizeof(req), 0,
               (struct sockaddr *)&dest, sizeof(dest));
    }

    printf("\nValidation request broadcast.\n");
    printf("Check daemon logs for VALIDATION_REQ handling.\n");

    close_socket(sock);

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
