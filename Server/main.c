#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "domainLookup.h"

#define SMTP_PORT 25
#define BUFFER_SIZE 1024

void send_smtp_hello(const char *email) {
    char domain[256];
    char resolved_ips[MAX_IPS][INET_ADDRSTRLEN];
    int ip_count;

    // Extract domain from email
    char *at_pos = strchr(email, '@');
    if (!at_pos) {
        fprintf(stderr, "Invalid email address\n");
        return;
    }
    strcpy(domain, at_pos + 1);

    // Perform DNS lookup to get mail server IP
    ip_count = dns_lookup(domain, 1, resolved_ips);
    if (ip_count == 0) {
        fprintf(stderr, "No IP found for domain: %s\n", domain);
        return;
    }

    int sock;
    struct sockaddr_in server;
    char buffer[BUFFER_SIZE];

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(SMTP_PORT);
    if (inet_pton(AF_INET, resolved_ips[0], &server.sin_addr) <= 0) {
        perror("Invalid SMTP server IP");
        close(sock);
        return;
    }

    // Connect to SMTP server
    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        perror("Connection to SMTP server failed");
        close(sock);
        return;
    }

    // Read server greeting
    recv(sock, buffer, BUFFER_SIZE - 1, 0);
    printf("Server: %s", buffer);

    // Send HELO command
    snprintf(buffer, BUFFER_SIZE, "HELO example.com\r\n");
    send(sock, buffer, strlen(buffer), 0);
    printf("Sent: %s", buffer);

    // Read server response
    recv(sock, buffer, BUFFER_SIZE - 1, 0);
    printf("Server: %s", buffer);

    // Close connection
    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <email_address>\n", argv[0]);
        return 1;
    }
    send_smtp_hello(argv[1]);
    return 0;
}
