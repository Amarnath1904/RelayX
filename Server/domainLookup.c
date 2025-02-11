#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "domainLookup.h"

// Structure for DNS header
struct DNS_HEADER {
    unsigned short id; // ID for the query
    unsigned char rd :1; // Recursion Desired
    unsigned char tc :1; // Truncated Message
    unsigned char aa :1; // Authoritative Answer
    unsigned char opcode :4; // Purpose of Message
    unsigned char qr :1; // Query/Response Flag

    unsigned char rcode :4; // Response Code
    unsigned char cd :1; // Checking Disabled
    unsigned char ad :1; // Authenticated Data
    unsigned char z :1; // Reserved
    unsigned char ra :1; // Recursion Available

    unsigned short q_count; // Number of question entries
    unsigned short ans_count; // Number of answer entries
    unsigned short auth_count; // Number of authority entries
    unsigned short add_count; // Number of resource entries
};

// Structure for DNS question
struct QUESTION {
    unsigned short qtype;
    unsigned short qclass;
};

void change_to_dns_format(unsigned char* dns, unsigned char* host) {
    int lock = 0, i;
    strcat((char*)host, ".");
    for (i = 0; i < strlen((char*)host); i++) {
        if (host[i] == '.') {
            *dns++ = i - lock;
            for (; lock < i; lock++) {
                *dns++ = host[lock];
            }
            lock++;
        }
    }
    *dns++ = '\0';
}

int dns_lookup(const char *domain, int query_type, char resolved_ips[MAX_IPS][INET_ADDRSTRLEN]) {
    int sock, ip_count = 0;
    struct sockaddr_in dest;
    unsigned char buffer[MAX_PACKET_SIZE];
    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("Socket creation failed");
        return 0;
    }

    dest.sin_family = AF_INET;
    dest.sin_port = htons(DNS_PORT);
    dest.sin_addr.s_addr = inet_addr(DNS_SERVER);

    memset(buffer, 0, MAX_PACKET_SIZE);
    dns = (struct DNS_HEADER*) buffer;
    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0;
    dns->opcode = 0;
    dns->aa = 0;
    dns->tc = 0;
    dns->rd = 1;
    dns->ra = 0;
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1);
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    unsigned char *qname = (unsigned char*)&buffer[sizeof(struct DNS_HEADER)];
    change_to_dns_format(qname, (unsigned char*)domain);

    qinfo = (struct QUESTION*) &buffer[sizeof(struct DNS_HEADER) + strlen((const char*)qname) + 1];
    qinfo->qtype = htons(query_type);
    qinfo->qclass = htons(1);

    if (sendto(sock, buffer, sizeof(struct DNS_HEADER) + strlen((const char*)qname) + 1 + sizeof(struct QUESTION), 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        perror("Sendto failed");
        close(sock);
        return 0;
    }

    int dest_len = sizeof(dest);
    if (recvfrom(sock, buffer, MAX_PACKET_SIZE, 0, (struct sockaddr*)&dest, (socklen_t*)&dest_len) < 0) {
        perror("Recvfrom failed");
        close(sock);
        return 0;
    }

    struct sockaddr_in a;
    unsigned char *reader = buffer + sizeof(struct DNS_HEADER) + strlen((const char*)buffer + sizeof(struct DNS_HEADER)) + 1 + sizeof(struct QUESTION);

    printf("🔍 Performing DNS lookup for: %s (Query Type: %d)\n", domain, query_type);

    for (int i = 0; i < ntohs(((struct DNS_HEADER*)buffer)->ans_count) && ip_count < MAX_IPS; i++) {
        reader += 2;
        unsigned short type = ntohs(*(unsigned short*)reader);
        reader += 8;
        unsigned short data_len = ntohs(*(unsigned short*)reader);
        reader += 2;

        if (type == 1) { // A Record (IPv4 Address)
            a.sin_addr.s_addr = *(long*)reader;
            strcpy(resolved_ips[ip_count], inet_ntoa(a.sin_addr));
            printf("✅ Found A Record: %s\n", resolved_ips[ip_count]);
            ip_count++;
            reader += data_len;
        }
        else if (type == 15) { // MX Record
            unsigned short preference = ntohs(*(unsigned short*)reader);
            reader += 2; // Move past preference value

            char mail_server[256];
            memset(mail_server, 0, sizeof(mail_server));

            int j = 0;
            while (*reader) {
                if (*reader >= 192) { // Name compression
                    reader = buffer + ((*reader & 0x3F) << 8) + *(reader + 1);
                } else {
                    int len = *reader++;
                    for (int k = 0; k < len; k++) {
                        mail_server[j++] = *reader++;
                    }
                    mail_server[j++] = '.';
                }
            }
            mail_server[j - 1] = '\0'; // Remove last dot

            printf("📬 Found MX Record (Pref %d): %s\n", preference, mail_server);
            strcpy(resolved_ips[ip_count], mail_server);
            ip_count++;
            reader += data_len - 2; // Move past remaining bytes
        }
    }
    close(sock);
    return ip_count;
}
