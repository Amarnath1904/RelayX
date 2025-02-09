#ifndef DOMAIN_LOOKUP_H
#define DOMAIN_LOOKUP_H

#include <netinet/in.h>

#define DNS_SERVER "8.8.8.8" // Google's Public DNS
#define DNS_PORT 53
#define MAX_PACKET_SIZE 512
#define MAX_IPS 10 // Maximum number of IPs to store
#define INET_ADDRSTRLEN 16 // Ensure INET_ADDRSTRLEN is defined

// Function prototype for DNS lookup
int dns_lookup(const char *domain, int query_type, char resolved_ips[MAX_IPS][INET_ADDRSTRLEN]);

#endif // DOMAIN_LOOKUP_H
