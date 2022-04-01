#ifndef DNSSPOOF_H
#define DNSSPOOF_H

#include<sys/socket.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pthread.h>

#define PROTOCOL_UDP 0x11

#define IP_PACKET_LEN 65535
#define DNS_SERVICE_PORT 53
#define DNS_TIMEOUT      10000UL
struct dnshdr {
	uint16_t	tid;		/* Transaction ID */
	uint16_t	flags;		/* Flags */
	uint16_t	nqueries;	/* Questions */
	uint16_t	nanswers;	/* Answers */
	uint16_t	nauth;		/* Authority PRs */
	uint16_t	nother;		/* Other PRs */
	unsigned char	data[1];	/* Data, variable length */
};
void* dns_spoofing(void* args);

#endif