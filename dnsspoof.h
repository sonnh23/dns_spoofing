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
#include <netinet/ip.h>
#include <netinet/udp.h>

#define PROTOCOL_UDP 0x11

#define IP_PACKET_LEN 65535
#define DNS_SERVICE_PORT 53
#define DNS_TIMEOUT      10000UL
#define REQUEST_SIZE 100

#define TYPE_A 0x0001
#define CLASS_IN 0x0001
struct dnshdr {
	uint16_t	tid;		/* Transaction ID */
	uint16_t	flags;		/* Flags */
	uint16_t	questitons;	/* Questions */

	uint16_t	answer_rrs;	/* Answers */
	uint16_t	auth_rrs;		/* Authority PRs */
	uint16_t	add_rrs;		/* Other PRs */

	/* ... Dont care the middle*/
}__attribute__((packed));

struct dnsquery {
	char* qname;
	uint16_t qtype;
	uint16_t qclass;
};
struct dnsanswer{
	uint16_t qname_pointer;
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t data_len;
	uint8_t  data[4];
}__attribute__((packed));

void* target_to_gateway(void* args);

void* gateway_to_target(void* args);



uint16_t udp_checksum( uint16_t* buf, size_t len, uint16_t* saddr, uint16_t* daddr);

uint16_t ip_cksum (const void *_data, int len);

void extract_dns_request(uint8_t *query_data, uint8_t *request);

void modify_l2_hdr(uint8_t *ip_pac, uint8_t* sha, uint8_t* tha);

uint8_t* construct_dns_response(uint8_t* ether_shost, uint8_t* ether_dhost, //l2hdr
                        uint16_t id, uint8_t protocol, uint8_t* saddr, uint8_t* daddr, //l3hdr
                        uint16_t uh_dport, uint16_t tid, //l4hdr
                        uint8_t* query_data, int query_data_len,
                        uint8_t* ip_spoof);


#endif