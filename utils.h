#ifndef UTILS_H
#define UTILS_H

#include <sys/socket.h>
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

struct attacking_args{
    struct sockaddr_ll socket_address;
    unsigned int addr_len;
    uint8_t* my_mac;
    uint8_t* target_mac;
    uint8_t* gateway_ip;
    uint8_t* target_ip;
    uint8_t* gateway_mac;
    uint8_t* my_ip;
    uint8_t* ip_dns_fake;
    char* qname;
};
typedef struct attacking_args attacking_args_t;



int compare_mac(uint8_t* mac_1, uint8_t* mac_2);
int compare_ip(uint8_t* ip_1, uint8_t* ip_2);

void dns_pac_status(uint8_t* pac, char* qname, uint16_t qtype, uint16_t qclass);
#endif