#ifndef ARPSPOOF_H
#define ARPSPOOF_H

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

#define ARP_PACKET_LEN sizeof(struct ether_header) + sizeof(struct ether_arp)

uint8_t* construct_arp_pac(int sock_r, struct sockaddr_ll socket_address, unsigned int addr_len,
                            uint8_t* sha, uint8_t* tha, uint8_t* spa, uint8_t* tpa, unsigned int op);

uint8_t* get_target_mac(int sock_r, struct sockaddr_ll socket_address, unsigned int addr_len,
                        uint8_t* my_mac, uint8_t* my_ip, uint8_t* target_ip);   

int send_arp_reply_fmac(int sock_r, struct sockaddr_ll socket_address, unsigned int addr_len,
                        uint8_t* my_mac, uint8_t* target_mac, uint8_t* gateway_ip, uint8_t* target_ip);
#endif